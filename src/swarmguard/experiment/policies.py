from __future__ import annotations

import random
import string
from dataclasses import dataclass
from functools import lru_cache

from swarmguard.config import PERMIT_PREFIX_SPACE, TICKET_SPACE, ZONE_SPACE

ALPHABET = string.digits + string.ascii_uppercase
COMMON_PREFIXES = ["A0", "A1", "B0", "B1", "C0", "C1", "D0", "E0", "F0", "G0"]
BENIGN_SCENARIOS = ("benign_flash", "benign_diagnostic", "benign_explorer", "benign_bulk")
ATTACK_SCENARIOS = (
    "independent_recon", "coordinated_swarm", "swarm_no_diagnostic",
    "matched_swarm", "camouflaged_swarm", "low_and_slow_swarm", "mixed_swarm",
)
SCENARIOS = BENIGN_SCENARIOS + ATTACK_SCENARIOS
KNOWN_ATTACK_SCENARIOS = ("independent_recon", "coordinated_swarm")
UNSEEN_ATTACK_SCENARIOS = tuple(x for x in ATTACK_SCENARIOS if x not in KNOWN_ATTACK_SCENARIOS)
FAMILIES = ("ticket", "permit_prefix", "zone")
SPACES = {"ticket": TICKET_SPACE, "permit_prefix": PERMIT_PREFIX_SPACE, "zone": ZONE_SPACE}


@dataclass(frozen=True)
class Action:
    path: str
    params: dict[str, str]
    family: str
    delay_s: float = 0.0


def base36_prefix(index: int) -> str:
    index %= PERMIT_PREFIX_SPACE
    return ALPHABET[index // 36] + ALPHABET[index % 36]


@lru_cache(maxsize=96)
def _partition_order(size: int, seed: int) -> tuple[int, ...]:
    order = list(range(size))
    random.Random(seed).shuffle(order)
    return tuple(order)


def _partition_index(agent_idx: int, agent_count: int, occurrence: int,
                     occurrences: int, space: int, *, seed: int, family_idx: int) -> int:
    """Independent family permutations and within-stratum jitter randomize every repeat.

    Across agents, queries are approximately uniform but sampling is stratified
    rather than independent. Neither identity ordering nor a common cross-family
    rank is exposed as a convenient coordination cue.
    """
    total = max(1, agent_count * occurrences)
    family_seed = seed + family_idx * 10_000_019
    rank = _partition_order(agent_count, family_seed)[agent_idx]
    ordinal = rank * occurrences + occurrence
    jitter = random.Random(family_seed + agent_idx * 97 + occurrence * 7919).random()
    return min(space - 1, int((ordinal + jitter) * space / total))


@lru_cache(maxsize=96)
def attack_members(agent_count: int, fraction: float, seed: int, repeat: int) -> frozenset[int]:
    count = max(1, min(agent_count, round(agent_count * fraction)))
    return frozenset(random.Random(seed + repeat * 104729 + 4409).sample(range(agent_count), count))


@lru_cache(maxsize=96)
def _attack_ranks(agent_count: int, fraction: float, seed: int, repeat: int) -> dict[int, int]:
    return {member: rank for rank, member in enumerate(sorted(attack_members(agent_count, fraction, seed, repeat)))}


def build_actions(scenario: str, *, agent_idx: int, agent_count: int,
                  requests_per_agent: int, seed: int, repeat: int,
                  attacker_fraction: float = 0.20, camouflage_fraction: float = 0.50,
                  slow_delay_s: float = 0.20) -> list[Action]:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    if agent_count < 1 or not 0 <= agent_idx < agent_count or requests_per_agent < 1:
        raise ValueError("invalid agent count, index or request budget")
    policy = scenario
    local_idx, local_count = agent_idx, agent_count
    if scenario == "mixed_swarm":
        members = attack_members(agent_count, attacker_fraction, seed, repeat)
        if agent_idx not in members:
            policy = "benign_flash"
        else:
            policy = "matched_swarm"
            # Membership exists exclusively in the evaluator / policy generator.
            local_idx = _attack_ranks(agent_count, attacker_fraction, seed, repeat)[agent_idx]
            local_count = len(members)

    repeat_seed = seed + repeat * 1_000_003
    rng = random.Random(repeat_seed + agent_idx * 97)
    occurrences = {family: sum(FAMILIES[r % 3] == family for r in range(requests_per_agent)) for family in FAMILIES}
    seen = {family: 0 for family in FAMILIES}
    actions: list[Action] = []
    for request_idx in range(requests_per_agent):
        family_idx = request_idx % 3
        family = FAMILIES[family_idx]
        occurrence = seen[family]
        seen[family] += 1
        hot = policy in ("benign_flash", "benign_diagnostic")
        if policy == "camouflaged_swarm" and rng.random() < camouflage_fraction:
            hot = True
        if hot:
            if family == "ticket":
                value = (agent_idx * 17 + rng.randrange(53)) % 4000
            elif family == "permit_prefix":
                prefix = COMMON_PREFIXES[(agent_idx + occurrence) % len(COMMON_PREFIXES)]
                value = ALPHABET.index(prefix[0]) * 36 + ALPHABET.index(prefix[1])
            else:
                value = (agent_idx * 7 + rng.randrange(5)) % 20
        elif policy == "benign_bulk":
            # Legitimate broad, repetitive batch work is an intentionally hard negative.
            value = (agent_idx * 31 + occurrence * 101 + repeat_seed) % SPACES[family]
        elif policy in ("independent_recon", "benign_explorer"):
            value = rng.randrange(SPACES[family])
        else:
            value = _partition_index(
                local_idx, local_count, occurrence, occurrences[family], SPACES[family],
                seed=repeat_seed, family_idx=family_idx,
            )

        if policy in ("independent_recon", "coordinated_swarm"):
            diagnostic = True
        elif policy == "benign_diagnostic":
            diagnostic = rng.random() < 0.75
        elif policy in ("matched_swarm", "benign_explorer", "mixed_swarm"):
            diagnostic = rng.random() < 0.05
        elif policy in ("camouflaged_swarm", "low_and_slow_swarm"):
            diagnostic = rng.random() < 0.05
        else:
            diagnostic = False
        delay = slow_delay_s * rng.uniform(0.5, 1.5) if policy == "low_and_slow_swarm" else 0.0
        if family == "ticket":
            actions.append(Action(f"/api/v1/tickets/{value}", {}, family, delay))
        elif family == "permit_prefix":
            actions.append(Action("/api/v1/permits/search", {"prefix": base36_prefix(value)}, family, delay))
        else:
            actions.append(Action(f"/api/v1/zones/{value}/status", {"view": "diagnostic" if diagnostic else "summary"}, family, delay))
    return actions


def semantic_event(action: Action, *, identity: str, ts: float) -> dict[str, str]:
    """The same allowed metadata emitted by the gateway, with no policy label."""
    if action.family == "ticket":
        key = action.path.rsplit("/", 1)[-1]
        numeric = key
    elif action.family == "permit_prefix":
        key = action.params["prefix"]
        numeric = ""
    else:
        key = action.path.split("/")[4]
        numeric = key
    return {
        "ts": str(ts), "identity": identity, "family": action.family,
        "resource_key": key, "numeric_key": numeric,
        "diagnostic": "1" if action.params.get("view") == "diagnostic" else "0",
    }


def reference_events(scenario: str, *, agent_count: int, requests_per_agent: int,
                     seed: int, repeat: int, arrival_window_ms: float = 1000,
                     **policy_options) -> list[dict[str, str]]:
    """Synthetic policy reference, not measured HTTP/service-performance evidence."""
    timed: list[tuple[float, dict[str, str]]] = []
    for agent_idx in range(agent_count):
        rng = random.Random(seed + repeat * 104729 + agent_idx * 7919)
        ts = 1000.0 + rng.random() * arrival_window_ms / 1000.0
        for action in build_actions(
            scenario, agent_idx=agent_idx, agent_count=agent_count,
            requests_per_agent=requests_per_agent, seed=seed, repeat=repeat, **policy_options,
        ):
            ts += action.delay_s + rng.uniform(0.0001, 0.003)
            timed.append((ts, semantic_event(action, identity=f"ref-{agent_idx}", ts=ts)))
    return [event for _, event in sorted(timed, key=lambda item: item[0])]
