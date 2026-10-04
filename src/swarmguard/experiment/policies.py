from __future__ import annotations

import random
import string
from dataclasses import dataclass

from swarmguard.config import PERMIT_PREFIX_SPACE, TICKET_SPACE, ZONE_SPACE

ALPHABET = string.digits + string.ascii_uppercase
COMMON_PREFIXES = ["A0", "A1", "B0", "B1", "C0", "C1", "D0", "E0", "F0", "G0"]
SCENARIOS = ("benign_flash", "independent_recon", "coordinated_swarm")


@dataclass(frozen=True)
class Action:
    path: str
    params: dict[str, str]
    family: str


def base36_prefix(index: int) -> str:
    index %= PERMIT_PREFIX_SPACE
    return ALPHABET[index // 36] + ALPHABET[index % 36]


def _stratified_index(agent_idx: int, agent_count: int, occurrence: int, occurrences: int, space: int) -> int:
    total = max(1, agent_count * occurrences)
    ordinal = agent_idx * occurrences + occurrence
    return min(space - 1, int(((ordinal + 0.5) / total) * space))


def build_actions(scenario: str, *, agent_idx: int, agent_count: int, requests_per_agent: int, seed: int, repeat: int) -> list[Action]:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    rng = random.Random(seed + repeat * 1_000_003 + agent_idx * 97)
    family_occurrences = {family: sum(1 for r in range(requests_per_agent) if ("ticket", "permit", "zone")[r % 3] == family) for family in ("ticket", "permit", "zone")}
    seen_occurrences = {"ticket": 0, "permit": 0, "zone": 0}
    actions: list[Action] = []
    for request_idx in range(requests_per_agent):
        family = ("ticket", "permit", "zone")[request_idx % 3]
        occurrence = seen_occurrences[family]
        seen_occurrences[family] += 1
        if scenario == "benign_flash":
            if family == "ticket":
                ticket_id = (agent_idx * 17 + rng.randrange(0, 53)) % 4_000
                actions.append(Action(f"/api/v1/tickets/{ticket_id}", {}, "ticket"))
            elif family == "permit":
                prefix = COMMON_PREFIXES[(agent_idx + occurrence) % len(COMMON_PREFIXES)]
                actions.append(Action("/api/v1/permits/search", {"prefix": prefix}, "permit_prefix"))
            else:
                zone_id = (agent_idx * 7 + rng.randrange(0, 5)) % 20
                actions.append(Action(f"/api/v1/zones/{zone_id}/status", {"view": "summary"}, "zone"))
        elif scenario == "independent_recon":
            if family == "ticket":
                actions.append(Action(f"/api/v1/tickets/{rng.randrange(TICKET_SPACE)}", {}, "ticket"))
            elif family == "permit":
                actions.append(Action("/api/v1/permits/search", {"prefix": base36_prefix(rng.randrange(PERMIT_PREFIX_SPACE))}, "permit_prefix"))
            else:
                actions.append(Action(f"/api/v1/zones/{rng.randrange(ZONE_SPACE)}/status", {"view": "diagnostic"}, "zone"))
        else:
            occ_total = family_occurrences[family]
            if family == "ticket":
                ticket_id = _stratified_index(agent_idx, agent_count, occurrence, occ_total, TICKET_SPACE)
                actions.append(Action(f"/api/v1/tickets/{ticket_id}", {}, "ticket"))
            elif family == "permit":
                idx = _stratified_index(agent_idx, agent_count, occurrence, occ_total, PERMIT_PREFIX_SPACE)
                actions.append(Action("/api/v1/permits/search", {"prefix": base36_prefix(idx)}, "permit_prefix"))
            else:
                zone_id = _stratified_index(agent_idx, agent_count, occurrence, occ_total, ZONE_SPACE)
                actions.append(Action(f"/api/v1/zones/{zone_id}/status", {"view": "diagnostic"}, "zone"))
    return actions
