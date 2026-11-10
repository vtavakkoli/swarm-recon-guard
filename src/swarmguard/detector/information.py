"""COVE: causal coverage-regularity and marginal-information descriptors.

The observational connection to EARS-Info (arXiv:2610.38040) is a hypothesis:
coordinated exploration can produce unusually even coverage of observable
resource regions. These metrics never observe attacker membership, labels,
hidden secrets, diagnostic headers, or future events.

No detector performance, malicious intent, or distribution-free service FPR
is implied by these deterministic feature definitions.
"""
from __future__ import annotations

import math
from collections.abc import Mapping

from swarmguard.detector.model import FAMILY_SPACES

BINS = 16
MIN_FAMILY_REQUESTS = 8
NO_EVIDENCE_SCORE = -1000.0


def information_features(
    region_counts: Mapping[str, Mapping[int, int]],
    unique_keys: Mapping[str, set[str]],
) -> dict[str, float]:
    """Use only current/past gateway-observable request regions.

    Pearson chi-square is small when observed resource regions are unusually
    evenly populated. We treat it as a *score*, not as a chi-square test:
    sequences are neither independent nor necessarily uniformly distributed.
    Per-family excess novelty is relative to the IID uniform-occupancy
    reference E[unique] = S(1 - (1 - 1/S)^n), not ground-truth information gain.
    Held-out whole-stream maxima determine all operating thresholds.
    """
    chi_squares: list[float] = []
    novelty_surplus: list[float] = []
    for family, space in FAMILY_SPACES.items():
        counts = region_counts.get(family, {})
        n = sum(int(value) for value in counts.values())
        if n < MIN_FAMILY_REQUESTS:
            continue
        expected_per_bin = n / BINS
        chi_squares.append(
            sum((counts.get(i, 0) - expected_per_bin) ** 2 / expected_per_bin
                for i in range(BINS))
        )
        # log1p/expm1 preserve precision when the semantic key space is large.
        expected_distinct = -space * math.expm1(n * math.log1p(-1.0 / space))
        observed_distinct = min(len(unique_keys.get(family, set())), n)
        novelty_surplus.append(
            (observed_distinct - expected_distinct) / math.sqrt(n)
        )

    return {
        "information_balance_chi2": (
            sum(chi_squares) / len(chi_squares)
            if chi_squares else -NO_EVIDENCE_SCORE
        ),
        "information_excess_gain": (
            sum(novelty_surplus) / len(novelty_surplus)
            if novelty_surplus else 0.0
        ),
        "information_active_families": float(len(chi_squares)),
    }


def information_scores(row: dict, state: dict) -> dict[str, float]:
    """Causal scores, with a two-window persistence gate for COVE.

    The single-window variant and no-gain ablation have their own independently
    calibrated stream-max thresholds; they are not cherry-picked at test time.
    """
    balance = -float(row["information_balance_chi2"])
    gain = float(row["information_excess_gain"])
    instant = balance + gain
    previous = state.get("cove_previous_instant")
    previous_balance = state.get("cove_previous_balance")
    state["cove_previous_instant"] = instant
    state["cove_previous_balance"] = balance
    return {
        "cove": min(instant, previous) if previous is not None else NO_EVIDENCE_SCORE,
        "cove_instant": instant,
        "cove_balance": (
            min(balance, previous_balance)
            if previous_balance is not None else NO_EVIDENCE_SCORE
        ),
    }
