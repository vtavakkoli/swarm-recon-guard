"""Independent, label-free marginal-difference diagnostics for paired HTTP runs."""
from __future__ import annotations

import math
from collections import Counter, defaultdict

import numpy as np

from swarmguard.experiment.policies import FAMILIES, SPACES, ALPHABET


def _key_fraction(event):
    family, key = event.get("family"), str(event.get("resource_key", ""))
    if family not in SPACES:
        return None
    try:
        pos = ALPHABET.index(key[0]) * 36 + ALPHABET.index(key[1]) if family == "permit_prefix" else int(key)
    except (IndexError, ValueError):
        return None
    return float(np.clip(pos / max(1, SPACES[family] - 1), 0, 1))


def marginal_profile(events):
    """Observable-only traffic proportions; includes no intent or membership data."""
    n = max(1, len(events))
    counts = Counter(e.get("family") for e in events)
    zones = [e for e in events if e.get("family") == "zone"]
    diagnostic = sum(e.get("diagnostic") == "1" for e in zones) / len(zones) if zones else None
    by_family = {family: [] for family in FAMILIES}
    per_identity = defaultdict(list)
    for event in events:
        per_identity[str(event.get("identity", ""))].append(event)
        value = _key_fraction(event)
        if value is not None:
            by_family[event["family"]].append(value)
    identities = list(per_identity.values())
    request_counts = [len(group) for group in identities]
    gaps = []
    for group in identities:
        times = sorted(float(e.get("ts", 0)) for e in group)
        gaps.extend(np.diff(times).tolist())
    histograms = {}
    for family, values in by_family.items():
        hist, _ = np.histogram(values, bins=16, range=(0, 1))
        histograms[family] = (hist / max(1, hist.sum())).tolist()
    return {
        "n_requests": len(events), "n_identities": len(identities),
        "mean_requests_per_identity": float(np.mean(request_counts)) if request_counts else 0,
        "mean_within_identity_gap_s": float(np.mean(gaps)) if gaps else None,
        "diagnostic_given_zone": diagnostic,
        **{"fraction_" + family: counts[family] / n for family in FAMILIES},
        "histograms": histograms,
    }


def js_divergence(p, q):
    """Jensen-Shannon divergence in bits (zero for identical histograms)."""
    x = np.asarray(p, dtype=float)
    y = np.asarray(q, dtype=float)
    if x.shape != y.shape:
        raise ValueError("histogram length mismatch")
    if x.sum() == 0 or y.sum() == 0:
        return None
    x, y = x / x.sum(), y / y.sum()
    m = (x + y) / 2
    return float((np.sum(x[x > 0] * np.log2(x[x > 0] / m[x > 0])) +
                  np.sum(y[y > 0] * np.log2(y[y > 0] / m[y > 0]))) / 2)


def comparison(control, attack):
    result = {
        "absolute_zone_diagnostic_rate_difference":
            abs(control["diagnostic_given_zone"] - attack["diagnostic_given_zone"])
            if control["diagnostic_given_zone"] is not None and attack["diagnostic_given_zone"] is not None else None,
        "absolute_mean_gap_difference_s":
            abs(control["mean_within_identity_gap_s"] - attack["mean_within_identity_gap_s"])
            if control["mean_within_identity_gap_s"] is not None and attack["mean_within_identity_gap_s"] is not None else None,
        "absolute_identity_count_difference": abs(control["n_identities"] - attack["n_identities"]),
    }
    for family in FAMILIES:
        result[family + "_histogram_js_bits"] = js_divergence(control["histograms"][family],
                                                               attack["histograms"][family])
        result[family + "_frequency_abs_difference"] = abs(control["fraction_" + family] -
                                                             attack["fraction_" + family])
    return result
