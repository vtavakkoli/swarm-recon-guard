from __future__ import annotations

import json
import math
from collections import Counter

import pytest

from swarmguard.detector.information import (
    NO_EVIDENCE_SCORE,
    information_features,
    information_scores,
)
from swarmguard.detector.online import ALL_METHODS, DetectorBundle
from swarmguard.detector.streaming import StreamDetector
from swarmguard.detector.windows import extract_windows
from swarmguard.experiment.policies import BENIGN_SCENARIOS, KNOWN_ATTACK_SCENARIOS, reference_events


WINDOWS = {"window_events": 16, "window_seconds": 1.0, "min_window_events": 4}


def test_balanced_coverage_is_more_regular_than_concentrated_coverage():
    balanced = information_features(
        {"ticket": Counter({i: 3 for i in range(16)})},
        {"ticket": {str(i) for i in range(48)}},
    )
    skewed = information_features(
        {"ticket": Counter({0: 48})},
        {"ticket": {str(i) for i in range(48)}},
    )
    assert balanced["information_balance_chi2"] == pytest.approx(0.0)
    assert skewed["information_balance_chi2"] > 0.0
    assert balanced["information_excess_gain"] == pytest.approx(skewed["information_excess_gain"])
    assert balanced["information_active_families"] == 1.0


def test_empty_or_short_family_is_not_treated_as_attack_evidence():
    empty = information_features({}, {})
    short = information_features({"ticket": {0: 7}}, {"ticket": {"a"}})
    for result in (empty, short):
        assert result["information_balance_chi2"] == -NO_EVIDENCE_SCORE
        assert result["information_active_families"] == 0
        assert math.isfinite(result["information_excess_gain"])
    state = {}
    assert information_scores(empty, state)["cove_instant"] == NO_EVIDENCE_SCORE


def test_two_window_gate_and_ablations_have_distinct_scores():
    state = {}
    first = {"information_balance_chi2": 2.0, "information_excess_gain": 1.0}
    second = {"information_balance_chi2": 4.0, "information_excess_gain": 3.0}
    a = information_scores(first, state)
    b = information_scores(second, state)
    assert a["cove"] == NO_EVIDENCE_SCORE
    assert a["cove_instant"] == -1
    assert b["cove"] == -1
    assert b["cove_instant"] == -1
    assert b["cove_balance"] == -4


def test_information_features_ignore_identity_diagnostic_and_hidden_labels():
    events = reference_events(
        "matched_swarm", agent_count=40, requests_per_agent=3,
        seed=101, repeat=0, arrival_window_ms=50,
    )
    a = extract_windows(events, WINDOWS)
    disguised = [
        {**e, "identity": "other-" + e["identity"],
         "diagnostic": "1" if i % 2 else "0",
         "scenario": "benign_flash", "label": 0, "attacker": False}
        for i, e in enumerate(events)
    ]
    b = extract_windows(disguised, WINDOWS)
    for x, y in zip(a, b):
        assert {k: v for k, v in x.items() if k.startswith("information_")} == {
            k: v for k, v in y.items() if k.startswith("information_")
        }
    assert all(row["information_active_families"] >= 0 for row in a)


def test_bundle_calibrates_new_methods_and_replays_identically():
    config = WINDOWS
    def build(scenario, seed):
        events = reference_events(scenario, agent_count=20, requests_per_agent=3,
                                  seed=seed, repeat=0, arrival_window_ms=50)
        rows = extract_windows(events, config)
        for row in rows:
            row["scenario"] = scenario
            row["label"] = int(scenario not in BENIGN_SCENARIOS)
        return events, rows

    training = [build(scenario, 100 + i)[1] for i in range(2)
                for scenario in BENIGN_SCENARIOS + KNOWN_ATTACK_SCENARIOS]
    bundle = DetectorBundle.fit(training, seed=2026, rff_dimensions=16)
    calibration = [build(BENIGN_SCENARIOS[i % len(BENIGN_SCENARIOS)], 900 + i)[1]
                   for i in range(19)]
    result = bundle.calibrate(calibration, 0.10)
    assert result["finite_thresholds"]
    assert {"cove", "cove_instant", "cove_balance"} <= set(ALL_METHODS)
    assert set(bundle.thresholds) == set(ALL_METHODS)
    cloned = DetectorBundle.from_dict(json.loads(json.dumps(bundle.to_dict(), allow_nan=False)))
    events, _ = build("matched_swarm", 1908)
    a, b = StreamDetector(bundle, config), StreamDetector(cloned, config)
    for event in events:
        a.update(event)
        b.update(event)
    a.finalize()
    b.finalize()
    for name in ("cove", "cove_instant", "cove_balance"):
        assert a.snapshot()["methods"][name] == b.snapshot()["methods"][name]


def test_old_bundle_missing_cove_thresholds_can_still_be_replayed():
    # Regression guard for pre-COVE evidence packages with 13 methods.
    from swarmguard.detector.online import ALL_METHODS
    events = reference_events("benign_flash", agent_count=10, requests_per_agent=3,
                              seed=19, repeat=0, arrival_window_ms=50)
    # The online state API uses threshold membership to select archive-version methods.
    class LegacyBundle:
        thresholds = {"heuristic": math.inf}
        def score(self, row, state):
            return {"heuristic": float(row["risk_score"]), "cove": 1000.0}
    detector = StreamDetector(LegacyBundle(), WINDOWS)
    for event in events:
        detector.update(event)
    detector.finalize()
    assert set(detector.snapshot()["methods"]) == {"heuristic"}
    assert len(ALL_METHODS) > 13
