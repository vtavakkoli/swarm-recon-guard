from __future__ import annotations

import json
import math

import numpy as np
import pytest

from swarmguard.detector.online import ALL_METHODS, DetectorBundle
from swarmguard.detector.streaming import StreamDetector
from swarmguard.detector.windows import extract_windows, graph_features
from swarmguard.experiment.policies import BENIGN_SCENARIOS, KNOWN_ATTACK_SCENARIOS, reference_events

CONFIG = {"window_events": 16, "window_seconds": 1.0, "min_window_events": 4}


def stream(scenario, n, seed):
    events = reference_events(scenario, agent_count=n, requests_per_agent=3, seed=seed, repeat=0, arrival_window_ms=50)
    rows = extract_windows(events, CONFIG)
    for row in rows:
        row.update({"scenario": scenario, "label": int(scenario not in BENIGN_SCENARIOS)})
    return events, rows


@pytest.fixture(scope="module")
def fitted_bundle():
    training = [stream(scenario, n, 100 + repeat)[1]
                for repeat in range(2) for n in (10, 40)
                for scenario in BENIGN_SCENARIOS + KNOWN_ATTACK_SCENARIOS]
    bundle = DetectorBundle.fit(training, seed=42, rff_dimensions=16)
    calibration = [stream(BENIGN_SCENARIOS[i % 4], (10, 40)[i % 2], 900 + i)[1] for i in range(24)]
    bundle.calibrate(calibration, 0.10)
    return bundle


def test_windows_preserve_short_tail_and_are_disjoint():
    events, rows = stream("coordinated_swarm", 10, 73)
    assert [row["window_requests"] for row in rows] == [16, 14]
    assert sum(row["window_requests"] for row in rows) == len(events)
    assert rows[-1]["cumulative_requests"] == 30
    assert rows[0]["end_ts"] <= rows[1]["start_ts"]


def test_graph_is_identity_renaming_invariant():
    events, _ = stream("matched_swarm", 40, 73)
    renamed = [{**event, "identity": "arbitrary-" + str(hash(event["identity"]))} for event in events]
    assert graph_features(events) == graph_features(renamed)


def test_prediction_ignores_scenario_and_hidden_membership(fitted_bundle):
    _, rows = stream("matched_swarm", 40, 4711)
    row = rows[0]
    stripped = {key: value for key, value in row.items() if key not in ("scenario", "label")}
    a = fitted_bundle.score(stripped, {})
    b = fitted_bundle.score({**stripped, "scenario": "benign", "label": 0, "attacker_count": 0}, {})
    assert a == b
    assert set(a) == set(ALL_METHODS)
    assert all(math.isfinite(score) for score in a.values())


def test_bundle_json_roundtrip_preserves_online_decisions(fitted_bundle):
    events, _ = stream("swarm_no_diagnostic", 40, 8128)
    clone = DetectorBundle.from_dict(json.loads(json.dumps(fitted_bundle.to_dict(), allow_nan=False)))
    a, b = StreamDetector(fitted_bundle, CONFIG), StreamDetector(clone, CONFIG)
    for event in events:
        a.update(event)
        b.update(event)
    a.finalize()
    b.finalize()
    for method in ALL_METHODS:
        for key in ("peak_score", "detected", "exposure_before_detection", "requests_at_detection"):
            assert a.snapshot()["methods"][method][key] == b.snapshot()["methods"][method][key]
    assert a.snapshot()["requests"] == 120


def test_small_stream_can_alarm_before_terminal_flush(fitted_bundle):
    clone = DetectorBundle.from_dict(fitted_bundle.to_dict())
    clone.thresholds = {name: math.inf for name in ALL_METHODS}
    clone.thresholds["heuristic"] = 0
    events, _ = stream("coordinated_swarm", 10, 123)
    detector = StreamDetector(clone, CONFIG)
    for event in events:
        detector.update(event)
    assert detector.snapshot()["methods"]["heuristic"]["requests_at_detection"] == 16
    detector.finalize()
    assert detector.snapshot()["windows_processed"] == 2
    with pytest.raises(RuntimeError):
        detector.update(events[0])


def test_calibration_uses_stream_maxima_and_separate_rank(fitted_bundle, monkeypatch):
    bundle = DetectorBundle.from_dict(fitted_bundle.to_dict())
    monkeypatch.setattr(bundle, "score", lambda row, state: {name: row["value"] for name in ALL_METHODS})
    calibration = [[{"label": 0, "value": i}, {"label": 0, "value": -999, "cumulative_requests": 2}]
                   for i in range(24)]
    for rows in calibration:
        rows[0]["cumulative_requests"] = 1
    report = bundle.calibrate(calibration, 0.10)
    assert report["rank_order"] == 23
    assert bundle.thresholds["heuristic"] == 22
    report = bundle.calibrate(calibration, 0.01)
    assert not report["finite_thresholds"]
    assert all(math.isinf(value) for value in bundle.thresholds.values())


def test_calibration_refuses_attack_contamination(fitted_bundle):
    bundle = DetectorBundle.from_dict(fitted_bundle.to_dict())
    with pytest.raises(ValueError, match="benign"):
        bundle.calibrate([[{"label": 1}]], 0.1)
