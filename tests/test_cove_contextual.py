from __future__ import annotations

import json
import math

import numpy as np
import pytest

from swarmguard.detector.contextual import ContextualCoordination, feature_vector
from swarmguard.detector.online import ALL_METHODS, DetectorBundle
from swarmguard.detector.streaming import StreamDetector
from swarmguard.detector.windows import extract_windows
from swarmguard.experiment.policies import BENIGN_SCENARIOS, KNOWN_ATTACK_SCENARIOS, reference_events
from swarmguard.experiment.publication import _check_provenance


CONFIG = {"window_events": 16, "window_seconds": 1.0, "min_window_events": 4}


def _row(label, discrepancy=10.0, gain=0.0, requests=120, identities=40):
    return {
        "label": label,
        "information_balance_chi2": discrepancy,
        "information_excess_gain": gain,
        "cumulative_requests": requests,
        "cumulative_identities": identities,
    }


def test_contextual_fit_uses_only_training_labels_and_gateway_features():
    streams = [
        [_row(0, 30 + i, 0, 120, 40)] * 3 for i in range(6)
    ] + [
        [_row(1, i + 2, 0.1, 120, 40)] * 3 for i in range(6)
    ]
    fitted = ContextualCoordination.fit(streams)
    assert fitted.score(_row(1, 2)) > fitted.score(_row(0, 35))
    row = _row(1, 2)
    changed = {**row, "label": 0, "scenario": "benign_explorer",
               "diagnostic_ratio": 1, "attacker_members": [0, 1]}
    assert fitted.score(changed) == fitted.score(row)
    restored = ContextualCoordination.from_dict(
        json.loads(json.dumps(fitted.to_dict()))
    )
    assert restored.score(row) == pytest.approx(fitted.score(row))
    assert feature_vector(row).shape == (4,)


def test_contextual_ignores_diagnostic_metadata_and_rejects_unfitted_shapes():
    row = _row(0, 11.5, 0.5)
    assert np.all(np.isfinite(feature_vector(row)))
    with pytest.raises(ValueError):
        feature_vector({**row, "information_balance_chi2": float("nan")})
    data = ContextualCoordination.fit([
        [_row(0, 30 + i)] for i in range(3)
    ] + [
        [_row(1, 3 + i)] for i in range(3)
    ]).to_dict()
    data["weights"] = [1.0, 2.0]
    with pytest.raises(ValueError):
        ContextualCoordination.from_dict(data)


def test_stream_balancing_prevents_long_runs_from_domination():
    # Duplicating windows inside a reference stream changes no per-stream mass.
    benign = [_row(0, 24), _row(0, 25)]
    attack = [_row(1, 2), _row(1, 3)]
    first = ContextualCoordination.fit([benign, benign, attack, attack])
    second = ContextualCoordination.fit([benign * 12, benign, attack * 12, attack])
    for row in benign + attack:
        assert first.score(row) == pytest.approx(second.score(row), abs=1e-5)


def test_full_bundle_contextual_is_serialized_calibrated_and_replayed():
    def sample(scenario, seed):
        events = reference_events(
            scenario, agent_count=20, requests_per_agent=3, seed=seed,
            repeat=0, arrival_window_ms=50,
        )
        windows = extract_windows(events, CONFIG)
        for row in windows:
            row.update({"scenario": scenario,
                        "label": int(scenario not in BENIGN_SCENARIOS)})
        return events, windows
    training = [
        sample(scenario, 90 + i)[1] for i in range(2)
        for scenario in BENIGN_SCENARIOS + KNOWN_ATTACK_SCENARIOS
    ]
    bundle = DetectorBundle.fit(training, seed=1, rff_dimensions=16)
    calibration = [sample(BENIGN_SCENARIOS[i % len(BENIGN_SCENARIOS)], 990 + i)[1]
                   for i in range(19)]
    assert bundle.calibrate(calibration, 0.10)["finite_thresholds"]
    assert "cove_contextual" in ALL_METHODS
    assert math.isfinite(bundle.thresholds["cove_contextual"])
    copy = DetectorBundle.from_dict(json.loads(json.dumps(bundle.to_dict())))
    events, _ = sample("matched_swarm", 2026)
    a, b = StreamDetector(bundle, CONFIG), StreamDetector(copy, CONFIG)
    for event in events:
        a.update(event)
        b.update(event)
    a.finalize()
    b.finalize()
    for key in ("peak_score", "detected", "requests_at_detection", "terminal_only_alarm"):
        assert a.snapshot()["methods"]["cove_contextual"][key] == b.snapshot()["methods"]["cove_contextual"][key]


def test_provenance_rejects_mislabeled_legacy_results(tmp_path):
    (tmp_path / "integrity.json").write_text(json.dumps({"complete": True}))
    (tmp_path / "calibration.json").write_text(json.dumps({
        "reference_source": "measured HTTP gateway telemetry",
        "finite_thresholds": True, "alpha": 0.1,
    }))
    (tmp_path / "detector_bundle.json").write_text(json.dumps({"contextual": {"schema_version": 1}}))
    p = {"git_commit": "a" * 40, "image_build_commit": "b" * 40,
         "source_tree_sha256": "0" * 64, "status": "completed"}
    with pytest.raises(ValueError, match="differs"):
        _check_provenance(p, tmp_path)
    p["image_build_commit"] = "a" * 40
    assert _check_provenance(p, tmp_path)["git_commit"] == "a" * 40
    p["source_tree_sha256"] = ""
    with pytest.raises(ValueError, match="fingerprint"):
        _check_provenance(p, tmp_path)
