from __future__ import annotations

import math

import numpy as np

from swarmguard.detector.online import ALL_METHODS, DetectorBundle
from swarmguard.detector.streaming import StreamDetector
from swarmguard.experiment.policies import build_actions, reference_events
from swarmguard.experiment.reviewer_controls import (
    IndividualOOD, calibrated_threshold, individual_features, summary,
)


def test_diagnostic_matched_policy_controls():
    # The new paired controls use the same 75% diagnostic probability and
    # independent, seed-stable resource selectors.
    for scenario in ("benign_explorer_diagnostic", "matched_swarm_diagnostic"):
        values = [build_actions(scenario, agent_idx=i, agent_count=1000,
                                requests_per_agent=3, seed=7, repeat=0)[2].params["view"]
                  for i in range(1000)]
        ratio = sum(value == "diagnostic" for value in values) / len(values)
        assert 0.69 < ratio < 0.81
    actions = build_actions("independent_recon_no_diagnostic", agent_idx=0,
                            agent_count=10, requests_per_agent=6, seed=7, repeat=0)
    assert all(a.params.get("view") != "diagnostic" for a in actions)


def test_single_identity_model_uses_no_hidden_labels():
    train = [reference_events("benign_explorer", agent_count=25,
                              requests_per_agent=3, seed=i, repeat=0)
             for i in range(4)]
    model = IndividualOOD().fit(train)
    tested = reference_events("matched_swarm", agent_count=25,
                              requests_per_agent=3, seed=19, repeat=0)
    stripped = [{k: v for k, v in row.items() if k not in ("scenario", "label", "attacker")}
                for row in tested]
    assert individual_features(tested).shape == (25, 12)
    assert math.isclose(model.score(tested), model.score(stripped))
    report = model.calibrate(train, alpha=0.1)
    assert not math.isfinite(model.threshold)  # 4 streams cannot resolve 10% FPR
    assert report["threshold"] is None


def test_stream_threshold_strict_ties():
    threshold, rank = calibrated_threshold([2.0] * 19, 0.1)
    assert rank == 18
    assert threshold == 2.0
    assert not 2.0 > threshold  # no alarm at a tied score


def test_summary_uses_run_units():
    rows = [dict(scenario="attack", agent_count=10, detected=(i == 0),
                 terminal_only_alarm=(i == 0), windows=2) for i in range(4)]
    result = summary(rows, ("scenario", "agent_count"))[0]
    assert result["n_runs"] == 4
    assert result["alarms"] == 1
    assert result["terminal_only_alarms"] == 1
    assert 0 <= result["wilson95_low"] < 0.25 < result["wilson95_high"] <= 1


def test_terminal_flush_is_identified():
    from swarmguard.detector.windows import extract_windows
    cfg = {"window_events": 16, "min_window_events": 4, "window_seconds": 5.0,
           "initial_window_events": 16}
    benign = []
    attack = []
    for i in range(5):
        for name, output in (("benign_explorer", benign), ("coordinated_swarm", attack)):
            rows = extract_windows(reference_events(name, agent_count=10,
                                  requests_per_agent=3, seed=i + 5, repeat=0), cfg)
            for row in rows:
                row["label"] = int(name == "coordinated_swarm")
                row["scenario"] = name
            output.append(rows)
    bundle = DetectorBundle.fit(benign + attack, rff_dimensions=8)
    bundle.thresholds = {name: math.inf for name in ALL_METHODS}
    bundle.thresholds["heuristic"] = -math.inf
    detector = StreamDetector(bundle, cfg)
    events = reference_events("coordinated_swarm", agent_count=3,
                              requests_per_agent=3, seed=50, repeat=0, arrival_window_ms=1)
    for event in events:
        detector.update(event)
    assert detector.snapshot()["methods"]["heuristic"]["detected"] is False
    detector.finalize()
    result = detector.snapshot()["methods"]["heuristic"]
    assert result["detected"] is True
    assert result["alarm_origin"] == "terminal_flush"
    assert result["terminal_only_alarm"] is True
    assert result["windows_to_alarm"] == 1



def test_paired_marginal_diagnostics_ignore_identity_spelling():
    from swarmguard.experiment.matching import marginal_profile, comparison, js_divergence
    stream = reference_events("benign_explorer_diagnostic", agent_count=20,
                              requests_per_agent=3, seed=51, repeat=0)
    profile = marginal_profile(stream)
    renamed = [{**e, "identity": "renamed-" + e["identity"]} for e in stream]
    other = marginal_profile(renamed)
    assert profile == other
    assert all(profile["histograms"][family] == other["histograms"][family]
               for family in ("ticket", "permit_prefix", "zone"))
    diff = comparison(profile, other)
    assert diff["absolute_zone_diagnostic_rate_difference"] == 0
    assert diff["ticket_histogram_js_bits"] == 0
    assert js_divergence([1, 0], [0, 1]) == 1
