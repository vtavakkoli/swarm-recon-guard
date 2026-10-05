import numpy as np

from swarmguard.experiment.policies import SCENARIOS, attack_members, build_actions
from swarmguard.reporting.report import _classification
from swarmguard.reporting.stats import average_precision
from swarmguard.experiment.runner import attach_wall_exposure
from swarmguard.config import TOTAL_SEMANTIC_SPACE


def test_every_policy_has_equal_budget_and_seeded_repeats_vary():
    for scenario in SCENARIOS:
        actions = build_actions(scenario, agent_idx=7, agent_count=40, requests_per_agent=6, seed=42, repeat=0)
        assert len(actions) == 6
    a = build_actions("coordinated_swarm", agent_idx=7, agent_count=100, requests_per_agent=6, seed=42, repeat=0)
    b = build_actions("coordinated_swarm", agent_idx=7, agent_count=100, requests_per_agent=6, seed=42, repeat=1)
    assert a != b


def test_matched_individual_resource_marginals_and_collective_partition():
    values = {}
    for scenario in ("matched_swarm", "benign_explorer"):
        values[scenario] = [int(build_actions(scenario, agent_idx=i, agent_count=1000, requests_per_agent=3, seed=42, repeat=0)[0].path.rsplit("/", 1)[-1]) / 50000 for i in range(1000)]
        assert abs(np.mean(values[scenario]) - 0.5) < 0.04
    bins = np.histogram(values["matched_swarm"], bins=10, range=(0, 1))[0]
    assert np.all(bins == 100)
    assert len(attack_members(100, 0.20, 42, 0)) == 20


def test_benign_diagnostics_and_attack_without_diagnostics():
    benign = [build_actions("benign_diagnostic", agent_idx=i, agent_count=40, requests_per_agent=3, seed=42, repeat=0)[2] for i in range(40)]
    assert any(action.params["view"] == "diagnostic" for action in benign)
    attack = build_actions("swarm_no_diagnostic", agent_idx=1, agent_count=40, requests_per_agent=6, seed=42, repeat=0)
    assert all(action.params.get("view") != "diagnostic" for action in attack)


def test_exposure_summary_includes_missed_attacks():
    rows = [
        {"label": 1, "detected": True, "peak_score": 2, "exposure_before_detection": 0.2,
         "exposure_at_alarm_or_end": 0.2, "detection_delay_ms": 100, "requests_at_detection": 16},
        {"label": 1, "detected": False, "peak_score": 0.5, "exposure_before_detection": None,
         "exposure_at_alarm_or_end": 0.8, "detection_delay_ms": None, "requests_at_detection": None},
        {"label": 0, "detected": False, "peak_score": 0, "exposure_before_detection": None,
         "exposure_at_alarm_or_end": 0.1, "detection_delay_ms": None, "requests_at_detection": None},
    ]
    result = _classification(rows)
    assert result["ebd_detected_mean"] == 0.2
    assert result["exposure_at_alarm_or_end_mean"] == 0.5
    assert result["censored_miss_count"] == 1


def test_average_precision_ties_are_order_invariant():
    assert average_precision([1, 0, 1, 0], [0.5] * 4) == 0.5
    assert average_precision([0, 0, 1, 1], [0.5] * 4) == 0.5


def test_wall_exposure_accounts_for_telemetry_backlog():
    online = {
        "semantic_coverage": 3 / TOTAL_SEMANTIC_SPACE,
        "events": [{"ts": str(1000 + i), "family": "ticket", "resource_key": str(i)} for i in range(3)],
        "methods": {
            "alarm": {"detected": True, "alarm_wall_timestamp": 1001.5},
            "miss": {"detected": False},
        },
    }
    attach_wall_exposure(online)
    assert online["methods"]["alarm"]["wall_exposure_at_detection"] == 2 / TOTAL_SEMANTIC_SPACE
    assert online["methods"]["miss"]["wall_exposure_at_alarm_or_end"] == 3 / TOTAL_SEMANTIC_SPACE
