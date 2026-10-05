from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from swarmguard.reporting.distributional import GaussianModel, evaluate_distributional


def _row(scenario: str, label: int, agents: int, repeat: int) -> dict[str, object]:
    jitter = repeat * 0.002 + (0.001 if agents == 100 else 0.0)
    if scenario == "benign_flash":
        base = [0.25, 0.10, 0.15, 0.01, 0.40, 0.02]
        score = 0.42 + jitter
    elif scenario == "independent_recon":
        base = [0.78, 0.75, 0.35, 0.30, 0.88, 0.18]
        score = 0.72 + jitter
    else:
        base = [0.90, 0.92, 0.86, 0.45, 0.92, 0.25]
        score = 0.82 + jitter
    names = (
        "novelty_ratio",
        "namespace_span",
        "gap_uniformity",
        "diagnostic_ratio",
        "family_entropy",
        "semantic_coverage",
    )
    values = [min(0.99, max(0.001, x + jitter)) for x in base]
    return {
        "scenario": scenario,
        "label": label,
        "agent_count": agents,
        "repeat": repeat,
        "detector_score_peak": score,
        **dict(zip(names, values)),
    }


def test_gaussian_model_prefers_nearby_points():
    x = np.asarray([[0.0, 0.0], [0.1, -0.1], [-0.1, 0.1], [0.05, 0.05]])
    model = GaussianModel.fit(x, shrinkage=0.2)
    near = model.mahalanobis_sq(np.asarray([[0.02, 0.01]]))[0]
    far = model.mahalanobis_sq(np.asarray([[3.0, 3.0]]))[0]
    assert near < far


def test_distributional_analysis_creates_cross_validated_outputs(tmp_path: Path):
    rows = []
    for repeat in range(4):
        for agents in (10, 100):
            rows.append(_row("benign_flash", 0, agents, repeat))
            rows.append(_row("independent_recon", 1, agents, repeat))
            rows.append(_row("coordinated_swarm", 1, agents, repeat))

    result = evaluate_distributional(rows, tmp_path, alpha=0.05, shrinkage=0.2)

    assert (tmp_path / "distributional_scores.csv").exists()
    assert (tmp_path / "distributional_summary.csv").exists()
    assert (tmp_path / "gaussian_diagnostics.json").exists()

    summaries = result["summary"]
    names = {(x["validation"], x["detector"]) for x in summaries}
    assert ("leave_repeat_out", "gaussian_ood") in names
    assert ("leave_repeat_out", "gaussian_llr") in names
    assert ("leave_repeat_out", "hybrid") in names
    hybrid = next(x for x in summaries if x["validation"] == "leave_repeat_out" and x["detector"] == "hybrid")
    assert hybrid["auroc"] > 0.95

    diagnostics = json.loads((tmp_path / "gaussian_diagnostics.json").read_text())
    assert diagnostics["dimension"] == 6
