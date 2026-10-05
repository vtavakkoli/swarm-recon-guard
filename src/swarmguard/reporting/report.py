from __future__ import annotations

import csv
import html
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from swarmguard.detector.online import ABLATIONS, METHODS
from swarmguard.experiment.policies import BENIGN_SCENARIOS, KNOWN_ATTACK_SCENARIOS
from swarmguard.reporting.distributional import evaluate_distributional
from swarmguard.reporting.stats import auroc, average_precision, describe, hedges_g, wilson_interval

METRICS = (
    "detected", "detector_score_peak", "detection_delay_ms", "exposure_before_detection",
    "semantic_coverage", "vulnerability_discovery_rate", "requests_per_second", "latency_p95_ms",
    "latency_p99_ms", "transport_error_rate", "sla_p95_delta_pct", "throughput_delta_pct",
    "per_identity_rule_triggered", "attacker_semantic_coverage", "information_bytes_received",
    "measurement_valid", "telemetry_failures",
)

METHOD_DESCRIPTIONS = {
    "heuristic": "Transparent six-feature score on each non-overlapping window.",
    "gaussian_ood": "Unconditional benign Gaussian Mahalanobis distance.",
    "gaussian_llr": "Known-attack Gaussian mixture versus unconditional benign Gaussian.",
    "conditional_ood": "Distance to the closest benign workload component after load-context regression.",
    "conditional_llr": "Known-attack versus benign mixtures conditioned on observed window and cumulative load.",
    "graph": "Conditional anomaly score of temporal bipartite graph descriptors, including complementary exploration.",
    "kernel_mmd": "Gaussian-kernel MMD approximation using fixed random Fourier features and recent window history.",
    "hybrid": "Training-standardized fusion of heuristic, conditional likelihood ratio and graph evidence.",
    "cusum": "Sequential accumulation of conditional log-likelihood ratios.",
    "hybrid_cusum": "Sequential accumulation of fused evidence with a fixed training-configured drift allowance.",
}


def _num(value):
    if value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _mean(values):
    clean = [x for value in values if (x := _num(value)) is not None]
    return statistics.fmean(clean) if clean else None


def _median(values):
    clean = [x for value in values if (x := _num(value)) is not None]
    return statistics.median(clean) if clean else None


def _fmt(value, percentage=False):
    value = _num(value)
    return "—" if value is None else f"{value:.1%}" if percentage else f"{value:.4g}"


def _interval(successes, n):
    lo, hi = wilson_interval(successes, n)
    return f"{successes / n:.1%} [{lo:.1%}, {hi:.1%}]" if n else "—"


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
                             for key, value in row.items()})


def _method_records(runs: list[dict]) -> list[dict]:
    records = []
    for run in runs:
        if not run.get("measurement_valid", True):
            continue
        for method, result in run.get("online", {}).get("methods", {}).items():
            records.append({
                "run_id": run["run_id"], "scenario": run["scenario"], "agent_count": run["agent_count"],
                "repeat": run["repeat"], "label": run["label"], "method": method,
                "known_attack": run["scenario"] in KNOWN_ATTACK_SCENARIOS,
                "final_coverage": run["semantic_coverage"],
                "processing_us_per_event": run["online"].get("processing_us_per_event"),
                "windows_processed": run["online"].get("windows_processed"), **result,
            })
    return records


def _classification(records: list[dict]) -> dict:
    benign = [row for row in records if int(row["label"]) == 0]
    attack = [row for row in records if int(row["label"]) == 1]
    fp = sum(bool(row["detected"]) for row in benign)
    tp = sum(bool(row["detected"]) for row in attack)
    tn, fn = len(benign) - fp, len(attack) - tp
    scored = [row for row in records if _num(row.get("peak_score")) is not None]
    labels = [int(row["label"]) for row in scored]
    scores = [float(row["peak_score"]) for row in scored]
    fpl, fph = wilson_interval(fp, len(benign))
    tpl, tph = wilson_interval(tp, len(attack))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(attack) if attack else None
    detected_attack = [row for row in attack if row["detected"]]
    exposure = describe([float(row["exposure_at_alarm_or_end"]) for row in attack])
    return {
        "n": len(records), "n_benign": len(benign), "n_attack": len(attack),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "auroc": auroc(labels, scores), "average_precision": average_precision(labels, scores),
        "false_positive_rate": fp / len(benign) if benign else None,
        "false_positive_wilson_low": fpl, "false_positive_wilson_high": fph,
        "detection_rate": recall, "detection_wilson_low": tpl, "detection_wilson_high": tph,
        "precision": precision, "f1": 2 * precision * recall / (precision + recall) if recall is not None and precision + recall else 0,
        "miss_rate": fn / len(attack) if attack else None,
        "ebd_detected_mean": _mean(row["exposure_before_detection"] for row in detected_attack),
        "exposure_at_alarm_or_end_mean": _num(exposure.mean),
        "exposure_ci95_low": _num(exposure.ci95_low), "exposure_ci95_high": _num(exposure.ci95_high),
        "detection_delay_median_ms": _median(row["detection_delay_ms"] for row in detected_attack),
        "detected_attack_count": len(detected_attack), "censored_miss_count": fn,
        "requests_at_detection_median": _median(row["requests_at_detection"] for row in detected_attack),
    }


def _group_methods(records: list[dict], grouping: tuple[str, ...]) -> list[dict]:
    groups = defaultdict(list)
    for row in records:
        groups[tuple(row[name] for name in grouping)].append(row)
    return [dict(zip(grouping, key)) | _classification(rows) for key, rows in sorted(groups.items())]


def _table(headers: list[str], rows: list[list[str]], *, filterable=False) -> str:
    return ('<div class="table-wrap"><table' + (' class="filterable"' if filterable else '') + '><thead><tr>' +
            "".join(f"<th>{html.escape(header)}</th>" for header in headers) +
            "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows) +
            "</tbody></table></div>")


def _bar_svg(rows: list[dict], metric: str, title: str, *, percent=True) -> str:
    rows = [row for row in rows if row.get("method") in METHODS and _num(row.get(metric)) is not None]
    if not rows:
        return "<p>No online observations.</p>"
    width, step, left = 720, 30, 155
    height = len(rows) * step + 50
    maximum = max(float(row[metric]) for row in rows)
    maximum = max(maximum, 1e-9)
    bars = []
    for i, row in enumerate(rows):
        y = i * step + 30
        value = float(row[metric])
        length = max(0, value) / maximum * 460
        bars.append(f'<text x="0" y="{y + 13}" fill="#475569" font-size="12">{html.escape(row["method"])}</text>'
                    f'<rect x="{left}" y="{y}" width="{length:.2f}" height="19" rx="3" fill="#0f766e"/>'
                    f'<text x="{left + length + 7:.2f}" y="{y + 13}" fill="#334155" font-size="12">{_fmt(value, percent)}</text>')
    return f'<svg role="img" aria-label="{html.escape(title)}" viewBox="0 0 {width} {height}">' + "".join(bars) + "</svg>"


def _representative_traces(out: Path) -> list[dict]:
    path = out / "window_traces.jsonl"
    if not path.exists():
        return []
    selected = defaultdict(list)
    metadata = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if int(row["repeat"]) != 0:
                continue
            key = row["run_id"]
            metadata[key] = {"scenario": row["scenario"], "agents": row["agent_count"], "run_id": key}
            selected[key].append({"requests": row["cumulative_requests"], "coverage": row["cumulative_coverage"], "scores": row["scores"]})
    traces = []
    for key, points in selected.items():
        if len(points) > 100:
            indices = sorted({round(i * (len(points) - 1) / 99) for i in range(100)})
            points = [points[i] for i in indices]
        traces.append(metadata[key] | {"points": points})
    return sorted(traces, key=lambda row: (row["agents"], row["scenario"]))


def build_report(runs: list[dict[str, object]], manifest: dict[str, object], out: Path) -> None:
    if not runs:
        raise ValueError("cannot build report without runs")
    baseline = {(int(row["agent_count"]), int(row["repeat"])): row for row in runs if row["scenario"] == "benign_flash"}
    for row in runs:
        benign = baseline.get((int(row["agent_count"]), int(row["repeat"])))
        if benign:
            for metric, output in (("latency_p95_ms", "sla_p95_delta_pct"), ("requests_per_second", "throughput_delta_pct")):
                value = float(benign[metric])
                row[output] = 100 * (float(row[metric]) - value) / value if value else 0.0
    _write_csv(out / "raw_metrics.csv", runs)
    groups = defaultdict(list)
    for row in runs:
        groups[(str(row["scenario"]), int(row["agent_count"]))].append(row)
    summaries = []
    for (scenario, n), rows in sorted(groups.items(), key=lambda item: (item[0][1], item[0][0])):
        record = {"scenario": scenario, "agent_count": n, "repeats": len(rows), "label": rows[0]["label"]}
        for metric in METRICS:
            summary = describe([x for row in rows if (x := _num(row.get(metric))) is not None])
            record.update({f"{metric}_{key}": value for key, value in vars(summary).items()})
        summaries.append(record)
    _write_csv(out / "summary.csv", summaries)
    effect_rows = []
    for n in sorted({int(row["agent_count"]) for row in runs}):
        benign = [row for row in runs if row["scenario"] == "benign_flash" and int(row["agent_count"]) == n]
        for scenario in sorted({str(row["scenario"]) for row in runs if int(row["label"]) == 1}):
            attack = [row for row in runs if row["scenario"] == scenario and int(row["agent_count"]) == n]
            for metric in ("detector_score_peak", "semantic_coverage", "vulnerability_discovery_rate"):
                effect_rows.append({"agent_count": n, "contrast": f"{scenario} vs benign_flash", "metric": metric,
                                    "hedges_g": hedges_g([float(row[metric]) for row in attack], [float(row[metric]) for row in benign])})
    _write_csv(out / "effect_sizes.csv", effect_rows)

    records = _method_records(runs)
    method_summary = _group_methods(records, ("method",))
    by_scale = _group_methods(records, ("method", "agent_count"))
    by_scenario = _group_methods(records, ("method", "scenario", "agent_count"))
    _write_csv(out / "online_scores.csv", records)
    _write_csv(out / "online_summary.csv", method_summary)
    _write_csv(out / "online_by_scale.csv", by_scale)
    _write_csv(out / "online_by_scenario.csv", by_scenario)
    _write_csv(out / "ablation_summary.csv", [row for row in method_summary if row["method"] in ABLATIONS + ("hybrid",)])
    generalization = []
    for method in sorted({row["method"] for row in records}):
        rows = [row for row in records if row["method"] == method]
        for regime in ("known", "unseen"):
            subset = [row for row in rows if int(row["label"]) == 0 or (row["known_attack"] == (regime == "known"))]
            generalization.append({"method": method, "attack_regime": regime, **_classification(subset)})
    _write_csv(out / "online_generalization.csv", generalization)
    service_rows = [{
        "scenario": row["scenario"], "agent_count": row["agent_count"], "repeat": row["repeat"],
        **{key: row.get(key) for key in ("requests", "duration_s", "requests_per_second", "latency_p50_ms",
                                       "latency_p95_ms", "latency_p99_ms", "transport_error_rate", "sla_p95_delta_pct",
                                       "throughput_delta_pct", "telemetry_processed", "telemetry_failures", "measurement_valid")},
        "detector_processing_us_per_event": row.get("online", {}).get("processing_us_per_event"),
        "windows_processed": row.get("online", {}).get("windows_processed"),
    } for row in runs]
    _write_csv(out / "service_metrics.csv", service_rows)
    legacy = [{"label": row["label"], "detected": row["detected"], "peak_score": row["detector_score_peak"],
               "exposure_before_detection": row["exposure_before_detection"],
               "exposure_at_alarm_or_end": row["exposure_before_detection"] if row["detected"] else row["semantic_coverage"],
               "detection_delay_ms": row["detection_delay_ms"], "requests_at_detection": None}
              for row in runs if row.get("measurement_valid", True)]
    classification = _classification(legacy)
    (out / "classification.json").write_text(json.dumps(classification, indent=2), encoding="utf-8")
    _write_csv(out / "classification_by_agents.csv", [
        {"agent_count": n, **_classification([record for record, run in zip(legacy, [r for r in runs if r.get("measurement_valid", True)]) if int(run["agent_count"]) == n])}
        for n in sorted({int(row["agent_count"]) for row in runs})
    ])
    suite = manifest.get("suite", {})
    stat_cfg = suite.get("statistical", {})
    distributional = {"summary": [], "diagnostics": {}}
    if stat_cfg.get("enabled", True):
        distributional = evaluate_distributional(
            [row for row in runs if row.get("measurement_valid", True)], out,
            alpha=float(stat_cfg.get("alpha", 0.01)), shrinkage=float(stat_cfg.get("shrinkage", 0.15)),
            hybrid_weight=float(stat_cfg.get("hybrid_weight", 0.5)),
            validation_modes=tuple(stat_cfg.get("validation_modes", ["leave_repeat_out", "leave_scale_out", "leave_attack_out"])),
        )
    calibration = manifest.get("calibration", {})
    if not calibration and (out / "calibration.json").exists():
        calibration = json.loads((out / "calibration.json").read_text())
    integrity = {
        "expected_runs": len(suite.get("scenarios", [])) * len(suite.get("agent_counts", [])) * int(suite.get("repeats", 1)),
        "observed_runs": len(runs), "invalid_runs": sum(not row.get("measurement_valid", True) for row in runs),
        "expected_requests": sum(int(row["expected_requests"]) for row in runs),
        "client_requests": sum(int(row["requests"]) for row in runs),
        "telemetry_processed": sum(int(row.get("telemetry_processed", row["requests"])) for row in runs),
        "telemetry_failures": sum(int(row.get("telemetry_failures", 0)) for row in runs),
    }
    integrity["complete"] = integrity["expected_runs"] in (0, len(runs)) and integrity["invalid_runs"] == 0 and integrity["expected_requests"] == integrity["telemetry_processed"]
    (out / "integrity.json").write_text(json.dumps(integrity, indent=2), encoding="utf-8")
    warnings = [
        "Synthetic policies and one municipal-style service do not establish production detection performance.",
        "Coordination is observable behavior, not proof of malicious intent; legitimate broad workflows are hard negative controls.",
        "Semantic coverage measures observed resource keys, not a verified percentage of reconstructed secret information.",
        "EBD among detected attacks is selection-biased; exposure at alarm or end and missed-attack counts are reported alongside it.",
        "Detection delay is gateway-event time to the first scored alarm window; it excludes additional deployment action latency.",
        "Detectors observe the whole experimental stream, including mixed benign and attacker identities; true membership is evaluator-only.",
        "The benchmark is observational: alarms do not block requests, so measured SLA differences are traffic effects, not mitigation benefits.",
        "Offline leave-scale/attack-out results use independent nested calibration but small folds cannot substantiate a 1% FPR.",
    ]
    if calibration:
        warnings.append(calibration["assumption"])
        if not calibration.get("finite_thresholds", True):
            warnings.append("Calibration sample size is insufficient for the requested alpha; thresholds are infinite and alarms disabled.")
        if max(int(row["expected_requests"]) for row in runs) > calibration.get("max_calibration_requests", 0):
            warnings.append("Test request horizons exceed calibration horizons; stream-level false-alarm control is not established for these longer streams.")
    if not integrity["complete"]:
        warnings.append("Measurement integrity is incomplete. Invalid runs are excluded from detector classification metrics.")
    (out / "limitations.json").write_text(json.dumps(warnings, indent=2), encoding="utf-8")
    selected = next((row for row in method_summary if row["method"] == "hybrid_cusum"), None)
    summary_text = (
        f"# SwarmReconGuard {manifest.get('version', '')}\n\n"
        f"Measured {len(runs)} HTTP runs and {integrity['client_requests']:,} requests. "
        f"Telemetry integrity: {'complete' if integrity['complete'] else 'incomplete'}.\n\n"
        "Online methods use independent reference training and benign stream calibration; calibration.json records whether the references were measured HTTP or policy simulation. "
        "HTTP test traces are not used for online fitting or threshold selection.\n\n"
    )
    if selected:
        summary_text += (f"Hybrid CUSUM: detection {_fmt(selected['detection_rate'], True)}, "
                         f"FPR {_fmt(selected['false_positive_rate'], True)}, "
                         f"missed attacks {selected['fn']}/{selected['n_attack']}, "
                         f"mean exposure at alarm or end {_fmt(selected['exposure_at_alarm_or_end_mean'], True)}.\n\n")
    summary_text += "## Limits\n\n" + "\n".join("- " + warning for warning in warnings) + "\n"
    (out / "executive_summary.md").write_text(summary_text, encoding="utf-8")

    online_table = _table(
        ["Method", "AUROC", "AP", "Detection [95% CI]", "FPR [95% CI]", "Precision", "Misses", "EBD, detected", "Exposure, alarm/end", "Median delay ms"],
        [[html.escape(row["method"]), _fmt(row["auroc"]), _fmt(row["average_precision"]),
          _interval(row["tp"], row["n_attack"]), _interval(row["fp"], row["n_benign"]),
          _fmt(row["precision"], True), f'{row["fn"]}/{row["n_attack"]}',
          _fmt(row["ebd_detected_mean"], True), _fmt(row["exposure_at_alarm_or_end_mean"], True),
          _fmt(row["detection_delay_median_ms"])] for row in method_summary if row["method"] in METHODS],
    )
    scale_table = _table(
        ["Method", "Agents", "Detection", "FPR", "AUROC", "Exposure, alarm/end", "Misses"],
        [[html.escape(row["method"]), f'{row["agent_count"]:,}', _fmt(row["detection_rate"], True),
          _fmt(row["false_positive_rate"], True), _fmt(row["auroc"]),
          _fmt(row["exposure_at_alarm_or_end_mean"], True), str(row["fn"])] for row in by_scale if row["method"] in METHODS], filterable=True,
    )
    scenario_table = _table(
        ["Method", "Scenario", "Agents", "Alarm rate", "Exposure, alarm/end", "Median delay ms", "Runs"],
        [[html.escape(row["method"]), html.escape(row["scenario"]), str(row["agent_count"]),
          _fmt(row["detection_rate"] if row["n_attack"] else row["false_positive_rate"], True),
          _fmt(row["exposure_at_alarm_or_end_mean"], True), _fmt(row["detection_delay_median_ms"]), str(row["n"])]
         for row in by_scenario if row["method"] in METHODS], filterable=True,
    )
    service_table = _table(
        ["Scenario", "Agents", "Coverage", "Campaign discovery", "p95 ms", "p99 ms", "req/s", "p95 Δ%", "Transport errors"],
        [[html.escape(row["scenario"]), str(row["agent_count"]), _fmt(row["semantic_coverage_mean"], True),
          _fmt(row["vulnerability_discovery_rate_mean"], True), _fmt(row["latency_p95_ms_mean"]),
          _fmt(row["latency_p99_ms_mean"]), _fmt(row["requests_per_second_mean"]),
          _fmt(row["sla_p95_delta_pct_mean"]), _fmt(row["transport_error_rate_mean"], True)] for row in summaries], filterable=True,
    )
    cv_table = _table(
        ["Offline validation", "Method", "Macro AUROC", "Macro AP", "Detection", "FPR"],
        [[html.escape(row["validation"]), html.escape(row["detector"]), _fmt(row["macro_auroc_mean"]),
          _fmt(row["macro_ap_mean"]), _fmt(row["detection_rate"], True), _fmt(row["false_positive_rate"], True)]
         for row in distributional["summary"]],
    )
    generalization_table = _table(
        ["Method", "Attack policies", "Detection", "FPR", "AUROC", "Misses"],
        [[html.escape(row["method"]), row["attack_regime"], _fmt(row["detection_rate"], True),
          _fmt(row["false_positive_rate"], True), _fmt(row["auroc"]), str(row["fn"])]
         for row in generalization if row["method"] in METHODS], filterable=True,
    )
    ablation_table = _table(
        ["Fusion variant", "AUROC", "Detection", "FPR", "Exposure, alarm/end"],
        [[html.escape(row["method"]), _fmt(row["auroc"]), _fmt(row["detection_rate"], True),
          _fmt(row["false_positive_rate"], True), _fmt(row["exposure_at_alarm_or_end_mean"], True)]
         for row in method_summary if row["method"] in ABLATIONS + ("hybrid",)],
    )
    artifacts = [path for path in sorted(out.iterdir()) if path.is_file() and path.name != "report.html"]
    links = "".join(f'<li><a href="{html.escape(path.name)}">{html.escape(path.name)}</a> <small>{path.stat().st_size / 1024:.1f} KiB</small></li>' for path in artifacts)
    explanations = "".join(f'<dt>{html.escape(name)}</dt><dd>{html.escape(description)}</dd>' for name, description in METHOD_DESCRIPTIONS.items())
    traces = _representative_traces(out)
    payload = json.dumps({"traces": traces, "thresholds": calibration.get("thresholds", {}),
                          "methods": list(METHODS)}, allow_nan=False).replace("<", "\\u003c")
    issues = "".join(f"<li>{html.escape(warning)}</li>" for warning in warnings)
    cards = [
        ("Measured runs", f"{len(runs):,}"), ("HTTP requests", f"{integrity['client_requests']:,}"),
        ("Online methods", str(len(METHODS))), ("Calibration streams", str(calibration.get("n_calibration_streams", 0))),
    ]
    card_html = "".join(f'<div class="card"><span>{label}</span><strong>{value}</strong></div>' for label, value in cards)
    operational = ""
    if selected:
        operational = (f'<p class="lead">Hybrid CUSUM detected <strong>{_fmt(selected["detection_rate"], True)}</strong> of attack runs; '
                       f'benign false alarms were <strong>{_fmt(selected["false_positive_rate"], True)}</strong>. '
                       f'<strong>{selected["fn"]}</strong> attack runs were missed. '
                       f'Mean exposure at alarm or run end was <strong>{_fmt(selected["exposure_at_alarm_or_end_mean"], True)}</strong>.</p>')
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SwarmReconGuard comprehensive benchmark</title><style>
:root{{color-scheme:light;--ink:#102438;--muted:#526477;--line:#dce5ed;--accent:#0f766e}}
*{{box-sizing:border-box}}body{{margin:0;background:#f3f7fa;color:var(--ink);font:15px/1.6 system-ui,sans-serif}}
header{{background:#102438;color:white;padding:38px max(24px,calc((100vw - 1280px)/2));border-bottom:5px solid #20b8a0}}
header p{{color:#c6d7e5;max-width:850px}}h1{{margin:0;font-size:36px;letter-spacing:-1px}}h2{{font-size:22px;margin-top:0}}h3{{font-size:17px}}
main{{max-width:1328px;margin:auto;padding:24px}}nav{{display:flex;flex-wrap:wrap;gap:14px;margin:16px 0}}a{{color:#08736d}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}.card,section{{background:white;border:1px solid var(--line);border-radius:12px;padding:22px}}
.card span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px}}.card strong{{font-size:30px}}section{{margin-top:20px}}
.lead{{font-size:17px}}.status{{padding:7px 12px;background:#e7f6f0;border-radius:7px;color:#065f46;display:inline-block}}.columns{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}}th{{background:#eef5f8;position:sticky;top:0}}th:first-child,td:first-child,td:nth-child(2){{text-align:left}}
small,.note{{color:var(--muted)}}pre{{background:#f0f5f8;border-radius:8px;padding:15px;overflow:auto;font-size:12px}}svg{{width:100%;height:auto}}select,input{{padding:9px;border:1px solid #b7c9d7;border-radius:6px;background:white;margin:5px 8px 10px 0}}
dt{{font-weight:650;margin-top:12px}}dd{{margin-left:0;color:var(--muted)}}.artifacts{{columns:2}}.warning{{border-left:4px solid #d49a24}}.authors{{font-size:13px}}
@media(max-width:800px){{.cards,.columns{{grid-template-columns:1fr 1fr}}header{{padding:24px}}main{{padding:12px}}.artifacts{{columns:1}}}}@media print{{nav,input,select{{display:none}}section{{break-inside:avoid}}body{{background:white}}}}
</style></head><body>
<header><h1>SwarmReconGuard</h1><p>Comprehensive comparison of collective reconnaissance detection, early exposure, benign false alarms and service performance.</p>
<p class="authors">Vahid Tavakkoli · Kabeh Mohsenzadegan · Kyamakya Kyandoghere · v{html.escape(str(manifest.get("version", "")))}</p></header>
<main><nav><a href="#online">Online results</a><a href="#traces">Alarm trajectories</a><a href="#scale">Scale &amp; scenarios</a><a href="#generalization">Generalization</a><a href="#service">Service quality</a><a href="#calibration">Calibration</a><a href="#artifacts">Artifacts</a></nav>
<div class="cards">{card_html}</div><section><span class="status">Measurement integrity: {"complete" if integrity["complete"] else "incomplete"}</span>{operational}
<p class="note">HTTP test runs are separate from training and calibration. The reference source is recorded below; publication uses measured gateway traffic for all three phases. A configured false-alarm target is not a measured production guarantee.</p></section>
<section id="online"><h2>Online detector comparison</h2>{online_table}
<p class="note">95% Wilson intervals describe independent run outcomes. Delay and EBD among detected attacks exclude misses; the adjacent exposure-at-alarm-or-end metric includes every attack run. Precision/AP reflect this benchmark's class proportions.</p>
<div class="columns"><div><h3>Detection rate</h3>{_bar_svg(method_summary, "detection_rate", "Detection rate")}</div>
<div><h3>Exposure at alarm or end</h3>{_bar_svg(method_summary, "exposure_at_alarm_or_end_mean", "Exposure at alarm or end")}</div></div></section>
<section id="traces"><h2>Alarm score trajectories</h2><p class="note">Predetermined repetition 0 for each scenario and population. Curves are downsampled for display; all windows and raw gateway events are saved in the artifacts.</p>
<select id="traceSelect" aria-label="Traffic scenario"></select><select id="methodSelect" aria-label="Detector method"></select><div id="trajectory"></div><p id="traceNote" class="note"></p></section>
<section id="scale"><h2>Population and traffic controls</h2><input id="filter" placeholder="Filter tables by method, scenario or scale" aria-label="Filter result tables">
<h3>Population scale</h3>{scale_table}<h3>Scenario-specific alarms</h3>{scenario_table}</section>
<section id="generalization"><h2>Generalization and component ablations</h2>{generalization_table}
<p class="note">Known attack references contain only the configured training policies. “Unseen” policies are excluded from online attack-model fitting. The model may know the tested population sizes; offline leave-scale-out evaluation below is a separate experiment.</p>
<h3>Remove one fusion component</h3>{ablation_table}<p class="note">Each ablation has its own independently calibrated stream-maximum threshold; comparisons do not reuse the full hybrid threshold.</p>
<h3>Offline cross-validation of completed-run features</h3>{cv_table}
<p class="note">These offline models are refitted inside each fold. Nested benign calibration runs are excluded from density fitting. Macro AUROC/AP avoid assuming raw scores are calibrated across folds; small calibration folds limit threshold claims.</p></section>
<section id="service"><h2>Service quality and information acquisition</h2>{service_table}
<p class="note">Cell means are shown here. SD and 95% Student-t intervals are in summary.csv. SLA deltas compare the same population/repetition with benign_flash, with randomized execution order. Detector processing cost is measured separately in service_metrics.csv. No mitigation is active.</p></section>
<section id="calibration"><h2>Calibration, assumptions and reproducibility</h2><div class="columns"><div><h3>Detector definitions</h3><dl>{explanations}</dl></div>
<div><h3>Independent reference calibration</h3><pre>{html.escape(json.dumps(calibration, indent=2, sort_keys=True))}</pre><h3>Measurement integrity</h3><pre>{html.escape(json.dumps(integrity, indent=2))}</pre></div></div>
<details><summary>Full experiment manifest and Gaussian diagnostics</summary><pre>{html.escape(json.dumps(manifest, indent=2, sort_keys=True))}</pre><pre>{html.escape(json.dumps(distributional["diagnostics"], indent=2))}</pre></details></section>
<section class="warning"><h2>Interpretation and limitations</h2><ul>{issues}</ul></section>
<section id="artifacts"><h2>Reproducible artifacts</h2><ul class="artifacts">{links}</ul><p class="note">The HTML report is self-contained and needs no Internet connection. Its artifact links refer to adjacent files in this result directory.</p></section>
</main><script type="application/json" id="traceData">{payload}</script><script>
const data=JSON.parse(document.getElementById("traceData").textContent);
const traceSelect=document.getElementById("traceSelect"), methodSelect=document.getElementById("methodSelect");
data.traces.forEach((t,i)=>{{const o=document.createElement("option");o.value=i;o.textContent=t.scenario+" · "+t.agents+" agents";traceSelect.appendChild(o);}});
data.methods.forEach(m=>{{const o=document.createElement("option");o.value=m;o.textContent=m;methodSelect.appendChild(o);}});
methodSelect.value="hybrid_cusum";
function draw(){{
 const t=data.traces[Number(traceSelect.value)],m=methodSelect.value;
 if(!t){{document.getElementById("trajectory").textContent="No online trace data.";return;}}
 const p=t.points.filter(p=>Number.isFinite(p.scores[m])),h=data.thresholds[m];
 if(!p.length)return;
 const w=1000,height=280,left=65,right=20,top=20,bottom=45;
 const maxX=Math.max(...p.map(p=>p.requests),1),vals=p.map(p=>p.scores[m]);
 if(Number.isFinite(h))vals.push(h);
 const minY=Math.min(0,...vals),maxY=Math.max(1,...vals);
 const x=v=>left+v/maxX*(w-left-right),y=v=>height-bottom-(v-minY)/Math.max(1e-9,maxY-minY)*(height-top-bottom);
 const points=p.map(p=>x(p.requests).toFixed(2)+","+y(p.scores[m]).toFixed(2)).join(" ");
 let svg='<svg role="img" aria-label="Detector score by observed request count" viewBox="0 0 '+w+' '+height+'">';
 svg+='<line x1="'+left+'" y1="'+(height-bottom)+'" x2="'+(w-right)+'" y2="'+(height-bottom)+'" stroke="#94a3b8"/>';
 svg+='<line x1="'+left+'" y1="'+top+'" x2="'+left+'" y2="'+(height-bottom)+'" stroke="#94a3b8"/>';
 svg+='<polyline points="'+points+'" fill="none" stroke="#0f766e" stroke-width="2"/>';
 if(Number.isFinite(h))svg+='<line x1="'+left+'" y1="'+y(h)+'" x2="'+(w-right)+'" y2="'+y(h)+'" stroke="#d97706" stroke-dasharray="5 4"/><text x="'+(left+6)+'" y="'+Math.max(15,y(h)-6)+'" font-size="12" fill="#b45309">calibrated alarm threshold</text>';
 svg+='<text x="'+left+'" y="'+(height-12)+'" font-size="12">0</text><text x="'+(w-75)+'" y="'+(height-12)+'" font-size="12">'+maxX+'</text>';
 svg+='<text x="8" y="'+(top+8)+'" font-size="12">'+maxY.toPrecision(3)+'</text><text x="8" y="'+(height-bottom)+'" font-size="12">'+minY.toPrecision(3)+'</text>';
 svg+='<text x="'+(w/2-70)+'" y="'+(height-10)+'" font-size="12">observed requests</text></svg>';
 document.getElementById("trajectory").innerHTML=svg;
 document.getElementById("traceNote").textContent="Final observed namespace coverage: "+(100*p[p.length-1].coverage).toFixed(2)+"%. Scores crossing the orange threshold indicate an alarm; later traffic continues because no blocking is enabled.";
}}
traceSelect.addEventListener("change",draw);methodSelect.addEventListener("change",draw);draw();
document.getElementById("filter").addEventListener("input",e=>{{const q=e.target.value.toLowerCase();document.querySelectorAll("table.filterable tbody tr").forEach(tr=>{{tr.hidden=!tr.textContent.toLowerCase().includes(q);}});}});
</script></body></html>"""
    (out / "report.html").write_text(page, encoding="utf-8")
