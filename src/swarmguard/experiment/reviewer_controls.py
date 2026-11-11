"""Reviewer control analyses from immutable run artifacts, without test-data fitting.

This module deliberately separates a low-budget identity baseline from the collective
detector and calibrates both on held-out benign *streams* (not individual requests).
For controlled synthetic laboratory data only; no public target endpoints are used.
"""
from __future__ import annotations

import argparse
import gzip
import json
import math
from collections import defaultdict
from pathlib import Path

import numpy as np

from swarmguard.detector.online import DetectorBundle
from swarmguard.detector.streaming import StreamDetector
from swarmguard.detector.windows import extract_windows
from swarmguard.experiment.policies import BENIGN_SCENARIOS, FAMILIES, SPACES, ALPHABET
from swarmguard.experiment.matching import marginal_profile, comparison
from swarmguard.reporting.report import _write_csv
from swarmguard.reporting.stats import wilson_interval

CONTROL_METHODS = ("heuristic", "conditional_ood", "hybrid_cusum", "graph", "cove", "cove_contextual")


def grouped_events(path: Path, key: str):
    """Yield one trace at a time to keep 10,000-identity studies memory-bounded."""
    opener = gzip.open if path.suffix == ".gz" else open
    current, rows = None, []
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            event = json.loads(line)
            stream = event.pop(key)
            if current is not None and stream != current:
                yield current, rows
                rows = []
            current = stream
            rows.append(event)
    if current is not None:
        yield current, rows


def _normalized_key(event):
    family, value = event.get("family", ""), str(event.get("resource_key", ""))
    if family not in SPACES:
        return None
    try:
        if family == "permit_prefix":
            n = ALPHABET.index(value[0]) * 36 + ALPHABET.index(value[1])
        else:
            n = int(value)
    except (IndexError, ValueError):
        return None
    return max(0.0, min(1.0, n / max(1, SPACES[family] - 1)))


def individual_features(events: list[dict]) -> np.ndarray:
    """One row per identity: endpoint mix, key positions, dispersion, diagnostics.

    Includes no attacker membership, scenario name, identity string, or global
    cross-identity counts. Features are available from a gateway request stream.
    """
    groups = defaultdict(list)
    for event in events:
        groups[str(event.get("identity", ""))].append(event)
    result = []
    for requests in groups.values():
        size = len(requests)
        families = [event.get("family") for event in requests]
        numeric = {family: [] for family in FAMILIES}
        for event in requests:
            family = event.get("family")
            value = _normalized_key(event)
            if family in numeric and value is not None:
                numeric[family].append(value)
        mix = [families.count(f) / size for f in FAMILIES]
        means = [float(np.mean(numeric[f])) if numeric[f] else 0.5 for f in FAMILIES]
        spread = [float(np.std(numeric[f])) if numeric[f] else 0.0 for f in FAMILIES]
        diag = sum(str(e.get("diagnostic", "0")) in ("1", "True", "true") for e in requests) / size
        timestamps = sorted(float(e.get("ts", 0)) for e in requests)
        gap = float(np.mean(np.diff(timestamps))) if len(timestamps) > 1 else 0.0
        result.append([math.log1p(size), *mix, *means, *spread, diag, math.log1p(max(0, gap))])
    return np.asarray(result, dtype=float).reshape((-1, 12))


class IndividualOOD:
    """Regularized one-class Mahalanobis baseline on single-identity vectors."""
    def __init__(self, shrinkage: float = 0.15):
        if not 0 < shrinkage <= 1:
            raise ValueError("shrinkage must be in (0, 1]")
        self.shrinkage = shrinkage
        self.mean = None
        self.precision = None
        self.threshold = math.inf

    def fit(self, streams):
        samples = [individual_features(events) for events in streams]
        samples = [values for values in samples if len(values)]
        if not samples:
            raise ValueError("missing benign identity-training streams")
        x = np.vstack(samples)
        if len(x) < 3:
            raise ValueError("at least three benign identities are required")
        self.mean = np.mean(x, axis=0)
        cov = np.cov(x, rowvar=False)
        scale = max(float(np.trace(cov)) / x.shape[1], 1e-4)
        cov = (1 - self.shrinkage) * cov + self.shrinkage * scale * np.eye(x.shape[1])
        cov += 1e-6 * np.eye(x.shape[1])
        self.precision = np.linalg.pinv(cov)
        return self

    def score(self, events):
        x = individual_features(events)
        if not len(x):
            return -math.inf
        diff = x - self.mean
        return float(np.max(np.sum((diff @ self.precision) * diff, axis=1)))

    def calibrate(self, streams, alpha):
        values = [self.score(events) for events in streams]
        self.threshold, rank = calibrated_threshold(values, alpha)
        return {"n_benign_streams": len(values), "rank": rank, "threshold": finite_or_none(self.threshold),
                "scope": "stream maximum of per-identity Mahalanobis scores; one alarm per stream"}


def calibrated_threshold(scores, alpha):
    if not 0 < alpha < 1 or not scores:
        raise ValueError("nonempty independent benign calibration and 0<alpha<1 required")
    rank = math.ceil((len(scores) + 1) * (1 - alpha))
    return (sorted(scores)[rank - 1] if rank <= len(scores) else math.inf), rank


def finite_or_none(value):
    return float(value) if value is not None and math.isfinite(float(value)) else None


def summary(records, grouping):
    groups = defaultdict(list)
    for row in records:
        groups[tuple(row[name] for name in grouping)].append(row)
    output = []
    for key, values in sorted(groups.items()):
        n = len(values)
        hits = sum(bool(row["detected"]) for row in values)
        lo, hi = wilson_interval(hits, n)
        output.append(dict(zip(grouping, key)) | {
            "n_runs": n, "alarms": hits, "alarm_rate": hits / n,
            "wilson95_low": lo, "wilson95_high": hi,
            "terminal_only_alarms": sum(bool(row.get("terminal_only_alarm")) for row in values),
            "mean_windows": sum(float(row.get("windows", 0)) for row in values) / n,
        })
    return output


def _scored_prefix(bundle, config, events, horizon):
    detector = StreamDetector(bundle, config, record_events=False)
    for event in events[:horizon]:
        detector.update(event)
    detector.finalize()
    snap = detector.snapshot()
    return {method: snap["methods"][method] for method in CONTROL_METHODS if method in snap["methods"]} | {
        "windows": snap["windows_processed"], "window_rows": detector.windows
    }


def evaluate(run_dir: Path, *, alpha: float = 0.01, prefixes=(30, 300), diagnostics_ablation=False):
    reference = run_dir / "reference_events.jsonl.gz"
    tests = run_dir / "event_traces.jsonl.gz"
    for path in (reference, tests, run_dir / "reference_manifest.jsonl",
                 run_dir / "detector_bundle.json", run_dir / "runs.jsonl"):
        if not path.is_file():
            raise FileNotFoundError(f"{path} is required; HTTP reference/test traces must be saved")
    meta = {m["stream_id"]: m for line in (run_dir / "reference_manifest.jsonl").read_text().splitlines()
            if (m := json.loads(line))}
    labels = {r["run_id"]: r for line in (run_dir / "runs.jsonl").read_text().splitlines()
              if (r := json.loads(line))}
    calibration = json.loads((run_dir / "calibration.json").read_text())
    config = calibration["window_config"]
    bundle = DetectorBundle.from_dict(json.loads((run_dir / "detector_bundle.json").read_text()))
    methods = tuple(method for method in CONTROL_METHODS if method in bundle.thresholds)
    training, benign_calibration = [], []
    calibration_prefix = defaultdict(list)
    ablation_train, ablation_cal = [], []

    for stream_id, events in grouped_events(reference, "stream_id"):
        phase = meta[stream_id]["phase"]
        if phase == "training" and meta[stream_id]["scenario"] in BENIGN_SCENARIOS:
            training.append(events)
        if phase == "calibration":
            benign_calibration.append(events)
            for horizon in prefixes:
                if len(events) >= horizon:
                    result = _scored_prefix(bundle, config, events, horizon)
                    for method in methods:
                        calibration_prefix[(horizon, method)].append(result[method]["peak_score"])
        if diagnostics_ablation:
            stripped = [{**e, "diagnostic": "0"} for e in events]
            rows = extract_windows(stripped, config)
            for row in rows:
                row["scenario"] = meta[stream_id]["scenario"]
                row["label"] = int(row["scenario"] not in BENIGN_SCENARIOS)
            if phase == "training":
                ablation_train.append(rows)
            elif phase == "calibration":
                ablation_cal.append(rows)
    baseline = IndividualOOD().fit(training)
    baseline_metadata = baseline.calibrate(benign_calibration, alpha)
    (run_dir / "identity_baseline_calibration.json").write_text(
        json.dumps(baseline_metadata, indent=2), encoding="utf-8")
    ablated = None
    if diagnostics_ablation:
        ablated = DetectorBundle.fit(
            ablation_train, seed=int(23), shrinkage=0.15,
            rff_dimensions=len(bundle.rff_phase), mmd_history=bundle.mmd_history,
            cusum_drift=bundle.cusum_drift,
        )
        ablation_meta = ablated.calibrate(ablation_cal, alpha)
        (run_dir / "diagnostic_ablation_calibration.json").write_text(
            json.dumps(ablation_meta, indent=2), encoding="utf-8")

    thresholds = {key: calibrated_threshold(scores, alpha)[0] for key, scores in calibration_prefix.items()}
    identity_rows, prefix_rows, ablation_rows, marginal_rows = [], [], [], []
    for run_id, events in grouped_events(tests, "run_id"):
        source = labels[run_id]
        if not source.get("measurement_valid", True):
            continue
        common = {key: source[key] for key in ("run_id", "scenario", "agent_count", "repeat", "label")}
        marginal_rows.append(common | marginal_profile(events))
        score = baseline.score(events)
        identity_rows.append(common | {"method": "per_identity_semantic_ood",
            "peak_score": score, "threshold": finite_or_none(baseline.threshold),
            "detected": score > baseline.threshold})
        for horizon in prefixes:
            if len(events) < horizon:
                continue  # never conflate an incomplete stream with an equal-length prefix
            sampled = _scored_prefix(bundle, config, events, horizon)
            for method in methods:
                threshold = thresholds.get((horizon, method), math.inf)
                observed = sampled[method]
                first_crossing = next((w for w in sampled["window_rows"]
                                       if w["scores"][method] > threshold), None)
                prefix_rows.append(common | {
                    "method": method, "event_prefix": horizon,
                    "n_calibration_streams": len(calibration_prefix[(horizon, method)]),
                    "peak_score": observed["peak_score"], "threshold": finite_or_none(threshold),
                    "detected": bool(observed["peak_score"] is not None and observed["peak_score"] > threshold),
                    "terminal_only_alarm": bool(first_crossing and first_crossing["terminal_flush"]),
                    "windows_to_alarm": first_crossing["window_index"] + 1 if first_crossing else None,
                    "windows": sampled["windows"],
                })
        if ablated:
            sampled = _scored_prefix(ablated, config, [{**e, "diagnostic": "0"} for e in events], len(events))
            for method in methods:
                observed = sampled[method]
                ablation_rows.append(common | {
                    "method": method, "peak_score": observed["peak_score"],
                    "threshold": finite_or_none(ablated.thresholds[method]),
                    "detected": observed["detected"],
                    "terminal_only_alarm": observed.get("terminal_only_alarm"),
                    "windows": sampled["windows"],
                })
    for name, values, groups in [
        ("identity_baseline", identity_rows, ("scenario", "agent_count")),
        ("prefix_control", prefix_rows, ("method", "event_prefix", "scenario", "agent_count")),
        ("diagnostic_ablation", ablation_rows, ("method", "scenario", "agent_count")),
    ]:
        _write_csv(run_dir / (name + "_runs.csv"), values)
        _write_csv(run_dir / (name + "_summary.csv"), summary(values, groups))
    _write_csv(run_dir / "observable_marginals.csv", marginal_rows)
    profiles = {(row["agent_count"], row["repeat"], row["scenario"]): row for row in marginal_rows}
    matches = []
    for benign, attack in (
        ("benign_explorer", "matched_swarm"),
        ("benign_explorer_diagnostic", "matched_swarm_diagnostic"),
        ("benign_explorer", "independent_recon_no_diagnostic"),
    ):
        for key in sorted({(row["agent_count"], row["repeat"]) for row in marginal_rows}):
            a, b = profiles.get((*key, benign)), profiles.get((*key, attack))
            if a and b:
                matches.append({"control_scenario": benign, "attack_scenario": attack,
                                "agent_count": key[0], "repeat": key[1], **comparison(a, b)})
    _write_csv(run_dir / "paired_marginal_diagnostics.csv", matches)
    metadata = {
        "alpha": alpha, "prefixes": list(prefixes),
        "methods": list(methods),
        "diagnostics_ablation": diagnostics_ablation,
        "baseline_calibration": baseline_metadata,
        "interpretation": [
            "One-class per-identity detector is trained only on benign reference identities; thresholds use held-out benign stream maxima.",
            "Matched event prefixes are eligible only when source stream contains at least that many events.",
            "Prefix thresholds are recalibrated on independent benign prefixes; scoring a forced terminal tail is explicitly non-prospective.",
            "No-diagnostic ablation refits and recalibrates on stripped reference telemetry; it is not evidence about counterfactual HTTP response payloads.",
            "Paired marginal checks compare diagnostic rates and per-family 16-bin key distributions at matched population and repeat.",
            "Calibration controls marginal stream false alarms only under comparable exchangeable benign horizons; not a per-scale production guarantee.",
        ],
    }
    (run_dir / "review_controls.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Run independent reviewer controls on saved HTTP artifacts")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--alpha", type=float, default=0.01)
    parser.add_argument("--prefixes", default="30,300")
    parser.add_argument("--diagnostic-ablation", action="store_true")
    args = parser.parse_args()
    horizons = tuple(sorted(set(int(v) for v in args.prefixes.split(",") if v.strip())))
    if not horizons or min(horizons) < 1:
        parser.error("all prefixes must be positive event counts")
    result = evaluate(args.run_dir, alpha=args.alpha, prefixes=horizons,
                      diagnostics_ablation=args.diagnostic_ablation)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
