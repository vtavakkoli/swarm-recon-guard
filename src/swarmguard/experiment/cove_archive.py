"""Replay an existing evidence ZIP with COVE without retraining on test runs.

Example:
  python -m swarmguard.experiment.cove_archive \
      --archive results/reviewer-evidence.zip --output results/cove-audit

Exploratory retrospective analysis: the method was developed while inspecting
the original benchmark. A new frozen confirmatory experiment is still needed.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

from swarmguard.detector.information import information_scores
from swarmguard.detector.windows import WindowExtractor
from swarmguard.experiment.policies import BENIGN_SCENARIOS
from swarmguard.reporting.stats import wilson_interval

METHODS = ("cove", "cove_instant", "cove_balance")


def _jsonlines(archive: ZipFile, name: str) -> list[dict]:
    return [json.loads(line) for line in archive.read(name).decode("utf-8").splitlines()
            if line.strip()]


def _window_ends(archive: ZipFile, filename: str, id_field: str) -> dict[str, list[int]]:
    ends: dict[str, list[int]] = defaultdict(list)
    for row in _jsonlines(archive, filename):
        ends[row[id_field]].append(int(row["cumulative_requests"]))
    return dict(ends)


def _replay(archive: ZipFile, filename: str, id_field: str,
            window_config: dict, expected_ends: dict[str, list[int]]) -> dict[str, list[dict]]:
    """Causally regenerate the exact online non-overlapping windows from raw events."""
    result: dict[str, list[dict]] = {}
    current_id = None
    extractor = None
    count = 0
    method_state: dict = {}
    rows: list[dict] = []

    def add_row(row: dict, terminal: bool):
        # Preserve gateway-event exposure. Do not use labels or hidden membership.
        rows.append({"cumulative_requests": int(row["cumulative_requests"]),
                     "cumulative_coverage": float(row["cumulative_coverage"]),
                     "terminal_flush": terminal,
                     "scores": information_scores(row, method_state)})

    def finish(stream_id: str):
        assert extractor is not None
        tail = extractor.flush()
        if tail is not None:
            add_row(tail, terminal=True)
        counts = [row["cumulative_requests"] for row in rows]
        if counts != expected_ends.get(stream_id):
            raise ValueError(f"Window boundary mismatch for {stream_id}: {counts[:5]}")
        if counts[-1] != count:
            raise ValueError(f"Missing gateway events for {stream_id}")
        result[stream_id] = rows.copy()

    with gzip.open(archive.open(filename), "rt", encoding="utf-8") as fh:
        for line in fh:
            event = json.loads(line)
            stream_id = event.pop(id_field)
            if stream_id != current_id:
                if current_id is not None:
                    finish(current_id)
                if stream_id in result or stream_id not in expected_ends:
                    raise ValueError(f"Unexpected or noncontiguous stream {stream_id}")
                extractor = WindowExtractor(**window_config)
                method_state = {}
                rows = []
                count = 0
                current_id = stream_id
            count += 1
            row = extractor.update(event)
            if row is not None:
                add_row(row, terminal=False)
    if current_id is not None:
        finish(current_id)
    if set(result) != set(expected_ends):
        raise ValueError("Missing or extra streams in the evidence archive")
    return result


def _thresholds(
    reference: dict[str, list[dict]], calibration_ids: list[str], alpha: float,
) -> tuple[dict[str, float], int]:
    if not 0 < alpha < 1:
        raise ValueError("alpha must be in (0,1)")
    n = len(calibration_ids)
    rank = math.ceil((n + 1) * (1 - alpha))
    # Same finite-sample convention as DetectorBundle.calibrate.
    thresholds = {
        method: (sorted(max(row["scores"][method] for row in reference[k])
                        for k in calibration_ids)[rank - 1] if rank <= n else math.inf)
        for method in METHODS
    }
    return thresholds, rank


def _rates(rows: list[dict], method: str) -> dict:
    benign = [r for r in rows if r["label"] == 0]
    attack = [r for r in rows if r["label"] == 1]
    fp = sum(r[f"{method}_detected"] for r in benign)
    tp = sum(r[f"{method}_detected"] for r in attack)
    flo, fhi = wilson_interval(fp, len(benign))
    tlo, thi = wilson_interval(tp, len(attack))
    return {"method": method, "benign_runs": len(benign), "attack_runs": len(attack),
            "true_positives": tp, "false_positives": fp,
            "detection_rate": tp / len(attack) if attack else None,
            "false_positive_rate": fp / len(benign) if benign else None,
            "detection_wilson_95": [tlo, thi], "fpr_wilson_95": [flo, fhi]}


def audit(archive_path: Path, output: Path, alpha: float | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    with ZipFile(archive_path) as archive:
        calibration = json.loads(archive.read("calibration.json"))
        if calibration.get("reference_source", "").lower().find("http") < 0:
            raise ValueError("COVE archive evaluation requires measured HTTP references")
        alpha = float(calibration["alpha"] if alpha is None else alpha)
        config = calibration["window_config"]
        reference_meta = {r["stream_id"]: r for r in _jsonlines(archive, "reference_manifest.jsonl")}
        test_meta = {r["run_id"]: r for r in _jsonlines(archive, "runs.jsonl")}
        reference = _replay(
            archive, "reference_events.jsonl.gz", "stream_id", config,
            _window_ends(archive, "reference_windows.jsonl", "stream_id"),
        )
        ids = sorted(k for k, r in reference_meta.items() if r["phase"] == "calibration")
        if not ids or any(reference_meta[k]["scenario"] not in BENIGN_SCENARIOS for k in ids):
            raise ValueError("Reference calibration must use independent benign streams")
        thresholds, rank = _thresholds(reference, ids, alpha)
        measured = _replay(
            archive, "event_traces.jsonl.gz", "run_id", config,
            _window_ends(archive, "window_traces.jsonl", "run_id"),
        )
        rows = []
        for run_id, sequence in measured.items():
            meta = test_meta[run_id]
            record = {"run_id": run_id, "scenario": meta["scenario"],
                      "agent_count": meta["agent_count"], "repeat": meta["repeat"],
                      "label": int(meta["label"]), "requests": sequence[-1]["cumulative_requests"]}
            for name in METHODS:
                alarm = next((row for row in sequence if row["scores"][name] > thresholds[name]), None)
                record[f"{name}_detected"] = alarm is not None
                record[f"{name}_peak"] = max(row["scores"][name] for row in sequence)
                record[f"{name}_requests_at_alarm"] = alarm["cumulative_requests"] if alarm else None
                record[f"{name}_terminal_only"] = alarm["terminal_flush"] if alarm else None
                record[f"{name}_exposure_at_alarm_or_end"] = (
                    alarm["cumulative_coverage"] if alarm else sequence[-1]["cumulative_coverage"]
                )
            rows.append(record)
        rows.sort(key=lambda r: (r["agent_count"], r["scenario"], r["repeat"], r["run_id"]))
        with (output / "cove_archive_runs.csv").open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        comparisons = [_rates(rows, name) for name in METHODS]
        for scale in sorted({r["agent_count"] for r in rows}):
            comparisons += [dict(agent_count=scale, **_rates(
                [r for r in rows if r["agent_count"] == scale], name)) for name in METHODS]
        with (output / "cove_archive_summary.csv").open("w", newline="", encoding="utf-8") as fh:
            fields = list(dict.fromkeys(k for row in comparisons for k in row))
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(comparisons)
        result = {
            "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "alpha": alpha, "n_calibration": len(ids), "calibration_rank": rank,
            "finite_thresholds": rank <= len(ids),
            "thresholds": {key: value if math.isfinite(value) else None for key, value in thresholds.items()},
            "reference_source": calibration["reference_source"],
            "reference_streams_replayed": len(reference),
            "test_runs_replayed": len(measured),
            "methods": list(METHODS),
            "overall": comparisons[:len(METHODS)],
            "limitation": (
                "EXPLORATORY retrospective analysis of an already examined benchmark. "
                "No unseen-policy or service-level FPR guarantee; benign explorers are hard negatives. "
                "Do not describe differences as confirmatory or IEEE acceptance evidence."
            ),
        }
        (output / "cove_archive_manifest.json").write_text(
            json.dumps(result, indent=2, allow_nan=False), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--alpha", type=float)
    args = parser.parse_args()
    result = audit(args.archive, args.output, args.alpha)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
