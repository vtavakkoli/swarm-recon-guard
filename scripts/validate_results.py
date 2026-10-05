"""Assert report completeness and replay integrity for a measured CI suite."""
import csv
import json
import sys
from pathlib import Path

from swarmguard.detector.online import ALL_METHODS, METHODS
from swarmguard.experiment.replay import verify_replay
from swarmguard.reporting.report import build_report

root = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
directories = sorted((p for p in root.iterdir() if p.is_dir() and (p / "manifest.json").exists()), key=lambda p: p.name)
if not directories:
    raise SystemExit("No experiment output")
for directory in directories:
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["status"] == "completed", directory
    integrity = json.loads((directory / "integrity.json").read_text())
    assert integrity["complete"], integrity
    with (directory / "online_summary.csv").open() as fh:
        methods = {row["method"] for row in csv.DictReader(fh)}
    assert methods == set(ALL_METHODS), methods
    calibration = json.loads((directory / "calibration.json").read_text())
    assert calibration["finite_thresholds"], calibration
    references = [json.loads(line) for line in (directory / "reference_manifest.jsonl").read_text().splitlines()]
    training = {row["seed"] for row in references if row["phase"] == "training"}
    calibration_seeds = {row["seed"] for row in references if row["phase"] == "calibration"}
    assert training.isdisjoint(calibration_seeds)
    assert set(calibration["thresholds"]) == set(ALL_METHODS)
    for artifact in ("event_traces.jsonl.gz", "window_traces.jsonl", "service_metrics.csv",
                     "ablation_summary.csv", "online_generalization.csv", "executive_summary.md", "report.html"):
        assert (directory / artifact).stat().st_size > 0, artifact
    checks = verify_replay(directory)
    assert len(checks) == manifest["run_count"] * len(ALL_METHODS)
    runs = [json.loads(line) for line in (directory / "runs.jsonl").read_text().splitlines()]
    build_report(runs, manifest, directory)
    page = (directory / "report.html").read_text()
    assert all(method in page for method in METHODS)
    assert "replay_checks.csv" in page
    print(f"Validated {directory}: {manifest['run_count']} measured runs, {len(checks)} identical replay decisions")
