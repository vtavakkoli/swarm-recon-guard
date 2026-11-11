"""One-command, fail-closed, reviewer-ready evidence finalization.

Executes replay, the individual-level/diagnostic/prefix/marginal controls,
regenerates reports, validates source provenance and creates a checksum-verified
archive. A historical run with missing or contradicted Git provenance is
*not* silently relabeled as if produced by the current version of the code.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import zipfile
from pathlib import Path

from swarmguard.detector.online import DetectorBundle
from swarmguard.experiment.replay import verify_replay
from swarmguard.experiment.reviewer_controls import evaluate
from swarmguard.reporting.report import build_report

REQUIRED = (
    "manifest.json", "integrity.json", "runs.jsonl", "event_traces.jsonl.gz",
    "window_traces.jsonl", "detector_bundle.json", "calibration.json",
    "reference_manifest.jsonl", "reference_events.jsonl.gz",
    "reference_windows.jsonl", "replay_checks.csv", "review_controls.json",
    "identity_baseline_calibration.json", "identity_baseline_runs.csv",
    "identity_baseline_summary.csv", "diagnostic_ablation_calibration.json",
    "diagnostic_ablation_runs.csv", "diagnostic_ablation_summary.csv",
    "prefix_control_runs.csv", "prefix_control_summary.csv",
    "observable_marginals.csv", "paired_marginal_diagnostics.csv",
    "online_summary.csv", "online_by_scenario.csv", "online_by_scale.csv",
    "online_generalization.csv", "service_metrics.csv", "report.html",
    "executive_summary.md", "final_evidence_validation.json",
)


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _filehash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_provenance(manifest: dict, run_dir: Path) -> dict:
    commit = str(manifest.get("git_commit", ""))
    image_commit = str(manifest.get("image_build_commit", ""))
    digest = str(manifest.get("source_tree_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Missing verified 40-digit Git revision; rebuild and rerun with SWARM_COMMIT")
    if commit != image_commit:
        raise ValueError(f"Experiment revision {commit} differs from Docker image revision {image_commit!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Missing source-code fingerprint; cannot certify old run with current code")
    if manifest.get("status") != "completed":
        raise ValueError("Only completed measured HTTP experiments may be published")
    integrity = _read(run_dir / "integrity.json")
    if not integrity.get("complete"):
        raise ValueError("Measured HTTP telemetry/run integrity is incomplete")
    calibration = _read(run_dir / "calibration.json")
    if "measured HTTP" not in calibration.get("reference_source", ""):
        raise ValueError("Publication evidence needs independent measured HTTP calibration")
    if not calibration.get("finite_thresholds"):
        raise ValueError("Finite-sample calibration cannot support requested alpha")
    if not _read(run_dir / "detector_bundle.json").get("contextual"):
        raise ValueError("COVE contextual detector absent from fitted model; rerun the current image")
    return {"git_commit": commit, "image_build_commit": image_commit,
            "source_tree_sha256": digest, "calibration_alpha": calibration["alpha"]}


def _audit_replay(run_dir: Path, expected_runs: int, n_methods: int) -> int:
    checks = verify_replay(run_dir)
    if len(checks) != expected_runs * n_methods:
        raise ValueError("Replay check count does not match runs x fitted detector methods")
    if not checks or any(not entry["matches"] for entry in checks):
        raise ValueError("Detector replay mismatch")
    return len(checks)


def _write_archive(run_dir: Path, target: Path, validation: dict) -> str:
    if target.resolve().is_relative_to(run_dir.resolve()):
        raise ValueError("Write evidence archive outside of source run directory")
    files = sorted(p for p in run_dir.iterdir() if p.is_file() and p.name != "artifact_checksums.sha256")
    present = {path.name for path in files}
    missing = sorted(set(REQUIRED) - present)
    if missing:
        raise ValueError(f"Evidence is incomplete; required outputs missing: {missing}")
    checksums = {path.name: _filehash(path) for path in files}
    manifest = _read(run_dir / "manifest.json")
    evidence = {
        "archive_schema": 2,
        "code_commit": validation["git_commit"],
        "image_build_commit": validation["image_build_commit"],
        "source_tree_sha256": validation["source_tree_sha256"],
        "suite_sha256": manifest.get("suite_sha256"),
        "run_count": manifest.get("run_count"),
        "calibration_alpha": validation["calibration_alpha"],
        "replay_checks_passed": validation["replay_checks_passed"],
        "files_sha256": checksums,
        "scope": "single synthetic HTTP test service; reference-only fitting and independent calibration",
        "scientific_status": "candidate experimental evidence, not independent real-world validation",
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
        info = zipfile.ZipInfo("evidence_manifest.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, json.dumps(evidence, sort_keys=True, indent=2).encode("utf-8"))
    # Verify the created ZIP before reporting success.
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Archive CRC verification failed")
        stored = json.loads(archive.read("evidence_manifest.json"))
        for name, digest in stored["files_sha256"].items():
            if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise RuntimeError(f"Archive checksum mismatch for {name}")
    return _filehash(target)


def finalize(run_dir: Path, output: Path, *, prefixes: tuple[int, ...] = (30, 300)) -> dict:
    run_dir = run_dir.resolve()
    manifest = _read(run_dir / "manifest.json")
    provenance = _check_provenance(manifest, run_dir)
    bundle = DetectorBundle.from_dict(_read(run_dir / "detector_bundle.json"))
    if set(bundle.thresholds) != set(bundle.score.__self__.thresholds):
        raise RuntimeError("Invalid detector bundle thresholds")
    print("[evidence] Checking full event replay", flush=True)
    replay_count = _audit_replay(run_dir, int(manifest["run_count"]), len(bundle.thresholds))
    print(f"[evidence] {replay_count} replayed decisions match", flush=True)
    print("[evidence] Individual OOD, diagnostic ablation, event-prefix and marginal controls", flush=True)
    evaluate(run_dir, alpha=float(provenance["calibration_alpha"]),
             prefixes=prefixes, diagnostics_ablation=True)
    runs = [json.loads(line) for line in (run_dir / "runs.jsonl").read_text().splitlines() if line.strip()]
    if len(runs) != int(manifest["run_count"]):
        raise ValueError("Experimental runs.jsonl count inconsistent with manifest")
    build_report(runs, manifest, run_dir)
    validation = {
        **provenance, "run_count": len(runs),
        "method_count": len(bundle.thresholds),
        "replay_checks_passed": replay_count,
        "reviewer_controls_completed": True, "prefixes": list(prefixes),
        "calibration_fpr_scope": (
            "complete-stream false-positive control under comparable exchangeable benign streams; "
            "not guaranteed by policy, scale or production traffic"
        ),
    }
    (run_dir / "final_evidence_validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True), encoding="utf-8")
    archive_sha = _write_archive(run_dir, output.resolve(), validation)
    return {"evidence_archive": str(output), "sha256": archive_sha, **validation}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefixes", default="30,300", help="Comma-separated positive event counts")
    args = parser.parse_args()
    prefixes = tuple(sorted(set(int(v) for v in args.prefixes.split(",") if v.strip())))
    if not prefixes or min(prefixes) < 1:
        parser.error("prefixes must be positive event counts")
    print(json.dumps(finalize(args.run_dir, args.output, prefixes=prefixes), indent=2))


if __name__ == "__main__":
    main()
