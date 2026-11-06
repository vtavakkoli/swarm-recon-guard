"""Build a deterministic evidence archive after replay checks and control analyses.

No data are silently regenerated. Package a *completed* results directory,
record every included file's SHA-256, and bind the archive to a Git commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


def package(run_dir: Path, output: Path) -> str:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "completed":
        raise ValueError("Only completed studies may be archived")
    commit = manifest.get("git_commit", "")
    if not re.fullmatch(r"[a-f0-9]{40}", str(commit)):
        raise ValueError("Provide exact code SHA-1 through SWARM_COMMIT before running publication experiments")
    required = ("runs.jsonl", "detector_bundle.json", "calibration.json", "reference_manifest.jsonl",
                "reference_events.jsonl.gz", "event_traces.jsonl.gz", "window_traces.jsonl",
                "reference_windows.jsonl", "replay_checks.csv", "online_by_scenario.csv",
                "online_by_scale.csv", "online_summary.csv", "manifest.json")
    missing = [name for name in required if not (run_dir / name).is_file()]
    if missing:
        raise ValueError(f"Missing archive artifacts: {missing}. Run scripts/validate_results.py first")
    replay_checks = (run_dir / "replay_checks.csv").read_text(encoding="utf-8")
    if "False" in replay_checks:
        raise ValueError("Replay mismatch: refusing to package")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.resolve().is_relative_to(run_dir.resolve()):
        raise ValueError("Write the ZIP outside the run directory to avoid self-inclusion")
    files = sorted(p for p in run_dir.iterdir() if p.is_file()
                   and p.name != "artifact_checksums.sha256")
    checksums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    evidence = {
        "archive_schema": 1,
        "code_commit": commit,
        "study_config_sha256": manifest.get("suite_sha256"),
        "run_count": manifest.get("run_count"),
        "run_dir": run_dir.name,
        "files_sha256": checksums,
        "scope": "measured synthetic HTTP service traffic; no production validation",
    }
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in files:
            info = zipfile.ZipInfo(path.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("evidence_manifest.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, json.dumps(evidence, indent=2, sort_keys=True).encode(),
                    compress_type=zipfile.ZIP_DEFLATED)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = package(args.run_dir, args.output)
    print(f"{args.output} SHA256 {digest}")


if __name__ == "__main__":
    main()
