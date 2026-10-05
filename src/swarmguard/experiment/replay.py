from __future__ import annotations

import csv
import gzip
import json
import math
from pathlib import Path

from swarmguard.detector.online import DetectorBundle
from swarmguard.detector.streaming import StreamDetector


def verify_replay(run_dir: Path) -> list[dict]:
    bundle = DetectorBundle.from_dict(json.loads((run_dir / "detector_bundle.json").read_text()))
    calibration = json.loads((run_dir / "calibration.json").read_text())
    expected = {row["run_id"]: row for line in (run_dir / "runs.jsonl").read_text().splitlines() if line.strip()
                for row in [json.loads(line)]}
    checks = []
    seen = set()
    current_id = None
    detector: StreamDetector | None = None

    def finish(run_id, stream):
        stream.finalize()
        actual = stream.snapshot()
        reference = expected[run_id]["online"]
        for name, method in actual["methods"].items():
            original = reference["methods"][name]
            a, b = method["peak_score"], original["peak_score"]
            delta = abs(float(a) - float(b)) if a is not None and b is not None else 0 if a == b else math.inf
            score_equal = delta < 1e-8 * max(1, abs(float(b or 0)))
            exposure_equal = math.isclose(method["exposure_at_alarm_or_end"], original["exposure_at_alarm_or_end"], abs_tol=1e-12)
            matches = (score_equal and exposure_equal and method["detected"] == original["detected"] and
                       method["requests_at_detection"] == original["requests_at_detection"] and
                       actual["requests"] == expected[run_id]["telemetry_processed"])
            checks.append({"run_id": run_id, "method": name, "matches": matches,
                           "peak_score_difference": delta, "requests": actual["requests"]})
        seen.add(run_id)

    with gzip.open(run_dir / "event_traces.jsonl.gz", "rt", encoding="utf-8") as fh:
        for line in fh:
            event = json.loads(line)
            run_id = event.pop("run_id")
            if run_id != current_id:
                if detector is not None:
                    finish(current_id, detector)
                if run_id in seen or run_id not in expected:
                    raise ValueError("trace must contain each known run in one contiguous block")
                current_id = run_id
                detector = StreamDetector(bundle, calibration["window_config"], record_events=False)
            detector.update(event)
    if detector is not None:
        finish(current_id, detector)
    if seen != set(expected):
        raise ValueError("saved event traces do not cover every test run")
    with (run_dir / "replay_checks.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(checks[0]))
        writer.writeheader()
        writer.writerows(checks)
    if not all(check["matches"] for check in checks):
        raise RuntimeError("Replay differs from original online decisions; see replay_checks.csv")
    return checks
