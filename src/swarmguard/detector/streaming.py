from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

from swarmguard.detector.online import ALL_METHODS, DetectorBundle
from swarmguard.detector.windows import WindowExtractor


@dataclass
class StreamDetector:
    bundle: DetectorBundle
    window_config: dict
    record_events: bool = True
    extractor: WindowExtractor = field(init=False)
    method_state: dict = field(default_factory=dict)
    windows: list[dict] = field(default_factory=list)
    alarms: dict[str, dict] = field(default_factory=dict)
    peaks: dict[str, float] = field(default_factory=lambda: {name: -math.inf for name in ALL_METHODS})
    processing_ns: int = 0
    start_ts: float | None = None
    finalized: bool = False
    events: list[dict[str, str]] = field(default_factory=list)

    def __post_init__(self):
        self.extractor = WindowExtractor(**self.window_config)

    def update(self, event: dict[str, str]) -> None:
        if self.finalized:
            raise RuntimeError("cannot append to a finalized stream")
        start = time.perf_counter_ns()
        if self.start_ts is None:
            self.start_ts = float(event["ts"])
        if self.record_events:
            self.events.append(event)
        row = self.extractor.update(event)
        if row is not None:
            self._score(row)
        self.processing_ns += time.perf_counter_ns() - start

    def _score(self, row: dict) -> None:
        scores = self.bundle.score(row, self.method_state)
        row["scores"] = scores
        self.windows.append(row)
        for name, score in scores.items():
            self.peaks[name] = max(self.peaks[name], score)
            threshold = self.bundle.thresholds.get(name, math.inf)
            if score > threshold and name not in self.alarms:
                self.alarms[name] = {
                    "window_index": row["window_index"], "timestamp": row["end_ts"],
                    "requests_at_detection": row["cumulative_requests"],
                    "exposure_before_detection": row["cumulative_coverage"],
                    "detection_delay_ms": 1000 * max(0.0, row["end_ts"] - float(self.start_ts)),
                }

    def finalize(self) -> None:
        if not self.finalized:
            start = time.perf_counter_ns()
            row = self.extractor.flush()
            if row is not None:
                self._score(row)
            self.processing_ns += time.perf_counter_ns() - start
            self.finalized = True

    def snapshot(self, include_windows: bool = False) -> dict:
        requests = self.extractor.cumulative.requests
        methods = {}
        coverage = sum(len(keys) for keys in self.extractor.cumulative.keys.values())
        from swarmguard.config import TOTAL_SEMANTIC_SPACE
        final_coverage = coverage / TOTAL_SEMANTIC_SPACE
        for name in ALL_METHODS:
            alarm = self.alarms.get(name)
            methods[name] = {
                "detected": alarm is not None,
                "peak_score": self.peaks[name] if math.isfinite(self.peaks[name]) else None,
                "threshold": self.bundle.thresholds[name] if math.isfinite(self.bundle.thresholds[name]) else None,
                "exposure_before_detection": alarm["exposure_before_detection"] if alarm else None,
                # Misses carry final exposure instead of disappearing from averages.
                "exposure_at_alarm_or_end": alarm["exposure_before_detection"] if alarm else final_coverage,
                "detection_delay_ms": alarm["detection_delay_ms"] if alarm else None,
                "requests_at_detection": alarm["requests_at_detection"] if alarm else None,
            }
        result = {
            "requests": requests, "windows_processed": len(self.windows), "finalized": self.finalized,
            "methods": methods, "semantic_coverage": final_coverage,
            "processing_ms": self.processing_ns / 1e6,
            "processing_us_per_event": self.processing_ns / 1000 / max(1, requests),
        }
        if include_windows:
            result["windows"] = self.windows
            if self.record_events:
                result["events"] = self.events
        return result
