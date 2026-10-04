from __future__ import annotations

import math
import statistics
import string
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from swarmguard.config import PERMIT_PREFIX_SPACE, TICKET_SPACE, TOTAL_SEMANTIC_SPACE, ZONE_SPACE

ALPHABET = string.digits + string.ascii_uppercase
FAMILY_SPACES = {"ticket": TICKET_SPACE, "permit_prefix": PERMIT_PREFIX_SPACE, "zone": ZONE_SPACE}


def _prefix_to_int(prefix: str) -> int | None:
    prefix = prefix.upper()
    if len(prefix) != 2 or any(c not in ALPHABET for c in prefix):
        return None
    return ALPHABET.index(prefix[0]) * 36 + ALPHABET.index(prefix[1])


def _normalized_entropy(counts: Counter[str]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    active = [v for k, v in counts.items() if k in FAMILY_SPACES and v > 0]
    if len(active) <= 1:
        return 0.0
    h = -sum((v / total) * math.log(v / total) for v in active)
    return h / math.log(len(FAMILY_SPACES))


def _gap_uniformity(values: set[int]) -> float:
    if len(values) < 4:
        return 0.0
    ordered = sorted(values)
    gaps = [b - a for a, b in zip(ordered, ordered[1:]) if b > a]
    if len(gaps) < 3:
        return 0.0
    mean_gap = statistics.fmean(gaps)
    if mean_gap <= 0:
        return 0.0
    std = statistics.pstdev(gaps)
    return 1.0 / (1.0 + std / mean_gap)


@dataclass
class RunRiskState:
    run_id: str
    threshold: float = 0.72
    min_events: int = 30
    consecutive_windows: int = 2
    evaluation_interval: int = 100
    requests: int = 0
    start_ts: float | None = None
    last_ts: float | None = None
    identities: set[str] = field(default_factory=set)
    keys: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    numeric: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    family_counts: Counter[str] = field(default_factory=Counter)
    diagnostic_count: int = 0
    score_peak: float = 0.0
    score_final: float = 0.0
    consecutive_above: int = 0
    detected: bool = False
    detection_ts: float | None = None
    coverage_at_detection: float | None = None

    def update(self, event: dict[str, str]) -> dict[str, float]:
        ts = float(event.get("ts", 0.0) or 0.0)
        if self.start_ts is None:
            self.start_ts = ts
        self.last_ts = ts
        self.requests += 1
        self.identities.add(event.get("identity", "anonymous"))
        family = event.get("family", "other")
        if family in FAMILY_SPACES:
            key = event.get("resource_key", "")
            self.keys[family].add(key)
            self.family_counts[family] += 1
            raw_numeric = event.get("numeric_key", "")
            if raw_numeric:
                try:
                    self.numeric[family].add(int(raw_numeric))
                except ValueError:
                    pass
            elif family == "permit_prefix":
                idx = _prefix_to_int(key)
                if idx is not None:
                    self.numeric[family].add(idx)
        if event.get("diagnostic") == "1":
            self.diagnostic_count += 1
        should_evaluate = self.requests >= self.min_events and (self.requests == self.min_events or self.requests % max(1, self.evaluation_interval) == 0)
        if not should_evaluate:
            return {}
        features = self.features()
        score = features["risk_score"]
        self.score_final = score
        self.score_peak = max(self.score_peak, score)
        self.consecutive_above = self.consecutive_above + 1 if score >= self.threshold else 0
        if not self.detected and self.consecutive_above >= self.consecutive_windows:
            self.detected = True
            self.detection_ts = ts
            self.coverage_at_detection = features["semantic_coverage"]
        return features

    def features(self) -> dict[str, float]:
        unique_total = sum(len(self.keys[f]) for f in FAMILY_SPACES)
        novelty = unique_total / self.requests if self.requests else 0.0
        identity_dispersion = len(self.identities) / self.requests if self.requests else 0.0
        diagnostic_ratio = self.diagnostic_count / self.requests if self.requests else 0.0
        family_entropy = _normalized_entropy(self.family_counts)
        spans, uniforms = [], []
        for family, space in FAMILY_SPACES.items():
            values = self.numeric[family]
            if len(values) >= 2:
                spans.append((max(values) - min(values)) / max(1, space - 1))
            if len(values) >= 4:
                uniforms.append(_gap_uniformity(values))
        namespace_span = statistics.fmean(spans) if spans else 0.0
        gap_uniformity = statistics.fmean(uniforms) if uniforms else 0.0
        semantic_coverage = unique_total / TOTAL_SEMANTIC_SPACE
        coverage_pressure = min(1.0, unique_total / max(100.0, 0.03 * TOTAL_SEMANTIC_SPACE))
        score = max(0.0, min(1.0, 0.18*novelty + 0.22*namespace_span + 0.20*gap_uniformity + 0.15*diagnostic_ratio + 0.15*family_entropy + 0.10*coverage_pressure))
        return {"risk_score":score,"semantic_coverage":semantic_coverage,"unique_resources":float(unique_total),"novelty_ratio":novelty,"identity_dispersion":identity_dispersion,"diagnostic_ratio":diagnostic_ratio,"family_entropy":family_entropy,"namespace_span":namespace_span,"gap_uniformity":gap_uniformity,"coverage_pressure":coverage_pressure}

    def snapshot(self) -> dict[str, object]:
        features = self.features()
        self.score_final = features["risk_score"]
        self.score_peak = max(self.score_peak, self.score_final)
        delay = None
        if self.detected and self.start_ts is not None and self.detection_ts is not None:
            delay = max(0.0, (self.detection_ts - self.start_ts) * 1000.0)
        return {"run_id":self.run_id,"requests":self.requests,"unique_identities":len(self.identities),"detected":self.detected,"score_peak":self.score_peak,"score_final":self.score_final,"detection_delay_ms":delay,"coverage_at_detection":self.coverage_at_detection,**features}
