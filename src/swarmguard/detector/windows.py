from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import numpy as np

from swarmguard.config import TOTAL_SEMANTIC_SPACE
from swarmguard.detector.model import FAMILY_SPACES, RunRiskState, _prefix_to_int

BASE_FEATURES = ("novelty_ratio", "namespace_span", "gap_uniformity", "diagnostic_ratio", "family_entropy", "semantic_coverage")
EXTENDED_FEATURES = BASE_FEATURES + ("cumulative_novelty", "cumulative_coverage")
GRAPH_FEATURES = ("cross_identity_novelty", "region_balance", "region_entropy", "identity_specialization", "temporal_progression", "component_fraction", "cumulative_cross_identity_novelty", "cumulative_region_balance")
CONTEXT_FEATURES = ("window_requests", "window_identities", "cumulative_requests", "cumulative_identities")


def context_vector(row: dict) -> np.ndarray:
    return np.asarray([1.0] + [math.log1p(float(row[name])) for name in CONTEXT_FEATURES])


def graph_features(events: list[dict[str, str]], bins: int = 16) -> dict[str, float]:
    owners: dict[tuple[str, str], str] = {}
    cross_repeats = 0
    per_identity: dict[str, Counter] = defaultdict(Counter)
    regions: dict[str, Counter] = defaultdict(Counter)
    series: dict[str, list[tuple[float, float]]] = defaultdict(list)
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != node:
            nxt = parent[node]
            parent[node] = root
            node = nxt
        return root

    for event in events:
        identity = event.get("identity", "anonymous")
        family, key = event.get("family", "other"), event.get("resource_key", "")
        if family not in FAMILY_SPACES:
            continue
        resource = (family, key)
        if resource in owners and owners[resource] != identity:
            cross_repeats += 1
        owners.setdefault(resource, identity)
        per_identity[identity][family] += 1
        raw = event.get("numeric_key", "")
        try:
            number = int(raw) if raw else _prefix_to_int(key) if family == "permit_prefix" else None
        except ValueError:
            number = None
        if number is None:
            continue
        normalized = min(1.0, max(0.0, number / max(1, FAMILY_SPACES[family] - 1)))
        region = min(bins - 1, int(normalized * bins))
        regions[family][region] += 1
        series[family].append((float(event.get("ts", 0)), normalized))
        left, right = find("identity:" + identity), find(f"region:{family}:{region}")
        parent[left] = right

    balances, entropies, progressions, specialization = [], [], [], []
    for family, counts in regions.items():
        values = np.asarray([counts.get(i, 0) for i in range(bins)], dtype=float)
        balances.append(float(1.0 / (1.0 + np.std(values) / max(1e-9, np.mean(values)))))
        probs = values[values > 0] / np.sum(values)
        entropies.append(float(-np.sum(probs * np.log(probs)) / math.log(bins)))
        pairs = np.asarray(series[family], dtype=float)
        if len(pairs) >= 4 and np.ptp(pairs[:, 0]) > 0 and np.ptp(pairs[:, 1]) > 0:
            progressions.append(float(abs(np.corrcoef(pairs.T)[0, 1])))
    for counts in per_identity.values():
        probs = np.asarray(list(counts.values()), dtype=float)
        probs /= np.sum(probs)
        specialization.append(float(1.0 + np.sum(probs * np.log(probs)) / math.log(len(FAMILY_SPACES))))
    components = Counter(find("identity:" + identity) for identity in per_identity)
    n = max(1, len(events))
    return {
        "cross_identity_novelty": 1.0 - cross_repeats / n,
        "region_balance": float(np.mean(balances)) if balances else 0.0,
        "region_entropy": float(np.mean(entropies)) if entropies else 0.0,
        "identity_specialization": float(np.mean(specialization)) if specialization else 0.0,
        "temporal_progression": float(np.mean(progressions)) if progressions else 0.0,
        "component_fraction": max(components.values(), default=0) / max(1, len(per_identity)),
        "graph_nodes": len(parent),
        "graph_edges": len(events),
    }


@dataclass
class WindowExtractor:
    window_events: int = 64
    window_seconds: float = 1.0
    min_window_events: int = 8
    initial_window_events: int = 16
    cumulative: RunRiskState = field(default_factory=lambda: RunRiskState("window", evaluation_interval=10**12))
    pending: list[dict[str, str]] = field(default_factory=list)
    index: int = 0
    resource_owners: dict[tuple[str, str], str] = field(default_factory=dict)
    cross_identity_repeats: int = 0
    cumulative_regions: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))

    def __post_init__(self):
        if self.window_events < self.min_window_events or min(self.initial_window_events, self.window_events) < self.min_window_events or self.min_window_events < 2 or self.window_seconds <= 0:
            raise ValueError("window size must exceed minimum >=2 and duration must be positive")

    def update(self, event: dict[str, str]) -> dict | None:
        self.cumulative.update(event)
        family, identity = event.get("family", "other"), event.get("identity", "anonymous")
        if family in FAMILY_SPACES:
            key = (family, event.get("resource_key", ""))
            if key in self.resource_owners and self.resource_owners[key] != identity:
                self.cross_identity_repeats += 1
            self.resource_owners.setdefault(key, identity)
            raw = event.get("numeric_key", "")
            try:
                numeric = int(raw) if raw else _prefix_to_int(key[1]) if family == "permit_prefix" else None
            except ValueError:
                numeric = None
            if numeric is not None:
                region = min(15, max(0, int(numeric / max(1, FAMILY_SPACES[family] - 1) * 16)))
                self.cumulative_regions[family][region] += 1
        self.pending.append(event)
        elapsed = float(event.get("ts", 0)) - float(self.pending[0].get("ts", 0))
        target_size = min(self.window_events, self.initial_window_events) if self.index == 0 else self.window_events
        if len(self.pending) >= target_size or (elapsed >= self.window_seconds and len(self.pending) >= self.min_window_events):
            return self.flush()
        return None

    def flush(self) -> dict | None:
        # No events are discarded. A short terminal window remains observable and
        # its request count enters the conditional model and calibration horizon.
        if not self.pending:
            return None
        local = RunRiskState("local", evaluation_interval=10**12)
        for event in self.pending:
            local.update(event)
        row = local.features()
        row.update(graph_features(self.pending))
        unique = sum(len(keys) for keys in self.cumulative.keys.values())
        balances = []
        for counts in self.cumulative_regions.values():
            values = np.asarray([counts.get(i, 0) for i in range(16)], dtype=float)
            balances.append(float(1 / (1 + np.std(values) / max(1e-9, np.mean(values)))))
        row.update({
            "window_index": self.index,
            "window_requests": len(self.pending),
            "window_identities": len(local.identities),
            "cumulative_requests": self.cumulative.requests,
            "cumulative_identities": len(self.cumulative.identities),
            "cumulative_coverage": unique / TOTAL_SEMANTIC_SPACE,
            "cumulative_novelty": unique / max(1, self.cumulative.requests),
            "cumulative_cross_identity_novelty": 1 - self.cross_identity_repeats / max(1, self.cumulative.requests),
            "cumulative_region_balance": float(np.mean(balances)) if balances else 0,
            "start_ts": float(self.pending[0].get("ts", 0)),
            "end_ts": float(self.pending[-1].get("ts", 0)),
            "unique_resources": sum(len(keys) for keys in local.keys.values()),
        })
        self.index += 1
        self.pending.clear()
        return row


def extract_windows(events: list[dict[str, str]], config: dict) -> list[dict]:
    extractor = WindowExtractor(**config)
    rows = []
    for event in events:
        row = extractor.update(event)
        if row is not None:
            rows.append(row)
    final = extractor.flush()
    if final is not None:
        rows.append(final)
    return rows
