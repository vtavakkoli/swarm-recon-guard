from __future__ import annotations

import hashlib
import csv
import gzip
import json
import random
import time
from pathlib import Path

from swarmguard.detector.online import DetectorBundle
from swarmguard.detector.windows import extract_windows
from swarmguard.experiment.policies import ATTACK_SCENARIOS, BENIGN_SCENARIOS, KNOWN_ATTACK_SCENARIOS, reference_events


def phase_seed(seed: int, phase: str, stream: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}|{phase}|{stream}".encode()).digest()[:8], "big")


def window_configuration(suite: dict) -> dict:
    cfg = suite.get("online", {})
    return {
        "window_events": int(cfg.get("window_events", 64)),
        "window_seconds": float(cfg.get("window_seconds", 1.0)),
        "min_window_events": int(cfg.get("min_window_events", 8)),
        "initial_window_events": int(cfg.get("initial_window_events", 16)),
    }


def prepare_bundle(suite: dict, out: Path) -> tuple[DetectorBundle, dict]:
    started = time.perf_counter()
    config = suite.get("online", {})
    calibration = suite.get("calibration", {})
    seed = int(suite.get("seed", 20261005))
    scales = [int(n) for n in calibration.get("agent_counts", suite["agent_counts"])]
    if not scales or min(scales) < 1:
        raise ValueError("reference population sizes must be positive")
    training_repeats = int(calibration.get("training_repeats", 3))
    calibration_streams = int(calibration.get("streams", 299))
    if training_repeats < 1 or calibration_streams < 1:
        raise ValueError("training repetitions and calibration streams must be positive")
    benign_regimes = tuple(calibration.get("benign_scenarios", BENIGN_SCENARIOS))
    known_attacks = tuple(calibration.get("attack_scenarios", KNOWN_ATTACK_SCENARIOS))
    if not benign_regimes or not set(benign_regimes) <= set(BENIGN_SCENARIOS):
        raise ValueError("calibration benign regimes must be recognized benign policies")
    if not known_attacks or not set(known_attacks) <= set(ATTACK_SCENARIOS):
        raise ValueError("known attack training regimes must be attacks")
    alpha = float(calibration.get("alpha", suite.get("statistical", {}).get("alpha", 0.01)))
    window_config = window_configuration(suite)
    metadata: list[dict] = []
    training, heldout = [], []

    def generate(phase: str, index: int, scenario: str, n: int) -> list[dict]:
        stream_seed = phase_seed(seed, phase, index)
        stream_id = f"{phase}-{index:05d}"
        events = reference_events(
            scenario, agent_count=n, requests_per_agent=int(suite.get("requests_per_agent", 3)),
            seed=stream_seed, repeat=0, arrival_window_ms=float(suite.get("arrival_window_ms", 1000)),
            attacker_fraction=float(suite.get("attacker_fraction", 0.20)),
            camouflage_fraction=float(suite.get("camouflage_fraction", 0.50)),
            slow_delay_s=float(suite.get("slow_delay_s", 0.20)),
        )
        rows = extract_windows(events, window_config)
        for row in rows:
            row.update({"phase": phase, "stream_id": stream_id, "scenario": scenario,
                        "agent_count": n, "seed": stream_seed, "label": int(scenario not in BENIGN_SCENARIOS)})
        metadata.append({"stream_id": stream_id, "phase": phase, "scenario": scenario,
                         "agent_count": n, "seed": stream_seed, "requests": len(events), "windows": len(rows)})
        return rows

    index = 0
    for _ in range(training_repeats):
        for n in scales:
            for scenario in benign_regimes + known_attacks:
                training.append(generate("training", index, scenario, n))
                index += 1
    print(f"[reference] training streams={len(training)} windows={sum(map(len, training))}", flush=True)
    bundle = DetectorBundle.fit(
        training, seed=phase_seed(seed, "kernel", 0),
        shrinkage=float(config.get("shrinkage", 0.15)),
        rff_dimensions=int(config.get("rff_dimensions", 64)),
        mmd_history=int(config.get("mmd_history", 8)), cusum_drift=float(config.get("cusum_drift", 0.5)),
    )
    rng = random.Random(phase_seed(seed, "calibration-selection", 0))
    for index in range(calibration_streams):
        heldout.append(generate("calibration", index, rng.choice(benign_regimes), rng.choice(scales)))
        if (index + 1) % 50 == 0:
            print(f"[reference] calibration {index + 1}/{calibration_streams}", flush=True)
    calibration_report = bundle.calibrate(heldout, alpha)
    calibration_report.update({
        "reference_source": "synthetic policy telemetry; independent of measured HTTP test traffic",
        "training_streams": len(training), "training_windows": sum(map(len, training)),
        "reference_agent_counts": scales, "benign_training_scenarios": list(benign_regimes),
        "known_attack_training_scenarios": list(known_attacks), "window_config": window_config,
        "preparation_seconds": time.perf_counter() - started,
        "kernel": "Gaussian kernel approximation with random Fourier features; fixed training bandwidth",
        "graph": "conditional density of temporal bipartite graph descriptors; no hidden membership or identity ordering",
    })
    (out / "detector_bundle.json").write_text(json.dumps(bundle.to_dict(), indent=2, allow_nan=False), encoding="utf-8")
    (out / "calibration.json").write_text(json.dumps(calibration_report, indent=2, allow_nan=False), encoding="utf-8")
    with (out / "reference_manifest.jsonl").open("w", encoding="utf-8") as fh:
        for record in metadata:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    with (out / "reference_windows.jsonl").open("w", encoding="utf-8") as fh:
        for stream in training + heldout:
            for row in stream:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    return bundle, calibration_report


async def prepare_http_bundle(suite: dict, out: Path, collect) -> tuple[DetectorBundle, dict]:
    """Fit and calibrate on disjoint, actually measured service-boundary streams."""
    started = time.perf_counter()
    config = suite.get("online", {})
    calibration = suite.get("calibration", {})
    seed = int(suite.get("seed", 20261005))
    scales = [int(n) for n in calibration.get("agent_counts", suite["agent_counts"])]
    training_repeats = int(calibration.get("training_repeats", 3))
    n_calibration = int(calibration.get("streams", 299))
    benign = tuple(calibration.get("benign_scenarios", BENIGN_SCENARIOS))
    attack = tuple(calibration.get("attack_scenarios", KNOWN_ATTACK_SCENARIOS))
    if not scales or min(scales) < 1 or training_repeats < 1 or n_calibration < 1:
        raise ValueError("invalid reference population or stream count")
    if not benign or not set(benign) <= set(BENIGN_SCENARIOS) or not attack or not set(attack) <= set(ATTACK_SCENARIOS):
        raise ValueError("reference regimes must contain only declared benign / attack policies")
    window_config = window_configuration(suite)
    training, heldout, metadata, http_metrics = [], [], [], []
    async def measure(phase, index, scenario, n):
        stream_seed = phase_seed(seed, phase, index)
        stream_id = f"{phase}-{index:05d}"
        print(f"[reference-http] {stream_id} scenario={scenario} agents={n}", flush=True)
        result = await collect(scenario, n, stream_seed)
        events = result.pop("reference_events")
        if len(events) != n * int(suite.get("requests_per_agent", 3)):
            raise RuntimeError("reference gateway telemetry is incomplete")
        rows = extract_windows(events, window_config)
        for row in rows:
            row.update({"phase": phase, "stream_id": stream_id, "scenario": scenario,
                        "agent_count": n, "seed": stream_seed, "label": int(scenario not in BENIGN_SCENARIOS)})
        metadata.append({"stream_id": stream_id, "phase": phase, "scenario": scenario, "agent_count": n,
                         "seed": stream_seed, "requests": len(events), "windows": len(rows), "source": "measured_http"})
        http_metrics.append({**result, "stream_id": stream_id, "phase": phase})
        with gzip.open(out / "reference_events.jsonl.gz", "at", encoding="utf-8", compresslevel=3) as fh:
            for event in events:
                fh.write(json.dumps({"stream_id": stream_id, **event}, sort_keys=True) + "\n")
        return rows

    plan = [(scenario, n) for _ in range(training_repeats) for n in scales for scenario in benign + attack]
    random.Random(phase_seed(seed, "training-order", 0)).shuffle(plan)
    for index, (scenario, n) in enumerate(plan):
        training.append(await measure("training", index, scenario, n))
    bundle = DetectorBundle.fit(
        training, seed=phase_seed(seed, "kernel", 0), shrinkage=float(config.get("shrinkage", 0.15)),
        rff_dimensions=int(config.get("rff_dimensions", 64)),
        mmd_history=int(config.get("mmd_history", 8)), cusum_drift=float(config.get("cusum_drift", 0.5)),
    )
    rng = random.Random(phase_seed(seed, "calibration-selection", 0))
    for index in range(n_calibration):
        heldout.append(await measure("calibration", index, rng.choice(benign), rng.choice(scales)))
    report = bundle.calibrate(heldout, float(calibration.get("alpha", 0.01)))
    report.update({
        "reference_source": "measured HTTP gateway telemetry on the same synthetic service; training, calibration and test seeds are disjoint",
        "training_streams": len(training), "training_windows": sum(map(len, training)),
        "reference_agent_counts": scales, "benign_training_scenarios": list(benign),
        "known_attack_training_scenarios": list(attack), "window_config": window_config,
        "preparation_seconds": time.perf_counter() - started,
        "reference_http_requests": sum(int(row["requests"]) for row in http_metrics),
        "kernel": "Gaussian kernel approximation with fixed training random Fourier features",
        "graph": "conditional density of temporal identity/resource-region bipartite descriptors",
    })
    with (out / "reference_http_metrics.csv").open("w", newline="", encoding="utf-8") as fh:
        fields = sorted(set().union(*(row.keys() for row in http_metrics)))
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(http_metrics)
    with (out / "reference_manifest.jsonl").open("w", encoding="utf-8") as fh:
        for record in metadata:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    with (out / "reference_windows.jsonl").open("w", encoding="utf-8") as fh:
        for stream in training + heldout:
            for row in stream:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    (out / "detector_bundle.json").write_text(json.dumps(bundle.to_dict(), indent=2, allow_nan=False), encoding="utf-8")
    (out / "calibration.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    return bundle, report
