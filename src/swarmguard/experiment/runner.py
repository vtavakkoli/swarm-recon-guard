from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import math
import os
import platform
import random
import statistics
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from swarmguard import __version__
from swarmguard.config import LAB_ALLOWED_DETECTOR_HOSTS, LAB_ALLOWED_GATEWAY_HOSTS, TOTAL_SEMANTIC_SPACE
from swarmguard.experiment.calibration import prepare_bundle, prepare_http_bundle, window_configuration
from swarmguard.experiment.policies import BENIGN_SCENARIOS, SCENARIOS, attack_members, build_actions
from swarmguard.reporting.report import build_report


@dataclass
class Findings:
    ticket_statuses: set[int] = field(default_factory=set)
    ticket_keys: set[str] = field(default_factory=set)
    permit_counts: dict[str, int] = field(default_factory=dict)
    zone_keys: set[str] = field(default_factory=set)
    diagnostic_seen: bool = False
    observed_bytes: int = 0

    def observe(self, path: str, params: dict[str, str], status: int, payload: object,
                body_bytes: int = 0) -> None:
        self.observed_bytes += body_bytes
        if path.startswith("/api/v1/tickets/"):
            self.ticket_keys.add(path.rsplit("/", 1)[-1])
            self.ticket_statuses.add(status)
        elif path == "/api/v1/permits/search" and isinstance(payload, dict):
            prefix = str(payload.get("prefix", params.get("prefix", "")))
            count = payload.get("count")
            if isinstance(count, int):
                self.permit_counts[prefix] = count
        elif "/api/v1/zones/" in path and isinstance(payload, dict):
            self.zone_keys.add(path.split("/")[4])
            self.diagnostic_seen = self.diagnostic_seen or "backend_shard" in payload

    def discovered(self) -> dict[str, bool]:
        return {
            "V001_ticket_enumeration": len(self.ticket_keys) >= 20 and 200 in self.ticket_statuses and 404 in self.ticket_statuses,
            "V002_permit_prefix_oracle": len(self.permit_counts) >= 10 and len(set(self.permit_counts.values())) >= 3,
            "V003_zone_diagnostic_disclosure": self.diagnostic_seen,
        }

    def coverage(self) -> float:
        return (len(self.ticket_keys) + len(self.permit_counts) + len(self.zone_keys)) / TOTAL_SEMANTIC_SPACE


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return ordered[lo] if lo == hi else ordered[lo] * (hi - pos) + ordered[hi] * (pos - lo)


def _validate_lab_url(url: str, allowed_hosts: set[str] | None = None) -> None:
    allowed_hosts = LAB_ALLOWED_GATEWAY_HOSTS if allowed_hosts is None else allowed_hosts
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in allowed_hosts:
        raise RuntimeError(f"Refusing target {url!r}. Lab hosts only: {sorted(allowed_hosts)}")


async def _wait_ready(client: httpx.AsyncClient, url: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if (await client.get(url)).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.25)
    raise RuntimeError(f"service did not become ready: {url}")


async def _run_one(*, client: httpx.AsyncClient, detector_client: httpx.AsyncClient,
                   gateway_url: str, detector_url: str, scenario: str, agent_count: int,
                   repeat: int, suite: dict, out: Path | None = None,
                   capture_reference: bool = False) -> dict[str, object]:
    # Opaque stream id: labels and membership remain evaluator-only.
    run_id = "run-" + uuid.uuid4().hex
    requests_per_agent = int(suite.get("requests_per_agent", 3))
    concurrency = int(suite.get("concurrency", 256))
    arrival_window_ms = float(suite.get("arrival_window_ms", 1000))
    seed = int(suite.get("seed", 20261005))
    detector_cfg = suite.get("detector", {})
    reset = await detector_client.post(f"{detector_url}/runs/{run_id}/reset", json={
        "threshold": float(detector_cfg.get("threshold", 0.72)),
        "min_events": int(detector_cfg.get("min_events", 10)),
        "consecutive_windows": int(detector_cfg.get("consecutive_windows", 2)),
        "evaluation_interval": min(int(detector_cfg.get("evaluation_interval", 100)), max(1, agent_count * requests_per_agent // 3)),
    })
    reset.raise_for_status()
    semaphore = asyncio.Semaphore(concurrency)
    population_findings, shared_findings = Findings(), Findings()
    individual_flags: list[dict | None] = [None] * agent_count
    latencies_ms: list[float] = []
    statuses: list[int] = []
    per_agent_counts = [0] * agent_count
    is_attack = scenario not in BENIGN_SCENARIOS
    members = attack_members(agent_count, float(suite.get("attacker_fraction", 0.20)), seed, repeat) if scenario == "mixed_swarm" else frozenset(range(agent_count)) if is_attack else frozenset()
    coordinated = is_attack and scenario != "independent_recon"

    async def run_agent(agent_idx: int) -> None:
        identity = f"u-{agent_idx:05d}"
        local = Findings()
        rng = random.Random(seed + repeat * 104729 + agent_idx * 7919)
        if arrival_window_ms > 0:
            await asyncio.sleep(rng.random() * arrival_window_ms / 1000)
        actions = build_actions(
            scenario, agent_idx=agent_idx, agent_count=agent_count,
            requests_per_agent=requests_per_agent, seed=seed, repeat=repeat,
            attacker_fraction=float(suite.get("attacker_fraction", 0.20)),
            camouflage_fraction=float(suite.get("camouflage_fraction", 0.50)),
            slow_delay_s=float(suite.get("slow_delay_s", 0.20)),
        )
        for action in actions:
            if action.delay_s:
                await asyncio.sleep(action.delay_s)
            async with semaphore:
                t0 = time.perf_counter()
                try:
                    response = await client.get(
                        f"{gateway_url}{action.path}", params=action.params,
                        headers={"X-Run-Id": run_id, "X-Lab-Identity": identity},
                    )
                    elapsed = (time.perf_counter() - t0) * 1000
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = None
                    args = (action.path, action.params, response.status_code, payload, len(response.content))
                    local.observe(*args)
                    population_findings.observe(*args)
                    if agent_idx in members:
                        shared_findings.observe(*args)
                    statuses.append(response.status_code)
                    latencies_ms.append(elapsed)
                except httpx.HTTPError:
                    statuses.append(599)
                    latencies_ms.append((time.perf_counter() - t0) * 1000)
                per_agent_counts[agent_idx] += 1
        individual_flags[agent_idx] = local.discovered()

    start_wall, start_perf = time.time(), time.perf_counter()
    await asyncio.gather(*(run_agent(i) for i in range(agent_count)))
    duration_s = max(1e-9, time.perf_counter() - start_perf)
    expected = agent_count * requests_per_agent
    deadline = time.monotonic() + float(suite.get("telemetry_drain_timeout_s", 60))
    snapshot: dict = {}
    while time.monotonic() < deadline:
        response = await detector_client.get(f"{detector_url}/runs/{run_id}")
        response.raise_for_status()
        snapshot = response.json()
        if snapshot.get("detector_error"):
            raise RuntimeError(f"detector failed in {run_id}: {snapshot['detector_error']}")
        if int(snapshot.get("telemetry_processed", snapshot.get("requests", 0))) >= expected:
            break
        await asyncio.sleep(0.10)
    response = await detector_client.post(f"{detector_url}/runs/{run_id}/finalize")
    response.raise_for_status()
    snapshot = response.json()
    telemetry_response = await client.get(f"{gateway_url}/_lab/telemetry/{run_id}")
    telemetry_response.raise_for_status()
    telemetry = telemetry_response.json()
    observed = int(snapshot.get("telemetry_processed", snapshot.get("requests", 0)))
    valid = observed == expected and not snapshot.get("detector_error") and telemetry["telemetry_failures"] == 0 and 599 not in statuses
    if suite.get("strict_telemetry", True) and not valid:
        raise RuntimeError(f"Incomplete measurement: expected={expected} processed={observed} telemetry={telemetry} transport_errors={statuses.count(599)}")

    if coordinated:
        discovered = shared_findings.discovered()
    else:
        names = tuple(population_findings.discovered())
        discovered = {name: any(flags and flags.get(name, False) for flags in individual_flags) for name in names}
    online = snapshot.get("online", {})
    if out is not None and online:
        with (out / "window_traces.jsonl").open("a", encoding="utf-8") as fh:
            for window in online.pop("windows", []):
                fh.write(json.dumps({"run_id": run_id, "scenario": scenario, "agent_count": agent_count,
                                     "repeat": repeat, "label": int(is_attack), **window}, sort_keys=True) + "\n")
        events = online.pop("events", [])
        if events:
            with gzip.open(out / "event_traces.jsonl.gz", "at", encoding="utf-8", compresslevel=3) as fh:
                for event in events:
                    fh.write(json.dumps({"run_id": run_id, **event}, sort_keys=True) + "\n")
    limit = int(suite.get("baseline_identity_request_limit", 20))
    row = {
        "run_id": run_id, "scenario": scenario, "label": int(is_attack), "agent_count": agent_count,
        "repeat": repeat, "seed": seed, "requests_per_agent": requests_per_agent,
        "requests": len(statuses), "expected_requests": expected, "duration_s": duration_s,
        "requests_per_second": len(statuses) / duration_s,
        "latency_p50_ms": _percentile(latencies_ms, 0.50), "latency_p95_ms": _percentile(latencies_ms, 0.95),
        "latency_p99_ms": _percentile(latencies_ms, 0.99), "latency_mean_ms": statistics.fmean(latencies_ms),
        "success_2xx_rate": sum(200 <= s < 300 for s in statuses) / len(statuses),
        "client_4xx_rate": sum(400 <= s < 500 for s in statuses) / len(statuses),
        "transport_error_rate": statuses.count(599) / len(statuses),
        "per_agent_request_mean": statistics.fmean(per_agent_counts), "per_agent_request_max": max(per_agent_counts),
        "per_identity_rule_triggered": max(per_agent_counts) > limit,
        "vulnerabilities_discovered": sum(discovered.values()), "vulnerability_discovery_rate": sum(discovered.values()) / len(discovered),
        **{f"finding_{name}": value for name, value in discovered.items()},
        "population_vulnerability_discovery_rate": sum(population_findings.discovered().values()) / 3,
        "attacker_count": len(members), "attacker_fraction": len(members) / agent_count,
        "attacker_semantic_coverage": shared_findings.coverage() if is_attack else 0,
        "information_bytes_received": population_findings.observed_bytes,
        "attacker_information_bytes_received": shared_findings.observed_bytes,
        "detected": bool(snapshot.get("detected", False)),
        "detector_score_peak": float(snapshot.get("score_peak", 0)),
        "detector_score_final": float(snapshot.get("score_final", 0)),
        "detection_delay_ms": snapshot.get("detection_delay_ms"),
        "exposure_before_detection": snapshot.get("coverage_at_detection"),
        "semantic_coverage": float(snapshot.get("semantic_coverage", 0)),
        "unique_resources": int(snapshot.get("unique_resources", 0)),
        **{name: float(snapshot.get(name, 0)) for name in ("novelty_ratio", "namespace_span", "gap_uniformity", "diagnostic_ratio", "family_entropy")},
        "measurement_valid": valid, "telemetry_processed": observed, "telemetry_failures": telemetry["telemetry_failures"],
        "online": online, "started_at_utc": datetime.fromtimestamp(start_wall, tz=timezone.utc).isoformat(),
    }
    if capture_reference:
        row["reference_events"] = snapshot.get("reference_events", [])
    released = await detector_client.delete(f"{detector_url}/runs/{run_id}")
    released.raise_for_status()
    await client.delete(f"{gateway_url}/_lab/telemetry/{run_id}")
    return row


def validate_suite(suite: dict) -> None:
    invalid = sorted(set(suite.get("scenarios", SCENARIOS)) - set(SCENARIOS))
    if invalid:
        raise ValueError(f"invalid scenarios: {invalid}")
    if not suite.get("agent_counts") or min(map(int, suite["agent_counts"])) < 1:
        raise ValueError("suite requires positive population sizes")
    for name in ("repeats", "requests_per_agent", "concurrency"):
        if int(suite.get(name, 1)) < 1:
            raise ValueError(f"{name} must be positive")
    if not any(s in BENIGN_SCENARIOS for s in suite.get("scenarios", SCENARIOS)):
        raise ValueError("include benign controls for comparison")
    for name in ("attacker_fraction", "camouflage_fraction"):
        if not 0 < float(suite.get(name, 0.2)) <= 1:
            raise ValueError(f"{name} must be in (0,1]")


async def run_suite(suite_path: Path, result_root: Path | None = None) -> Path:
    suite = yaml.safe_load(suite_path.read_text())
    validate_suite(suite)
    scenarios = suite.get("scenarios", list(SCENARIOS))
    scales = [int(n) for n in suite["agent_counts"]]
    repeats = int(suite.get("repeats", 5))
    gateway_url = os.getenv("GATEWAY_URL", "http://gateway:8080").rstrip("/")
    detector_url = os.getenv("DETECTOR_URL", "http://detector:8090").rstrip("/")
    _validate_lab_url(gateway_url)
    _validate_lab_url(detector_url, LAB_ALLOWED_DETECTOR_HOSTS)
    result_root = result_root or Path(os.getenv("RESULT_ROOT", "results"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suite_name = str(suite.get("name", suite_path.stem)).replace(" ", "-").replace("/", "-")
    out = result_root / f"{suite_name}-{stamp}-{uuid.uuid4().hex[:6]}"
    out.mkdir(parents=True)
    manifest = {
        "framework": "SwarmReconGuard", "version": __version__, "suite": suite,
        "suite_file": str(suite_path), "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(), "platform": platform.platform(),
        "cpu_count": os.cpu_count(), "machine": platform.machine(),
        "suite_sha256": hashlib.sha256(suite_path.read_bytes()).hexdigest(),
        "git_commit": os.getenv("SWARM_COMMIT", "not supplied"),
        "safety_scope": "synthetic internal Docker service only",
        "evaluation_source": "measured HTTP/gateway telemetry", "status": "in_progress",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    started = time.perf_counter()
    runs: list[dict] = []
    timeout = httpx.Timeout(connect=10, read=120, write=120, pool=120)
    limits = httpx.Limits(max_connections=max(512, int(suite.get("concurrency", 256)) * 2), max_keepalive_connections=256)
    try:
        async with httpx.AsyncClient(timeout=timeout, limits=limits, trust_env=False) as client, httpx.AsyncClient(timeout=120, trust_env=False) as detector_client:
            await _wait_ready(client, f"{gateway_url}/healthz")
            await _wait_ready(detector_client, f"{detector_url}/healthz")
            if suite.get("online", {}).get("enabled", True):
                cleared = await detector_client.delete(f"{detector_url}/configure")
                cleared.raise_for_status()
                if suite.get("calibration", {}).get("source", "http") == "http":
                    async def collect(scenario, n, stream_seed):
                        return await _run_one(
                            client=client, detector_client=detector_client,
                            gateway_url=gateway_url, detector_url=detector_url,
                            scenario=scenario, agent_count=n, repeat=0,
                            suite={**suite, "seed": stream_seed}, capture_reference=True,
                        )
                    bundle, calibration = await prepare_http_bundle(suite, out, collect)
                elif suite.get("calibration", {}).get("source") == "policy":
                    bundle, calibration = prepare_bundle(suite, out)
                else:
                    raise ValueError("calibration.source must be http or policy")
                manifest["calibration"] = calibration
                configure = await detector_client.post(f"{detector_url}/configure", json={
                    "bundle": bundle.to_dict(), "window_config": window_configuration(suite),
                    "record_events": bool(suite.get("save_event_traces", True)),
                })
                configure.raise_for_status()
            for n in scales:
                for repeat in range(repeats):
                    order = list(scenarios)
                    random.Random(int(suite.get("seed", 20261005)) + repeat * 7919 + n).shuffle(order)
                    for scenario in order:
                        print(f"[run] scenario={scenario} agents={n} repeat={repeat + 1}/{repeats}", flush=True)
                        row = await _run_one(
                            client=client, detector_client=detector_client,
                            gateway_url=gateway_url, detector_url=detector_url, scenario=scenario,
                            agent_count=n, repeat=repeat, suite=suite, out=out,
                        )
                        runs.append(row)
                        with (out / "runs.jsonl").open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps(row, sort_keys=True) + "\n")
        manifest.update({"status": "completed", "run_count": len(runs), "elapsed_seconds": time.perf_counter() - started})
        build_report(runs, manifest, out)
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    except Exception as exc:
        manifest.update({"status": "failed", "completed_runs": len(runs), "error": f"{type(exc).__name__}: {exc}"})
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        raise
    return out
