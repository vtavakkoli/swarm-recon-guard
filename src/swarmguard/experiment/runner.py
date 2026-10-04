from __future__ import annotations

import asyncio
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
from swarmguard.config import LAB_ALLOWED_GATEWAY_HOSTS
from swarmguard.experiment.policies import SCENARIOS, build_actions
from swarmguard.reporting.report import build_report


@dataclass
class Findings:
    ticket_statuses: set[int] = field(default_factory=set)
    ticket_keys: set[str] = field(default_factory=set)
    permit_counts: dict[str, int] = field(default_factory=dict)
    diagnostic_seen: bool = False

    def observe(self, path: str, params: dict[str, str], status: int, payload: object) -> None:
        if path.startswith("/api/v1/tickets/"):
            self.ticket_keys.add(path.rsplit("/", 1)[-1]); self.ticket_statuses.add(status)
        elif path == "/api/v1/permits/search" and isinstance(payload, dict):
            prefix = str(payload.get("prefix", params.get("prefix", ""))); count = payload.get("count")
            if isinstance(count, int): self.permit_counts[prefix] = count
        elif "/api/v1/zones/" in path and isinstance(payload, dict):
            self.diagnostic_seen = self.diagnostic_seen or "backend_shard" in payload

    def discovered(self) -> dict[str, bool]:
        return {
            "V001_ticket_enumeration": len(self.ticket_keys) >= 20 and 200 in self.ticket_statuses and 404 in self.ticket_statuses,
            "V002_permit_prefix_oracle": len(self.permit_counts) >= 10 and len(set(self.permit_counts.values())) >= 3,
            "V003_zone_diagnostic_disclosure": self.diagnostic_seen,
        }


def _percentile(values: list[float], q: float) -> float:
    if not values: return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1: return ordered[0]
    pos = (len(ordered)-1)*q; lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi: return ordered[lo]
    return ordered[lo]*(hi-pos) + ordered[hi]*(pos-lo)


def _validate_lab_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in LAB_ALLOWED_GATEWAY_HOSTS:
        raise RuntimeError(f"Refusing target {url!r}. Lab gateway hosts only: {sorted(LAB_ALLOWED_GATEWAY_HOSTS)}")


async def _wait_ready(client: httpx.AsyncClient, url: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            r = await client.get(url)
            if r.status_code == 200: return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.25)
    raise RuntimeError(f"service did not become ready: {url}")


async def _run_one(*, client:httpx.AsyncClient, detector_client:httpx.AsyncClient, gateway_url:str, detector_url:str, scenario:str, agent_count:int, repeat:int, suite:dict) -> dict[str, object]:
    run_id = f"{scenario}-{agent_count}-r{repeat}-{uuid.uuid4().hex[:8]}"
    requests_per_agent = int(suite.get("requests_per_agent", 3)); concurrency = int(suite.get("concurrency", 256))
    arrival_window_ms = float(suite.get("arrival_window_ms", 1000.0)); seed = int(suite.get("seed", 20261005)); detector_cfg = suite.get("detector", {})
    await detector_client.post(f"{detector_url}/runs/{run_id}/reset", json={"threshold":float(detector_cfg.get("threshold",.72)),"min_events":int(detector_cfg.get("min_events",30)),"consecutive_windows":int(detector_cfg.get("consecutive_windows",2)),"evaluation_interval":int(detector_cfg.get("evaluation_interval",100))})
    semaphore = asyncio.Semaphore(concurrency); shared_findings = Findings(); individual_flags=[None]*agent_count; latencies_ms=[]; statuses=[]; per_agent_counts=[0]*agent_count

    async def run_agent(agent_idx:int) -> None:
        identity=f"u-{repeat:02d}-{agent_idx:05d}"; local=Findings(); rng=random.Random(seed+repeat*104729+agent_idx*7919)
        if arrival_window_ms>0: await asyncio.sleep(rng.random()*arrival_window_ms/1000.0)
        actions=build_actions(scenario,agent_idx=agent_idx,agent_count=agent_count,requests_per_agent=requests_per_agent,seed=seed,repeat=repeat)
        for action in actions:
            async with semaphore:
                t0=time.perf_counter()
                try:
                    response=await client.get(f"{gateway_url}{action.path}",params=action.params,headers={"X-Run-Id":run_id,"X-Lab-Identity":identity})
                    elapsed=(time.perf_counter()-t0)*1000.0
                    try: payload=response.json()
                    except Exception: payload=None
                    local.observe(action.path,action.params,response.status_code,payload)
                    if scenario=="coordinated_swarm": shared_findings.observe(action.path,action.params,response.status_code,payload)
                    statuses.append(response.status_code); latencies_ms.append(elapsed)
                except httpx.HTTPError:
                    statuses.append(599); latencies_ms.append((time.perf_counter()-t0)*1000.0)
                per_agent_counts[agent_idx]+=1
        individual_flags[agent_idx]=local.discovered()

    start_wall=time.time(); start_perf=time.perf_counter(); await asyncio.gather(*(run_agent(i) for i in range(agent_count))); duration_s=max(1e-9,time.perf_counter()-start_perf)
    expected_requests=agent_count*requests_per_agent; snapshot={}; deadline=time.monotonic()+15.0
    while time.monotonic()<deadline:
        r=await detector_client.get(f"{detector_url}/runs/{run_id}"); r.raise_for_status(); snapshot=r.json()
        if int(snapshot.get("requests",0))>=expected_requests: break
        await asyncio.sleep(.05)
    if scenario=="coordinated_swarm": discovered=shared_findings.discovered()
    else:
        names=("V001_ticket_enumeration","V002_permit_prefix_oracle","V003_zone_diagnostic_disclosure")
        discovered={name:any(flags and flags.get(name,False) for flags in individual_flags) for name in names}
    success_2xx=sum(1 for s in statuses if 200<=s<300); client_errors=sum(1 for s in statuses if 400<=s<500); transport_errors=sum(1 for s in statuses if s==599)
    baseline_identity_limit=int(suite.get("baseline_identity_request_limit",20))
    return {"run_id":run_id,"scenario":scenario,"label":0 if scenario=="benign_flash" else 1,"agent_count":agent_count,"repeat":repeat,"seed":seed,"requests_per_agent":requests_per_agent,"requests":len(statuses),"expected_requests":expected_requests,"duration_s":duration_s,"requests_per_second":len(statuses)/duration_s,"latency_p50_ms":_percentile(latencies_ms,.50),"latency_p95_ms":_percentile(latencies_ms,.95),"latency_p99_ms":_percentile(latencies_ms,.99),"latency_mean_ms":statistics.fmean(latencies_ms) if latencies_ms else float("nan"),"success_2xx_rate":success_2xx/len(statuses) if statuses else 0.0,"client_4xx_rate":client_errors/len(statuses) if statuses else 0.0,"transport_error_rate":transport_errors/len(statuses) if statuses else 0.0,"per_agent_request_mean":statistics.fmean(per_agent_counts) if per_agent_counts else 0.0,"per_agent_request_max":max(per_agent_counts,default=0),"per_identity_rule_triggered":max(per_agent_counts,default=0)>baseline_identity_limit,"vulnerabilities_discovered":sum(discovered.values()),"vulnerability_discovery_rate":sum(discovered.values())/len(discovered),**{f"finding_{k}":v for k,v in discovered.items()},"detected":bool(snapshot.get("detected",False)),"detector_score_peak":float(snapshot.get("score_peak",0.0)),"detector_score_final":float(snapshot.get("score_final",0.0)),"detection_delay_ms":snapshot.get("detection_delay_ms"),"exposure_before_detection":snapshot.get("coverage_at_detection"),"semantic_coverage":float(snapshot.get("semantic_coverage",0.0)),"unique_resources":int(float(snapshot.get("unique_resources",0.0))),"novelty_ratio":float(snapshot.get("novelty_ratio",0.0)),"namespace_span":float(snapshot.get("namespace_span",0.0)),"gap_uniformity":float(snapshot.get("gap_uniformity",0.0)),"diagnostic_ratio":float(snapshot.get("diagnostic_ratio",0.0)),"family_entropy":float(snapshot.get("family_entropy",0.0)),"started_at_utc":datetime.fromtimestamp(start_wall,tz=timezone.utc).isoformat()}


async def run_suite(suite_path:Path, result_root:Path|None=None) -> Path:
    suite=yaml.safe_load(suite_path.read_text()); scenarios=suite.get("scenarios",list(SCENARIOS)); invalid=sorted(set(scenarios)-set(SCENARIOS))
    if invalid: raise ValueError(f"invalid scenarios: {invalid}")
    agent_counts=[int(x) for x in suite.get("agent_counts",[10,100,1000,10000])]; repeats=int(suite.get("repeats",5))
    gateway_url=os.getenv("GATEWAY_URL","http://gateway:8080").rstrip("/"); detector_url=os.getenv("DETECTOR_URL","http://detector:8090").rstrip("/"); _validate_lab_url(gateway_url)
    result_root=result_root or Path(os.getenv("RESULT_ROOT","results")); stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"); suite_name=str(suite.get("name",suite_path.stem)).replace(" ","-"); out=result_root/f"{suite_name}-{stamp}"; out.mkdir(parents=True,exist_ok=True)
    manifest={"framework":"SwarmReconGuard","version":__version__,"suite":suite,"suite_file":str(suite_path),"created_at_utc":datetime.now(timezone.utc).isoformat(),"python":platform.python_version(),"platform":platform.platform(),"safety_scope":"synthetic internal Docker service only"}; (out/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True))
    timeout=httpx.Timeout(connect=10.0,read=30.0,write=30.0,pool=30.0); limits=httpx.Limits(max_connections=max(512,int(suite.get("concurrency",256))*2),max_keepalive_connections=256); runs=[]
    async with httpx.AsyncClient(timeout=timeout,limits=limits) as client, httpx.AsyncClient(timeout=10.0) as detector_client:
        await _wait_ready(client,f"{gateway_url}/healthz"); await _wait_ready(detector_client,f"{detector_url}/healthz")
        for agent_count in agent_counts:
            for repeat in range(repeats):
                for scenario in scenarios:
                    print(f"[run] scenario={scenario} agents={agent_count} repeat={repeat+1}/{repeats}",flush=True)
                    row=await _run_one(client=client,detector_client=detector_client,gateway_url=gateway_url,detector_url=detector_url,scenario=scenario,agent_count=agent_count,repeat=repeat,suite=suite); runs.append(row)
                    with (out/"runs.jsonl").open("a",encoding="utf-8") as fh: fh.write(json.dumps(row,sort_keys=True)+"\n")
    build_report(runs,manifest,out); return out
