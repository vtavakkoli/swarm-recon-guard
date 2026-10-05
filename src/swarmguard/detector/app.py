from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from swarmguard.detector.model import RunRiskState
from swarmguard.detector.online import DetectorBundle
from swarmguard.detector.streaming import StreamDetector

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
STREAM = os.getenv("DETECTOR_STREAM", "swarmguard:events")
redis_client: redis.Redis | None = None
consumer_task: asyncio.Task | None = None
states: dict[str, RunRiskState] = {}
online_states: dict[str, StreamDetector] = {}
telemetry_counts: dict[str, int] = {}
stream_errors: dict[str, str] = {}
reference_buffers: dict[str, list[dict[str, str]]] = {}
bundle: DetectorBundle | None = None
window_config: dict = {}
record_events = True
last_stream_id = "$"


class ResetRequest(BaseModel):
    threshold: float = Field(default=0.72, ge=0.0, le=1.0)
    min_events: int = Field(default=30, ge=1)
    consecutive_windows: int = Field(default=2, ge=1, le=20)
    evaluation_interval: int = Field(default=100, ge=1, le=10000)


class ConfigureRequest(BaseModel):
    bundle: dict
    window_config: dict
    record_events: bool = True


async def _consume() -> None:
    global last_stream_id
    assert redis_client is not None
    while True:
        try:
            rows = await redis_client.xread({STREAM: last_stream_id}, count=1000, block=1000)
            for _, entries in rows:
                for stream_id, event in entries:
                    last_stream_id = stream_id
                    run_id = event.get("run_id", "unassigned")
                    state = states.get(run_id)
                    if state is not None:
                        try:
                            state.update(event)
                            online = online_states.get(run_id)
                            if online is not None:
                                online.update(event)
                            else:
                                reference_buffers.setdefault(run_id, []).append(event)
                            telemetry_counts[run_id] = telemetry_counts.get(run_id, 0) + 1
                        except Exception as exc:
                            stream_errors[run_id] = f"{type(exc).__name__}: {exc}"
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(0.2)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global redis_client, consumer_task
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    consumer_task = asyncio.create_task(_consume())
    yield
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    await redis_client.aclose()


app = FastAPI(title="SwarmReconGuard Collective Detector", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/runs/{run_id}/reset")
async def reset(run_id: str, body: ResetRequest) -> dict[str, object]:
    states[run_id] = RunRiskState(run_id=run_id, threshold=body.threshold, min_events=body.min_events, consecutive_windows=body.consecutive_windows, evaluation_interval=body.evaluation_interval)
    telemetry_counts[run_id] = 0
    stream_errors.pop(run_id, None)
    if bundle is not None:
        online_states[run_id] = StreamDetector(bundle, window_config, record_events=record_events)
    else:
        reference_buffers[run_id] = []
    return {"run_id": run_id, "status": "ready"}


@app.post("/configure")
async def configure(body: ConfigureRequest) -> dict[str, object]:
    global bundle, window_config, record_events
    if online_states:
        raise HTTPException(status_code=409, detail="release previous streams before configuring a new model")
    bundle = DetectorBundle.from_dict(body.bundle)
    window_config = body.window_config
    record_events = body.record_events
    return {"status": "configured", "methods": list(bundle.thresholds)}


@app.delete("/configure")
async def clear_configuration() -> dict:
    global bundle
    if states:
        raise HTTPException(status_code=409, detail="release active streams before clearing the model")
    bundle = None
    return {"status": "unconfigured"}


@app.post("/runs/{run_id}/finalize")
async def finalize(run_id: str) -> dict:
    state = states.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="unknown run")
    online = online_states.get(run_id)
    if online is not None:
        online.finalize()
    return await snapshot(run_id, include_windows=True)


@app.delete("/runs/{run_id}")
async def release(run_id: str) -> dict:
    states.pop(run_id, None)
    online_states.pop(run_id, None)
    telemetry_counts.pop(run_id, None)
    stream_errors.pop(run_id, None)
    reference_buffers.pop(run_id, None)
    return {"status": "released"}


@app.get("/runs/{run_id}")
async def snapshot(run_id: str, include_windows: bool = False) -> dict[str, object]:
    state = states.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="unknown run")
    result = state.snapshot()
    result["telemetry_processed"] = telemetry_counts.get(run_id, 0)
    result["detector_error"] = stream_errors.get(run_id)
    online = online_states.get(run_id)
    if online is not None:
        result["online"] = online.snapshot(include_windows)
    elif include_windows:
        result["reference_events"] = reference_buffers.get(run_id, [])
    return result
