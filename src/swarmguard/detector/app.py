from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from swarmguard.detector.model import RunRiskState

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
STREAM = os.getenv("DETECTOR_STREAM", "swarmguard:events")
redis_client: redis.Redis | None = None
consumer_task: asyncio.Task | None = None
states: dict[str, RunRiskState] = {}
last_stream_id = "$"


class ResetRequest(BaseModel):
    threshold: float = Field(default=0.72, ge=0.0, le=1.0)
    min_events: int = Field(default=30, ge=1)
    consecutive_windows: int = Field(default=2, ge=1, le=20)
    evaluation_interval: int = Field(default=100, ge=1, le=10000)


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
                        state.update(event)
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
    return {"run_id": run_id, "status": "ready"}


@app.get("/runs/{run_id}")
async def snapshot(run_id: str) -> dict[str, object]:
    state = states.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return state.snapshot()
