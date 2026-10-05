from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager
from urllib.parse import urlencode

import httpx
import redis.asyncio as redis
from fastapi import FastAPI, Request, Response

TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://target:8000").rstrip("/")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
STREAM = os.getenv("DETECTOR_STREAM", "swarmguard:events")
UPSTREAM_TIMEOUT_S = float(os.getenv("GATEWAY_UPSTREAM_TIMEOUT_S", "120"))
UPSTREAM_MAX_CONNECTIONS = int(os.getenv("GATEWAY_MAX_CONNECTIONS", "512"))
UPSTREAM_MAX_KEEPALIVE = int(os.getenv("GATEWAY_MAX_KEEPALIVE", "256"))

client: httpx.AsyncClient | None = None
redis_client: redis.Redis | None = None
telemetry_failures: dict[str, int] = {}
forwarded_requests: dict[str, int] = {}
deduplicated_retries: dict[str, int] = {}
response_cache: dict[str, dict[str, tuple[int, bytes, str]]] = {}
request_locks: dict[str, dict[str, asyncio.Lock]] = {}


def _semantic_metadata(path: str, query: dict[str, str]) -> tuple[str, str, int | None]:
    parts = [p for p in path.split("/") if p]
    try:
        if len(parts) >= 4 and parts[:3] == ["api", "v1", "tickets"]:
            ticket_id = int(parts[3])
            return "ticket", str(ticket_id), ticket_id
        if parts[:4] == ["api", "v1", "permits", "search"]:
            prefix = query.get("prefix", "").upper()
            return "permit_prefix", prefix, None
        if len(parts) >= 5 and parts[:3] == ["api", "v1", "zones"] and parts[4] == "status":
            zone_id = int(parts[3])
            return "zone", str(zone_id), zone_id
    except (ValueError, IndexError):
        pass
    return "other", path, None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global client, redis_client
    client = httpx.AsyncClient(
        base_url=TARGET_BASE_URL,
        timeout=httpx.Timeout(UPSTREAM_TIMEOUT_S),
        limits=httpx.Limits(
            max_connections=UPSTREAM_MAX_CONNECTIONS,
            max_keepalive_connections=UPSTREAM_MAX_KEEPALIVE,
        ),
        trust_env=False,
    )
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    yield
    await client.aclose()
    await redis_client.aclose()


app = FastAPI(title="SwarmReconGuard Gateway", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/_lab/telemetry/{run_id}")
async def telemetry_status(run_id: str) -> dict:
    return {
        "forwarded_requests": forwarded_requests.get(run_id, 0),
        "deduplicated_retries": deduplicated_retries.get(run_id, 0),
        "telemetry_failures": telemetry_failures.get(run_id, 0),
    }


@app.delete("/_lab/telemetry/{run_id}")
async def release_telemetry(run_id: str) -> dict:
    telemetry_failures.pop(run_id, None)
    forwarded_requests.pop(run_id, None)
    deduplicated_retries.pop(run_id, None)
    response_cache.pop(run_id, None)
    request_locks.pop(run_id, None)
    return {"status": "released"}


@app.api_route("/{path:path}", methods=["GET"])
async def proxy(path: str, request: Request) -> Response:
    assert client is not None and redis_client is not None

    if path == "healthz":
        return Response(content='{"status":"ok"}', media_type="application/json")

    run_id = request.headers.get("x-run-id", "unassigned")
    identity = request.headers.get("x-lab-identity", "anonymous")
    request_id = request.headers.get("x-lab-request-id")
    request_lock: asyncio.Lock | None = None
    if request_id:
        cached = response_cache.get(run_id, {}).get(request_id)
        if cached is not None:
            deduplicated_retries[run_id] = deduplicated_retries.get(run_id, 0) + 1
            status_code, content, content_type = cached
            return Response(content=content, status_code=status_code, headers={"content-type": content_type})
        request_lock = request_locks.setdefault(run_id, {}).setdefault(request_id, asyncio.Lock())
        await request_lock.acquire()
        # A prior attempt may have completed while this retry waited.
        cached = response_cache.get(run_id, {}).get(request_id)
        if cached is not None:
            deduplicated_retries[run_id] = deduplicated_retries.get(run_id, 0) + 1
            request_lock.release()
            status_code, content, content_type = cached
            return Response(content=content, status_code=status_code, headers={"content-type": content_type})
    query_items = list(request.query_params.multi_items())
    query_dict = dict(query_items)
    query_string = urlencode(query_items)

    start = time.perf_counter()
    try:
        upstream = await client.get(f"/{path}", params=query_items)
    except httpx.HTTPError:
        if request_lock is not None and request_lock.locked():
            request_lock.release()
        return Response(
            content='{"detail":"synthetic upstream temporarily unavailable"}',
            status_code=503,
            media_type="application/json",
            headers={"retry-after": "0"},
        )
    forwarded_requests[run_id] = forwarded_requests.get(run_id, 0) + 1
    latency_ms = (time.perf_counter() - start) * 1000.0

    family, resource_key, numeric_key = _semantic_metadata(f"/{path}", query_dict)
    event = {
        "ts": f"{time.time():.6f}",
        "run_id": run_id,
        "identity": identity,
        "method": "GET",
        "path": f"/{path}",
        "query": query_string,
        "status": str(upstream.status_code),
        "body_bytes": str(len(upstream.content)),
        "latency_ms": f"{latency_ms:.6f}",
        "family": family,
        "resource_key": resource_key,
        "numeric_key": "" if numeric_key is None else str(numeric_key),
        "diagnostic": "1" if query_dict.get("view") == "diagnostic" else "0",
    }
    try:
        await redis_client.xadd(STREAM, event, maxlen=100_000, approximate=True)
    except Exception:
        telemetry_failures[run_id] = telemetry_failures.get(run_id, 0) + 1

    content_type = upstream.headers.get("content-type", "application/json")
    if request_id:
        response_cache.setdefault(run_id, {})[request_id] = (
            upstream.status_code,
            bytes(upstream.content),
            content_type,
        )
    if request_lock is not None and request_lock.locked():
        request_lock.release()
    headers = {"content-type": content_type}
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)
