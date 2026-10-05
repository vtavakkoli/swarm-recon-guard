from __future__ import annotations

import httpx
import pytest

from swarmguard.experiment.runner import _request_with_retries


@pytest.mark.asyncio
async def test_transport_retry_recovers_with_same_request_id():
    attempts = 0
    seen_ids: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        seen_ids.append(request.headers["x-lab-request-id"])
        if attempts == 1:
            raise httpx.ConnectError("transient", request=request)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response, retries = await _request_with_retries(
            client,
            "http://gateway/api/v1/test",
            params={},
            headers={"X-Lab-Request-Id": "run:7:2"},
            retries=3,
            backoff_ms=0,
        )

    assert response is not None
    assert response.status_code == 200
    assert retries == 1
    assert attempts == 2
    assert seen_ids == ["run:7:2", "run:7:2"]


@pytest.mark.asyncio
async def test_retryable_503_is_retried_but_ordinary_4xx_is_not():
    statuses = iter([503, 200])

    async def transient_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(next(statuses))

    async with httpx.AsyncClient(transport=httpx.MockTransport(transient_handler)) as client:
        response, retries = await _request_with_retries(
            client,
            "http://gateway/api/v1/test",
            params={},
            headers={"X-Lab-Request-Id": "r1"},
            retries=2,
            backoff_ms=0,
        )
    assert response is not None and response.status_code == 200
    assert retries == 1

    calls = 0

    async def client_error_handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(client_error_handler)) as client:
        response, retries = await _request_with_retries(
            client,
            "http://gateway/api/v1/test",
            params={},
            headers={"X-Lab-Request-Id": "r2"},
            retries=3,
            backoff_ms=0,
        )
    assert response is not None and response.status_code == 404
    assert retries == 0
    assert calls == 1
