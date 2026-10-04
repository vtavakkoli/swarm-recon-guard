from __future__ import annotations

import hashlib
import os
import string
from fastapi import FastAPI, HTTPException, Query

from swarmguard.config import PERMIT_PREFIX_SPACE, TICKET_SPACE, ZONE_SPACE

app = FastAPI(title="SwarmReconGuard Synthetic Municipal Service", version="0.1.0")
SEED = os.getenv("LAB_SEED", "20261005")
ALPHABET = string.digits + string.ascii_uppercase


def _digest(*parts: object) -> int:
    raw = "|".join([SEED, *map(str, parts)]).encode()
    return int(hashlib.sha256(raw).hexdigest()[:16], 16)


def _ticket_exists(ticket_id: int) -> bool:
    return _digest("ticket", ticket_id) % 100 < 73


def _prefix_index(prefix: str) -> int:
    if len(prefix) != 2 or any(c not in ALPHABET for c in prefix):
        raise HTTPException(status_code=422, detail="prefix must be exactly two base36 characters")
    return ALPHABET.index(prefix[0]) * 36 + ALPHABET.index(prefix[1])


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/tickets/{ticket_id}")
def ticket_status(ticket_id: int) -> dict[str, object]:
    if ticket_id < 0 or ticket_id >= TICKET_SPACE:
        raise HTTPException(status_code=404, detail="ticket not found")
    if not _ticket_exists(ticket_id):
        raise HTTPException(status_code=404, detail="ticket not found")
    return {
        "ticket_id": ticket_id,
        "status": ["valid", "expired", "closed"][_digest("status", ticket_id) % 3],
        "zone": _digest("zone", ticket_id) % ZONE_SPACE,
        "updated_bucket": _digest("update", ticket_id) % 24,
    }


@app.get("/api/v1/permits/search")
def permit_search(prefix: str = Query(min_length=2, max_length=2)) -> dict[str, object]:
    prefix = prefix.upper()
    idx = _prefix_index(prefix)
    count = 1 + (_digest("permit-prefix", idx) % 97)
    return {"prefix": prefix, "count": count, "namespace_size": PERMIT_PREFIX_SPACE}


@app.get("/api/v1/zones/{zone_id}/status")
def zone_status(zone_id: int, view: str = Query(default="summary", pattern="^(summary|diagnostic)$")) -> dict[str, object]:
    if zone_id < 0 or zone_id >= ZONE_SPACE:
        raise HTTPException(status_code=404, detail="zone not found")
    payload: dict[str, object] = {
        "zone_id": zone_id,
        "availability_bucket": _digest("availability", zone_id) % 11,
        "service_state": "open",
    }
    if view == "diagnostic":
        payload.update(
            {
                "backend_shard": f"shard-{_digest('shard', zone_id) % 8}",
                "sample_version": 1 + (_digest("version", zone_id) % 5),
                "cache_bucket": _digest("cache", zone_id) % 32,
            }
        )
    return payload
