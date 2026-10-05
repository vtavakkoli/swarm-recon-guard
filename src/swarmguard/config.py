from __future__ import annotations

from dataclasses import dataclass

TICKET_SPACE = 50_000
PERMIT_PREFIX_SPACE = 36 * 36
ZONE_SPACE = 500
TOTAL_SEMANTIC_SPACE = TICKET_SPACE + PERMIT_PREFIX_SPACE + ZONE_SPACE

LAB_ALLOWED_GATEWAY_HOSTS = {"gateway", "localhost", "127.0.0.1"}
LAB_ALLOWED_DETECTOR_HOSTS = {"detector", "localhost", "127.0.0.1"}


@dataclass(frozen=True)
class DetectorConfig:
    threshold: float = 0.72
    min_events: int = 30
    consecutive_windows: int = 2
