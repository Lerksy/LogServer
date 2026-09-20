from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITIES_BY_URGENCY = (
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(slots=True)
class LogInput:
    message: str
    source: str
    severity: str = "info"
    facility: str | None = None
    topics: list[str] = field(default_factory=list)
    event_at: str | None = None
    raw: str | None = None
    transport: str = "http"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LogRecord:
    id: int
    received_at: str
    message: str
    source: str
    severity: str
    facility: str | None
    topics: list[str]
    event_at: str | None
    raw: str | None
    transport: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
