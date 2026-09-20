from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = Path("data/logs.db")
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    ingest_token: str | None = None
    max_body_bytes: int = 1_048_576

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_path=Path(os.getenv("LOGSERVER_DB", "data/logs.db")),
            http_host=os.getenv("LOGSERVER_HTTP_HOST", "0.0.0.0"),
            http_port=_int_env("LOGSERVER_HTTP_PORT", 8080),
            syslog_host=os.getenv("LOGSERVER_SYSLOG_HOST", "0.0.0.0"),
            syslog_port=_int_env("LOGSERVER_SYSLOG_PORT", 5514),
            ingest_token=os.getenv("LOGSERVER_INGEST_TOKEN") or None,
            max_body_bytes=_int_env("LOGSERVER_MAX_BODY_BYTES", 1_048_576),
        )

