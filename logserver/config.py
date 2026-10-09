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


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _path_env(name: str) -> Path | None:
    value = os.getenv(name)
    return Path(value) if value else None


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = Path("data/logs.db")
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    syslog_tcp_port: int = 5514
    syslog_tls_port: int = 6514
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    tls_auto_generate: bool = False
    max_syslog_bytes: int = 262_144
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
            syslog_tcp_port=_int_env("LOGSERVER_SYSLOG_TCP_PORT", 5514),
            syslog_tls_port=_int_env("LOGSERVER_SYSLOG_TLS_PORT", 6514),
            tls_certfile=_path_env("LOGSERVER_TLS_CERTFILE"),
            tls_keyfile=_path_env("LOGSERVER_TLS_KEYFILE"),
            tls_auto_generate=_bool_env("LOGSERVER_TLS_AUTO_GENERATE", False),
            max_syslog_bytes=_int_env("LOGSERVER_MAX_SYSLOG_BYTES", 262_144),
            ingest_token=os.getenv("LOGSERVER_INGEST_TOKEN") or None,
            max_body_bytes=_int_env("LOGSERVER_MAX_BODY_BYTES", 1_048_576),
        )

