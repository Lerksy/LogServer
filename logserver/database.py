from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .models import LogInput, LogRecord, SEVERITIES_BY_URGENCY, utc_now
from .search import compile_search


class LogDatabase:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    event_at TEXT,
                    source TEXT NOT NULL,
                    facility TEXT,
                    severity TEXT NOT NULL,
                    topics TEXT NOT NULL DEFAULT '[]',
                    message TEXT NOT NULL,
                    raw TEXT,
                    transport TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_logs_received_at ON logs(received_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_event_at ON logs(event_at DESC);
                CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);
                CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);

                CREATE TABLE IF NOT EXISTS telegram_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    bot_token TEXT NOT NULL DEFAULT '',
                    chat_id TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                INSERT OR IGNORE INTO telegram_settings (id, updated_at) VALUES (1, '');

                CREATE TABLE IF NOT EXISTS alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    query TEXT NOT NULL DEFAULT '',
                    regex TEXT NOT NULL DEFAULT '',
                    regex_target TEXT NOT NULL DEFAULT 'message',
                    ip_lookup_field TEXT NOT NULL DEFAULT '',
                    country_filter TEXT NOT NULL DEFAULT '',
                    country_filter_mode TEXT NOT NULL DEFAULT 'include',
                    template TEXT NOT NULL,
                    parse_mode TEXT NOT NULL DEFAULT '',
                    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
                    batch_window_seconds INTEGER NOT NULL DEFAULT 2,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_sent_at TEXT,
                    last_error TEXT,
                    sent_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);

                CREATE TABLE IF NOT EXISTS ip_lookup_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT NOT NULL DEFAULT '',
                    city TEXT NOT NULL DEFAULT '',
                    company TEXT NOT NULL DEFAULT '',
                    fetched_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_ip_lookup_cache_expires_at
                    ON ip_lookup_cache(expires_at);
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(alert_rules)")}
            if "batch_window_seconds" not in columns:
                connection.execute(
                    "ALTER TABLE alert_rules ADD COLUMN batch_window_seconds INTEGER NOT NULL DEFAULT 2"
                )
            if "ip_lookup_field" not in columns:
                connection.execute(
                    "ALTER TABLE alert_rules ADD COLUMN ip_lookup_field TEXT NOT NULL DEFAULT ''"
                )
            if "country_filter" not in columns:
                connection.execute(
                    "ALTER TABLE alert_rules ADD COLUMN country_filter TEXT NOT NULL DEFAULT ''"
                )
            if "country_filter_mode" not in columns:
                connection.execute(
                    "ALTER TABLE alert_rules ADD COLUMN country_filter_mode TEXT NOT NULL DEFAULT 'include'"
                )

    def insert(self, item: LogInput) -> LogRecord:
        return self.insert_many([item])[0]

    def insert_many(self, items: list[LogInput]) -> list[LogRecord]:
        records: list[LogRecord] = []
        with closing(self._connect()) as connection, connection:
            for item in items:
                cursor = connection.execute(
                    """
                    INSERT INTO logs (
                        received_at, event_at, source, facility, severity,
                        topics, message, raw, transport, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        utc_now(),
                        item.event_at,
                        item.source,
                        item.facility,
                        item.severity,
                        json.dumps(item.topics, ensure_ascii=False, separators=(",", ":")),
                        item.message,
                        item.raw,
                        item.transport,
                        json.dumps(item.metadata, ensure_ascii=False, separators=(",", ":")),
                    ),
                )
                row = connection.execute("SELECT * FROM logs WHERE id = ?", (cursor.lastrowid,)).fetchone()
                assert row is not None
                records.append(self._record(row))
        return records

    def search(
        self,
        query: str | None = None,
        *,
        limit: int = 100,
        before_id: int | None = None,
        minimum_severity: str = "debug",
    ) -> tuple[list[LogRecord], bool]:
        sql_filter = compile_search(query)
        clauses = [sql_filter.clause]
        params = list(sql_filter.params)
        try:
            severity_index = SEVERITIES_BY_URGENCY.index(minimum_severity)
        except ValueError as exc:
            raise ValueError(f"Unknown minimum severity '{minimum_severity}'") from exc
        if severity_index < len(SEVERITIES_BY_URGENCY) - 1:
            included = SEVERITIES_BY_URGENCY[: severity_index + 1]
            placeholders = ",".join("?" for _ in included)
            clauses.append(f"severity IN ({placeholders})")
            params.extend(included)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        params.append(limit + 1)
        sql = f"SELECT * FROM logs WHERE {' AND '.join(f'({part})' for part in clauses)} ORDER BY id DESC LIMIT ?"
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(sql, params).fetchall()
        has_more = len(rows) > limit
        return [self._record(row) for row in rows[:limit]], has_more

    def count(self) -> int:
        with closing(self._connect()) as connection, connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM logs").fetchone()
        assert row is not None
        return int(row["count"])

    def matches(self, record_id: int, query: str | None) -> bool:
        sql_filter = compile_search(query)
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                f"SELECT 1 FROM logs WHERE id = ? AND ({sql_filter.clause}) LIMIT 1",
                (record_id, *sql_filter.params),
            ).fetchone()
        return row is not None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _record(row: sqlite3.Row) -> LogRecord:
        return LogRecord(
            id=row["id"],
            received_at=row["received_at"],
            event_at=row["event_at"],
            source=row["source"],
            facility=row["facility"],
            severity=row["severity"],
            topics=json.loads(row["topics"]),
            message=row["message"],
            raw=row["raw"],
            transport=row["transport"],
            metadata=json.loads(row["metadata"]),
        )
