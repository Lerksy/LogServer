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
                """
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
