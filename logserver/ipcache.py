from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ABUSE_FILTERS = {"all", "reported", "clean", "unavailable"}


class IPCacheRepository:
    def __init__(self, database_path: Path | str):
        self.path = Path(database_path)

    def list_addresses(
        self,
        *,
        query: str = "",
        abuse: str = "all",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        if abuse not in ABUSE_FILTERS:
            raise ValueError("unknown abuse filter")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM ip_intel_cache ORDER BY ip, fetched_at DESC"
            ).fetchall()

        items = [self._merge_ip(group) for group in self._group_by_ip(rows)]
        items.sort(key=lambda item: item["fetched_at"], reverse=True)
        counts = {
            "total": len(items),
            "reported": sum(item["abuse_status"] == "reported" for item in items),
            "clean": sum(item["abuse_status"] == "clean" for item in items),
            "unavailable": sum(item["abuse_status"] == "unavailable" for item in items),
        }

        normalized_query = query.strip().casefold()
        if normalized_query:
            items = [item for item in items if self._matches(item, normalized_query)]
        if abuse != "all":
            items = [item for item in items if item["abuse_status"] == abuse]

        filtered = len(items)
        page = items[offset:offset + limit]
        return {
            "items": page,
            "counts": counts,
            "filtered": filtered,
            "has_more": offset + len(page) < filtered,
            "next_offset": offset + len(page) if offset + len(page) < filtered else None,
        }

    def get_address(self, ip: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM ip_intel_cache WHERE ip = ? ORDER BY fetched_at DESC",
                (ip,),
            ).fetchall()
        return self._merge_ip(rows) if rows else None

    @staticmethod
    def _group_by_ip(rows: list[sqlite3.Row]) -> list[list[sqlite3.Row]]:
        groups: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            groups.setdefault(row["ip"], []).append(row)
        return list(groups.values())

    @classmethod
    def _merge_ip(cls, rows: list[sqlite3.Row]) -> dict[str, Any]:
        newest = max(rows, key=lambda row: row["fetched_at"])
        location = max(
            rows,
            key=lambda row: (cls._location_priority(row["provider"]), row["fetched_at"]),
        )
        twoip_rows = [row for row in rows if row["provider"].startswith("2ip")]
        abuse = max(twoip_rows, key=lambda row: row["fetched_at"]) if twoip_rows else newest
        abuse_count = cls._numeric_abuse_count(abuse["abuse_count"])
        if abuse_count is None:
            abuse_status = "unavailable"
        elif abuse_count > 0:
            abuse_status = "reported"
        else:
            abuse_status = "clean"
        errors = list(dict.fromkeys(row["error"] for row in rows if row["error"]))
        return {
            "ip": newest["ip"],
            "country": location["country"],
            "city": location["city"],
            "company": location["company"],
            "abuse_count": abuse_count,
            "abuse_status": abuse_status,
            "abuse_summary": abuse["abuse_summary"],
            "abuse_last_seen": abuse["abuse_last_seen"],
            "providers": sorted({row["provider"] for row in rows}),
            "fetched_at": newest["fetched_at"],
            "expires_at": newest["expires_at"],
            "expired": cls._expired(newest["expires_at"]),
            "error": "; ".join(errors),
        }

    @staticmethod
    def _location_priority(provider: str) -> int:
        if provider == "2ip:en":
            return 3
        if provider == "ipapi":
            return 2
        return 1

    @staticmethod
    def _numeric_abuse_count(value: str) -> int | None:
        try:
            count = int(value)
        except (TypeError, ValueError):
            return None
        return max(0, count)

    @staticmethod
    def _matches(item: dict[str, Any], query: str) -> bool:
        values = (
            item["ip"], item["country"], item["city"], item["company"],
            item["abuse_summary"], " ".join(item["providers"]), item["error"],
        )
        return any(query in str(value).casefold() for value in values)

    @staticmethod
    def _expired(value: str) -> bool:
        try:
            expires_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return True
        return expires_at <= datetime.now(timezone.utc)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection
