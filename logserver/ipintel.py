from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


IP_TEMPLATE_FIELDS = {
    "ip_country", "ip_city", "ip_company",
    "ip_abuse_count", "ip_abuse_summary", "ip_abuse_last_seen",
}
IP_PROVIDERS = {"ipapi", "2ip"}


@dataclass(frozen=True, slots=True)
class IPInfo:
    country: str
    city: str
    company: str
    abuse_count: str = "Unavailable"
    abuse_summary: str = "Not supported by this provider"
    abuse_last_seen: str = ""

    def to_context(self) -> dict[str, str]:
        return {
            "ip_country": self.country,
            "ip_city": self.city,
            "ip_company": self.company,
            "ip_abuse_count": self.abuse_count,
            "ip_abuse_summary": self.abuse_summary,
            "ip_abuse_last_seen": self.abuse_last_seen,
        }


class IPEnricher:
    def __init__(
        self,
        database_path: Path | str,
        *,
        fetcher: Callable[[str], dict[str, Any]] | None = None,
        twoip_geo_fetcher: Callable[[str, str], dict[str, Any]] | None = None,
        twoip_abuse_fetcher: Callable[[str, str], dict[str, Any]] | None = None,
        twoip_token_getter: Callable[[], str] | None = None,
        cache_days: int = 30,
        failure_hours: int = 1,
        minimum_interval: float = 1.0,
    ):
        self.path = Path(database_path)
        self.fetcher = fetcher or self._fetch_ipapi
        self.twoip_geo_fetcher = twoip_geo_fetcher or self._fetch_twoip_geo
        self.twoip_abuse_fetcher = twoip_abuse_fetcher or self._fetch_twoip_abuses
        self.twoip_token_getter = twoip_token_getter or (lambda: "")
        self.cache_ttl = timedelta(days=cache_days)
        self.failure_ttl = timedelta(hours=failure_hours)
        self.minimum_interval = minimum_interval
        self._next_request_at = 0.0
        self._request_lock = threading.Lock()

    def lookup(self, value: str, provider: str = "ipapi") -> IPInfo:
        if provider not in IP_PROVIDERS:
            raise ValueError(f"Unknown IP provider '{provider}'")
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return self._unknown()
        ip = address.compressed
        cached = self._cached(provider, ip)
        if cached is not None:
            return cached
        if not address.is_global:
            result = self._unknown()
            self._store(provider, ip, result, self.cache_ttl, "non-public IP address")
            return result

        try:
            if provider == "2ip":
                result, error = self._lookup_twoip(ip)
            else:
                result, error = self._lookup_ipapi(ip)
            ttl = self.failure_ttl if error else self.cache_ttl
            self._store(provider, ip, result, ttl, error)
            return result
        except Exception as exc:
            result = self._unknown()
            self._store(provider, ip, result, self.failure_ttl, str(exc))
            return result

    def _lookup_ipapi(self, ip: str) -> tuple[IPInfo, str | None]:
        payload = self._paced_request(lambda: self.fetcher(ip))
        self._raise_payload_error(payload)
        result = IPInfo(
            country=self._value(payload.get("country_name")),
            city=self._value(payload.get("city")),
            company=self._value(payload.get("org")),
        )
        if all(value == "Unknown" for value in (result.country, result.city, result.company)):
            raise RuntimeError("ipapi.co returned no location or organization data")
        return result, None

    def _lookup_twoip(self, ip: str) -> tuple[IPInfo, str | None]:
        token = self.twoip_token_getter().strip()
        payload = self._paced_request(lambda: self.twoip_geo_fetcher(ip, token))
        self._raise_payload_error(payload)
        asn = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
        base = {
            "country": self._value(payload.get("country")),
            "city": self._value(payload.get("city")),
            "company": self._value(asn.get("name")),
        }
        if all(value == "Unknown" for value in base.values()):
            raise RuntimeError("2ip.io returned no location or organization data")
        if not token:
            return IPInfo(
                **base,
                abuse_count="Unavailable",
                abuse_summary="2ip token required",
            ), None
        try:
            abuse_payload = self._paced_request(lambda: self.twoip_abuse_fetcher(ip, token))
            self._raise_payload_error(abuse_payload)
            abuse_count, abuse_summary, abuse_last_seen = self._abuse_values(abuse_payload)
            return IPInfo(
                **base,
                abuse_count=abuse_count,
                abuse_summary=abuse_summary,
                abuse_last_seen=abuse_last_seen,
            ), None
        except Exception as exc:
            return IPInfo(
                **base,
                abuse_count="Unknown",
                abuse_summary="Abuse lookup failed",
            ), str(exc)

    def _paced_request(self, request: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        with self._request_lock:
            wait = self._next_request_at - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._next_request_at = time.monotonic() + self.minimum_interval
            return request()

    def _cached(self, provider: str, ip: str) -> IPInfo | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM ip_intel_cache WHERE provider = ? AND ip = ?",
                (provider, ip),
            ).fetchone()
        if row is None:
            return None
        try:
            expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if expires_at <= datetime.now(timezone.utc):
            return None
        return IPInfo(
            row["country"], row["city"], row["company"],
            row["abuse_count"], row["abuse_summary"], row["abuse_last_seen"],
        )

    def _store(
        self,
        provider: str,
        ip: str,
        result: IPInfo,
        ttl: timedelta,
        error: str | None,
    ) -> None:
        now = datetime.now(timezone.utc)
        fetched_at = self._timestamp(now)
        expires_at = self._timestamp(now + ttl)
        with closing(self._connect()) as connection, connection:
            connection.execute("DELETE FROM ip_intel_cache WHERE expires_at <= ?", (fetched_at,))
            connection.execute(
                """
                INSERT INTO ip_intel_cache (
                    provider, ip, country, city, company,
                    abuse_count, abuse_summary, abuse_last_seen,
                    fetched_at, expires_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, ip) DO UPDATE SET
                    country = excluded.country,
                    city = excluded.city,
                    company = excluded.company,
                    abuse_count = excluded.abuse_count,
                    abuse_summary = excluded.abuse_summary,
                    abuse_last_seen = excluded.abuse_last_seen,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at,
                    error = excluded.error
                """,
                (
                    provider, ip, result.country, result.city, result.company,
                    result.abuse_count, result.abuse_summary, result.abuse_last_seen,
                    fetched_at, expires_at, (error or "")[:500] or None,
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _fetch_ipapi(ip: str) -> dict[str, Any]:
        encoded_ip = urllib.parse.quote(ip, safe="")
        request = urllib.request.Request(
            f"https://ipapi.co/{encoded_ip}/json/",
            headers={"Accept": "application/json", "User-Agent": "MikroTik-LogServer/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"ipapi.co returned HTTP {exc.code}") from exc
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"ipapi.co lookup failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("ipapi.co returned an invalid response")
        return payload

    @classmethod
    def _fetch_twoip_geo(cls, ip: str, token: str) -> dict[str, Any]:
        query = "?" + urllib.parse.urlencode({"token": token}) if token else ""
        encoded_ip = urllib.parse.quote(ip, safe="")
        return cls._fetch_json(f"https://api.2ip.io/{encoded_ip}{query}", "2ip.io")

    @classmethod
    def _fetch_twoip_abuses(cls, ip: str, token: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"token": token})
        encoded_ip = urllib.parse.quote(ip, safe="")
        return cls._fetch_json(f"https://api.2ip.io/abuses/{encoded_ip}?{query}", "2ip.io")

    @staticmethod
    def _fetch_json(url: str, service: str) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "MikroTik-LogServer/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{service} returned HTTP {exc.code}") from exc
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"{service} lookup failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"{service} returned an invalid response")
        return payload

    @staticmethod
    def _raise_payload_error(payload: dict[str, Any]) -> None:
        if payload.get("error"):
            raise RuntimeError(str(payload.get("reason") or payload.get("message") or "lookup failed"))

    @classmethod
    def _abuse_values(cls, payload: dict[str, Any]) -> tuple[str, str, str]:
        abuses = payload.get("abuses", [])
        if isinstance(abuses, dict):
            abuses = [abuses]
        if not isinstance(abuses, list):
            raise RuntimeError("2ip.io returned invalid abuse data")
        reports = [item for item in abuses if isinstance(item, dict)]
        descriptions: list[str] = []
        dates: list[str] = []
        for report in reports:
            description = cls._value(report.get("description"))
            if description != "Unknown" and description not in descriptions:
                descriptions.append(description)
            date = str(report.get("date") or "").strip()
            if date:
                dates.append(date)
        summary = "; ".join(descriptions)[:1000] if descriptions else "No reports"
        return str(len(reports)), summary, max(dates, default="")

    @staticmethod
    def _value(value: Any) -> str:
        if value is None:
            return "Unknown"
        text = str(value).strip()
        return text[:255] if text else "Unknown"

    @staticmethod
    def _unknown() -> IPInfo:
        return IPInfo("Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "")

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
