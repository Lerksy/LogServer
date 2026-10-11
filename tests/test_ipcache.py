import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from logserver.database import LogDatabase
from logserver.ipcache import IPCacheRepository


class IPCacheRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "logs.db"
        LogDatabase(self.path).initialize()
        self.repository = IPCacheRepository(self.path)
        self._insert(
            "ipapi", "8.8.8.8", "United States", "Mountain View", "Google LLC",
            "Unavailable", "Not supported by ipapi.co", "", "2026-01-01T00:00:00.000Z",
        )
        self._insert(
            "2ip:en", "8.8.8.8", "United States", "Chicago", "GOOGLE",
            "1", "Port Scan", "2025-12-01", "2026-01-02T00:00:00.000Z",
        )
        self._insert(
            "2ip:ua", "8.8.8.8", "США", "Чикаго", "GOOGLE",
            "2", "Port Scan; Mail Spam", "2026-01-01", "2026-01-03T00:00:00.000Z",
        )
        self._insert(
            "2ip:en", "1.1.1.1", "Australia", "Sydney", "CLOUDFLARENET",
            "0", "No reports", "", "2026-01-04T00:00:00.000Z",
        )
        self._insert(
            "ipapi", "192.0.2.1", "Unknown", "Unknown", "Unknown",
            "Unknown", "Unknown", "", "2026-01-05T00:00:00.000Z", "non-public IP address",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _insert(
        self,
        provider,
        ip,
        country,
        city,
        company,
        abuse_count,
        abuse_summary,
        abuse_last_seen,
        fetched_at,
        error=None,
    ):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                INSERT INTO ip_intel_cache (
                    provider, ip, country, city, company, abuse_count, abuse_summary,
                    abuse_last_seen, fetched_at, expires_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '2099-01-01T00:00:00.000Z', ?)
                """,
                (
                    provider, ip, country, city, company, abuse_count, abuse_summary,
                    abuse_last_seen, fetched_at, error,
                ),
            )

    def test_merges_provider_and_language_variants_by_ip(self):
        result = self.repository.list_addresses(limit=10)

        self.assertEqual(result["counts"], {"total": 3, "reported": 1, "clean": 1, "unavailable": 1})
        google = next(item for item in result["items"] if item["ip"] == "8.8.8.8")
        self.assertEqual(google["country"], "United States")
        self.assertEqual(google["abuse_count"], 2)
        self.assertEqual(google["abuse_status"], "reported")
        self.assertEqual(google["providers"], ["2ip:en", "2ip:ua", "ipapi"])

    def test_filters_searches_and_paginates(self):
        reported = self.repository.list_addresses(abuse="reported", limit=10)
        self.assertEqual([item["ip"] for item in reported["items"]], ["8.8.8.8"])

        clean = self.repository.list_addresses(query="cloudflare", abuse="clean", limit=10)
        self.assertEqual([item["ip"] for item in clean["items"]], ["1.1.1.1"])

        first = self.repository.list_addresses(limit=1)
        self.assertTrue(first["has_more"])
        second = self.repository.list_addresses(limit=1, offset=first["next_offset"])
        self.assertEqual(len(second["items"]), 1)


if __name__ == "__main__":
    unittest.main()
