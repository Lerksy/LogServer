import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from logserver.alerts import AlertRepository
from logserver.database import LogDatabase
from logserver.models import LogInput


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = LogDatabase(Path(self.tempdir.name) / "logs.db")
        self.database.initialize()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_insert_round_trip(self):
        record = self.database.insert(
            LogInput(
                message="admin logged in",
                source="router-1",
                severity="info",
                facility="local0",
                topics=["system", "account"],
                metadata={"address": "10.0.0.2"},
            )
        )
        self.assertEqual(record.id, 1)
        self.assertEqual(record.topics, ["system", "account"])
        self.assertEqual(record.metadata["address"], "10.0.0.2")
        self.assertEqual(self.database.count(), 1)

    def test_search_and_pagination(self):
        self.database.insert(LogInput(message="accepted", source="edge-a", severity="info", topics=["firewall"]))
        second = self.database.insert(LogInput(message="blocked", source="edge-b", severity="error", topics=["firewall"]))
        self.database.insert(LogInput(message="connected", source="edge-a", severity="info", topics=["wireguard"]))

        records, has_more = self.database.search("source:edge-a", limit=10)
        self.assertFalse(has_more)
        self.assertEqual([item.message for item in records], ["connected", "accepted"])

        records, has_more = self.database.search("topic:firewall", limit=1)
        self.assertTrue(has_more)
        self.assertEqual(records[0].id, second.id)
        older, has_more = self.database.search("topic:firewall", limit=1, before_id=second.id)
        self.assertFalse(has_more)
        self.assertEqual(older[0].message, "accepted")

    def test_complex_search(self):
        self.database.insert(LogInput(message="login failed", source="edge-a", severity="error"))
        self.database.insert(LogInput(message="link failed", source="edge-b", severity="critical"))
        self.database.insert(LogInput(message="login ok", source="edge-a", severity="info"))
        records, _ = self.database.search(
            '(severity:error OR severity:critical) AND NOT source:"edge-b"'
        )
        self.assertEqual([item.message for item in records], ["login failed"])

    def test_topic_equality_matches_a_complete_topic(self):
        self.database.insert(LogInput(message="one", source="edge", topics=["firewall"]))
        self.database.insert(LogInput(message="two", source="edge", topics=["firewall-detail"]))
        records, _ = self.database.search("topic=firewall")
        self.assertEqual([item.message for item in records], ["one"])

    def test_minimum_severity_includes_more_urgent_levels(self):
        for severity in ("debug", "info", "warning", "error", "critical"):
            self.database.insert(LogInput(message=severity, source="edge", severity=severity))
        records, _ = self.database.search(minimum_severity="warning")
        self.assertEqual([item.severity for item in records], ["critical", "error", "warning"])

    def test_ip_cache_migration_preserves_existing_alert_rule(self):
        path = Path(self.tempdir.name) / "legacy.db"
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL,
                    event_at TEXT, source TEXT NOT NULL, facility TEXT, severity TEXT NOT NULL,
                    topics TEXT NOT NULL, message TEXT NOT NULL, raw TEXT,
                    transport TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE telegram_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1), bot_token TEXT NOT NULL DEFAULT '',
                    chat_id TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
                );
                INSERT INTO telegram_settings VALUES (1, '', '', '');
                CREATE TABLE alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, query TEXT NOT NULL DEFAULT '',
                    regex TEXT NOT NULL DEFAULT '', regex_target TEXT NOT NULL DEFAULT 'message',
                    template TEXT NOT NULL, parse_mode TEXT NOT NULL DEFAULT '',
                    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
                    batch_window_seconds INTEGER NOT NULL DEFAULT 2,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    last_sent_at TEXT, last_error TEXT, sent_count INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO alert_rules (
                    name, query, regex, regex_target, template, created_at, updated_at
                ) VALUES ('Existing rule', '', '', 'message', '{message}', 'then', 'then');
                """
            )

        LogDatabase(path).initialize()

        rule = AlertRepository(path).get_rule(1)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "Existing rule")
        self.assertEqual(rule.ip_lookup_field, "")
        self.assertEqual(rule.country_filter, "")
        self.assertEqual(rule.country_filter_mode, "include")
        with closing(sqlite3.connect(path)) as connection:
            cache_exists = connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'ip_lookup_cache'"
            ).fetchone()[0]
        self.assertEqual(cache_exists, 1)


if __name__ == "__main__":
    unittest.main()
