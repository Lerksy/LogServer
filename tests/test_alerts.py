import tempfile
import unittest
from pathlib import Path

from logserver.alerts import (
    AlertDispatcher,
    AlertRepository,
    AlertValidationError,
    validate_rule,
)
from logserver.database import LogDatabase
from logserver.models import LogInput


def rule_payload(**overrides):
    payload = {
        "name": "Firewall sources",
        "enabled": True,
        "query": "severity:error",
        "regex": r"src=(?P<src_ip>\d+\.\d+\.\d+\.\d+)",
        "regex_target": "message",
        "template": "Blocked {src_ip}: {message}",
        "parse_mode": "",
        "cooldown_seconds": 0,
        "batch_window_seconds": 2,
    }
    payload.update(overrides)
    return payload


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = LogDatabase(Path(self.tempdir.name) / "logs.db")
        self.database.initialize()
        self.repository = AlertRepository(self.database.path)
        self.repository.update_telegram_settings(bot_token="123:secret", chat_id="-1001")
        self.sent = []
        self.dispatcher = AlertDispatcher(
            self.database,
            self.repository,
            sender=lambda settings, text, mode: self.sent.append((settings, text, mode)),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_settings_public_shape_never_contains_token(self):
        public = self.repository.get_telegram_settings().to_public_dict()
        self.assertTrue(public["bot_token_configured"])
        self.assertEqual(public["chat_id"], "-1001")
        self.assertNotIn("bot_token", public)
        self.assertNotIn("secret", repr(public))

    def test_validation_accepts_named_capture_and_rejects_unsafe_template(self):
        values = validate_rule(rule_payload())
        self.assertEqual(values["batch_window_seconds"], 2)
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="{message.__class__}"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(regex="("))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(regex_target=[]))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(parse_mode={}))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="Header [[body]] body [[body]] again"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="[[body]]Body only"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="Header [[/body]] Footer"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="Header [[/body]] Middle [[body]] Body"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="Header [[body]] Body [[/body]] again [[/body]]"))

    def test_consecutive_matches_are_sent_as_one_batch(self):
        rule = self.repository.create_rule(validate_rule(rule_payload(batch_window_seconds=10)))
        first = self.database.insert(LogInput(message="drop src=192.0.2.1", source="router", severity="error"))
        second = self.database.insert(LogInput(message="drop src=192.0.2.2", source="router", severity="error"))

        self.dispatcher.process(first)
        self.dispatcher.process(second)
        self.assertEqual(self.sent, [])
        self.dispatcher.flush_all()

        self.assertEqual(len(self.sent), 1)
        self.assertIn("Blocked 192.0.2.1", self.sent[0][1])
        self.assertIn("Blocked 192.0.2.2", self.sent[0][1])
        updated = self.repository.get_rule(rule.id)
        self.assertEqual(updated.sent_count, 1)
        self.assertIsNone(updated.last_error)

    def test_nonmatching_log_ends_a_batch(self):
        self.repository.create_rule(validate_rule(rule_payload(batch_window_seconds=10)))
        matching = self.database.insert(LogInput(message="drop src=192.0.2.1", source="router", severity="error"))
        unrelated = self.database.insert(LogInput(message="link up", source="router", severity="info"))

        self.dispatcher.process(matching)
        self.dispatcher.process(unrelated)
        self.assertEqual(len(self.sent), 1)

    def test_compact_batch_renders_header_once_and_each_body_once(self):
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=10,
            template="Firewall alert on {source}\n[[body]]\n• {src_ip}",
        )))
        first = self.database.insert(LogInput(message="drop src=192.0.2.1", source="router", severity="error"))
        second = self.database.insert(LogInput(message="drop src=192.0.2.2", source="router", severity="error"))

        self.dispatcher.process(first)
        self.dispatcher.process(second)
        self.dispatcher.flush_all()

        self.assertEqual(len(self.sent), 1)
        self.assertEqual(
            self.sent[0][1],
            "Firewall alert on router\n• 192.0.2.1\n• 192.0.2.2",
        )

    def test_compact_batch_renders_footer_once(self):
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=10,
            parse_mode="HTML",
            template=(
                "<b>Firewall alert: {count} entries</b>\n<blockquote expandable>\n"
                "[[body]]\n• <code>{src_ip}</code>\n[[/body]]\n"
                "</blockquote>\n<i>{count} entries in this batch</i>"
            ),
        )))
        first = self.database.insert(LogInput(message="drop src=192.0.2.1", source="router", severity="error"))
        second = self.database.insert(LogInput(message="drop src=192.0.2.2", source="router", severity="error"))

        self.dispatcher.process(first)
        self.dispatcher.process(second)
        self.dispatcher.flush_all()

        self.assertEqual(len(self.sent), 1)
        text = self.sent[0][1]
        self.assertEqual(text.count("<blockquote expandable>"), 1)
        self.assertEqual(text.count("</blockquote>"), 1)
        self.assertEqual(text.count("entries in this batch"), 1)
        self.assertEqual(text.count("<code>192.0.2."), 2)
        self.assertEqual(text.count("2 entries"), 2)

    def test_count_is_one_when_batching_is_disabled(self):
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            template="Entries: {count}",
        )))
        record = self.database.insert(LogInput(
            message="drop src=192.0.2.1",
            source="router",
            severity="error",
        ))

        self.dispatcher.process(record)

        self.assertEqual(self.sent[0][1], "Entries: 1")

    def test_zero_batch_window_sends_immediately(self):
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            template="{time}",
        )))
        with_event_time = self.database.insert(LogInput(
            message="drop src=192.0.2.1",
            source="router",
            severity="error",
            event_at="2026-09-21T01:02:03.000Z",
        ))
        without_event_time = self.database.insert(LogInput(
            message="drop src=192.0.2.2",
            source="router",
            severity="error",
        ))

        self.dispatcher.process(with_event_time)
        self.dispatcher.process(without_event_time)

        self.assertEqual(self.sent[0][1], "21 Sep 2026 · 01:02:03")
        self.assertRegex(self.sent[1][1], r"^\d{2} [A-Z][a-z]{2} \d{4} · \d{2}:\d{2}:\d{2}$")


if __name__ == "__main__":
    unittest.main()
