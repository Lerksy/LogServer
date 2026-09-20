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

    def test_zero_batch_window_sends_immediately(self):
        self.repository.create_rule(validate_rule(rule_payload(batch_window_seconds=0)))
        record = self.database.insert(LogInput(message="drop src=192.0.2.1", source="router", severity="error"))
        self.dispatcher.process(record)
        self.assertEqual(len(self.sent), 1)


if __name__ == "__main__":
    unittest.main()
