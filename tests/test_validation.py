import unittest

from logserver.validation import ValidationError, log_input_from_json


class ValidationTests(unittest.TestCase):
    def test_normalizes_http_input(self):
        item = log_input_from_json(
            {
                "message": "  hello  ",
                "topics": "system, account",
                "level": "WARNING",
                "timestamp": "2026-09-20T12:30:00+02:00",
            },
            "127.0.0.1",
        )
        self.assertEqual(item.message, "hello")
        self.assertEqual(item.topics, ["system", "account"])
        self.assertEqual(item.severity, "warning")
        self.assertEqual(item.event_at, "2026-09-20T10:30:00.000Z")

    def test_rejects_bad_payloads(self):
        for payload in [{}, {"message": ""}, {"message": "x", "severity": "bad"}, {"message": "x", "metadata": []}]:
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                log_input_from_json(payload, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()

