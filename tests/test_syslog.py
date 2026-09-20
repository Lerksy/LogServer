import unittest
from datetime import datetime, timezone

from logserver.syslog import parse_syslog


class SyslogParserTests(unittest.TestCase):
    def test_routeros_rfc3164_message(self):
        item = parse_syslog(
            b"<134>Sep 20 12:34:56 edge-router system,info,account user admin logged in",
            "192.0.2.4",
            now=datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(item.source, "edge-router")
        self.assertEqual(item.facility, "local0")
        self.assertEqual(item.severity, "info")
        self.assertEqual(item.topics, ["system", "info", "account"])
        self.assertEqual(item.message, "user admin logged in")
        self.assertEqual(item.event_at, "2026-09-20T12:34:56.000Z")

    def test_routeros_topics_string_with_firewall_prefix(self):
        item = parse_syslog(
            b"<134>Sep 21 01:14:12 RouterOS firewall,info [Alex PC RDP] dstnat: packet dropped",
            "192.168.1.1",
            now=datetime(2026, 9, 21, 2, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(item.topics, ["firewall", "info"])
        self.assertEqual(item.message, "[Alex PC RDP] dstnat: packet dropped")

    def test_current_routeros_topic_vocabulary(self):
        item = parse_syslog(
            b"<135>Sep 21 01:14:12 RouterOS bridge,stp,debug,packet transmitted BPDU",
            "192.168.1.1",
            now=datetime(2026, 9, 21, 2, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(item.topics, ["bridge", "stp", "debug", "packet"])
        self.assertEqual(item.message, "transmitted BPDU")

    def test_rfc5424_message(self):
        item = parse_syslog(
            b"<131>1 2026-09-20T11:22:33Z router.example firewall 91 ID47 - blocked packet",
            "192.0.2.5",
        )
        self.assertEqual(item.source, "router.example")
        self.assertEqual(item.severity, "error")
        self.assertEqual(item.message, "blocked packet")
        self.assertEqual(item.metadata["protocol"], "rfc5424")
        self.assertEqual(item.metadata["app"], "firewall")

    def test_unstructured_message_preserves_peer(self):
        item = parse_syslog(b"plain log", "198.51.100.9")
        self.assertEqual(item.source, "198.51.100.9")
        self.assertEqual(item.message, "plain log")
        self.assertEqual(item.raw, "plain log")


if __name__ == "__main__":
    unittest.main()
