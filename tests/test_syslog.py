import socket
import threading
import unittest
from datetime import datetime, timezone

from logserver.syslog import SyslogTCPServer, parse_cef, parse_remote_message, parse_syslog


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

    def test_routeros_cef_message(self):
        item = parse_cef(
            b"Oct  2 17:36:35 MikroTik CEF:0|MikroTik|hAP ax^2|7.25beta5|10|"
            b"system,error,critical|High|dvchost=edge-router dvc=192.168.88.36 "
            b"msg=login failure for user guest from 192.168.88.17 via ssh "
            b"app=ssh duser=guest outcome=failure src=192.168.88.17\r\n",
            "192.0.2.7",
            now=datetime(2026, 10, 2, 18, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(item.source, "edge-router")
        self.assertEqual(item.severity, "error")
        self.assertEqual(item.topics, ["system", "error", "critical"])
        self.assertEqual(item.message, "login failure for user guest from 192.168.88.17 via ssh")
        self.assertEqual(item.event_at, "2026-10-02T17:36:35.000Z")
        self.assertEqual(item.transport, "cef-tcp")
        self.assertEqual(item.metadata["product"], "hAP ax^2")
        self.assertEqual(item.metadata["extensions"]["src"], "192.168.88.17")

    def test_cef_iso_timestamp_and_escaped_extension(self):
        item = parse_cef(
            b"2026-10-02T17:36:35.123+03:00 core CEF:0|MikroTik|CCR|7.25|12|"
            b"system,info|Low|dvchost=core msg=value\\=one and slash\\\\two app=test\n",
            "192.0.2.8",
            transport="cef-tls",
        )
        self.assertEqual(item.event_at, "2026-10-02T14:36:35.123Z")
        self.assertEqual(item.message, "value=one and slash\\two")
        self.assertEqual(item.transport, "cef-tls")

    def test_udp_cef_is_detected(self):
        item = parse_remote_message(
            b"Oct  2 17:36:35 router CEF:0|MikroTik|RB5009|7.25|1|system,info|Low|"
            b"dvchost=router msg=started\r\n",
            "192.0.2.9",
        )
        self.assertEqual(item.transport, "cef-udp")
        self.assertEqual(item.message, "started")


class _CollectingService:
    def __init__(self):
        self.items = []
        self.ready = threading.Event()

    def ingest(self, item):
        self.items.append(item)
        if len(self.items) >= 2:
            self.ready.set()


class SyslogTCPServerTests(unittest.TestCase):
    def test_fragmented_and_combined_cef_frames(self):
        service = _CollectingService()
        server = SyslogTCPServer(("127.0.0.1", 0), service)
        thread = server.start_in_thread()
        first = (
            b"Oct  2 17:36:35 one CEF:0|MikroTik|RB5009|7.25|1|system,info|Low|"
            b"dvchost=one msg=first\r\n"
        )
        second = (
            b"Oct  2 17:36:36 two CEF:0|MikroTik|CCR|7.25|2|system,warning|Medium|"
            b"dvchost=two msg=second\r\n"
        )
        try:
            with socket.create_connection(server.server_address, timeout=2) as connection:
                connection.sendall(first[:31])
                connection.sendall(first[31:] + second)
            self.assertTrue(service.ready.wait(2))
            self.assertEqual([item.message for item in service.items], ["first", "second"])
            self.assertEqual([item.source for item in service.items], ["one", "two"])
            self.assertTrue(all(item.transport == "cef-tcp" for item in service.items))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
