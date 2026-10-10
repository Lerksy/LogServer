import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from logserver.config import Settings
from logserver.database import LogDatabase
from logserver.events import EventBroker
from logserver.http import LogHTTPServer
from logserver.service import LogService


class HTTPIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        database = LogDatabase(Path(self.tempdir.name) / "logs.db")
        database.initialize()
        service = LogService(database, EventBroker())
        settings = Settings(database_path=database.path, ingest_token="secret")
        self.server = LogHTTPServer(("127.0.0.1", 0), service, settings)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request(self, path, *, method="GET", payload=None, token=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        return response.status, json.loads(body) if body else None

    def test_health_and_static_ui(self):
        status, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok", "logs": 0})
        response = urllib.request.urlopen(self.base_url + "/", timeout=2)
        self.assertIn(b"Router LogServer", response.read())
        response = urllib.request.urlopen(self.base_url + "/manage", timeout=2)
        management = response.read()
        self.assertIn(b"Alert Management", management)
        self.assertIn(b"IP intelligence services", management)

    def test_live_streams_are_limited_per_client(self):
        streams = []
        try:
            for _ in range(2):
                response = urllib.request.urlopen(self.base_url + "/api/stream", timeout=2)
                self.assertEqual(response.readline(), b": connected\n")
                streams.append(response)

            status, body = self.request("/api/stream")
            self.assertEqual(status, 429)
            self.assertEqual(body["error"]["code"], "stream_limit")
        finally:
            for response in streams:
                response.close()

    def test_ingest_requires_token(self):
        status, body = self.request("/api/logs", method="POST", payload={"message": "denied"})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")

    def test_ingest_batch_and_search(self):
        payload = [
            {"message": "login accepted", "source": "router-a", "severity": "info", "topics": ["account"]},
            {"message": "packet blocked", "source": "router-a", "severity": "error", "topics": ["firewall"]},
        ]
        status, body = self.request("/api/logs", method="POST", payload=payload, token="secret")
        self.assertEqual(status, 201)
        self.assertEqual(body["count"], 2)

        status, body = self.request("/api/logs?q=severity%3Aerror")
        self.assertEqual(status, 200)
        self.assertEqual([item["message"] for item in body["items"]], ["packet blocked"])

        status, body = self.request("/api/logs?minimum_severity=warning")
        self.assertEqual(status, 200)
        self.assertEqual([item["message"] for item in body["items"]], ["packet blocked"])

        status, body = self.request("/api/logs?minimum_severity=verbose")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "minimum_severity")

    def test_invalid_search_is_a_client_error(self):
        status, body = self.request("/api/logs?q=%28unclosed")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "search_syntax")

    def test_alert_settings_and_rule_crud(self):
        status, settings = self.request(
            "/api/admin/telegram",
            method="PUT",
            payload={"bot_token": "123:secret", "chat_id": "-1001"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(settings["bot_token_configured"])
        self.assertNotIn("bot_token", settings)

        status, ip_settings = self.request(
            "/api/admin/ip-services",
            method="PUT",
            payload={"twoip_token": "twoip-secret"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(ip_settings["twoip_token_configured"])
        self.assertNotIn("twoip_token", ip_settings)
        status, ip_settings = self.request("/api/admin/ip-services")
        self.assertEqual(status, 200)
        self.assertTrue(ip_settings["twoip_token_configured"])

        rule = {
            "name": "Errors",
            "enabled": True,
            "query": "severity:error",
            "regex": r"src=(?P<src_ip>\S+)",
            "regex_target": "message",
            "ip_lookup_field": "src_ip",
            "ip_provider": "2ip",
            "ip_locale": "de",
            "country_filter": r"^(Germany|France)$",
            "country_filter_mode": "include",
            "additional_chat_ids": ["-1002", "@operations"],
            "template": "Source {src_ip} ({ip_country}): {message}",
            "parse_mode": "",
            "cooldown_seconds": 0,
            "batch_window_seconds": 2,
        }
        status, created = self.request("/api/admin/rules", method="POST", payload=rule)
        self.assertEqual(status, 201)
        self.assertEqual(created["name"], "Errors")
        self.assertEqual(created["ip_lookup_field"], "src_ip")
        self.assertEqual(created["ip_provider"], "2ip")
        self.assertEqual(created["ip_locale"], "de")
        self.assertEqual(created["country_filter"], r"^(Germany|France)$")
        self.assertEqual(created["additional_chat_ids"], ["-1002", "@operations"])

        status, listing = self.request("/api/admin/rules")
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["items"]), 1)

        rule["name"] = "Critical errors"
        status, updated = self.request(f"/api/admin/rules/{created['id']}", method="PUT", payload=rule)
        self.assertEqual(status, 200)
        self.assertEqual(updated["name"], "Critical errors")

        status, deleted = self.request(f"/api/admin/rules/{created['id']}", method="DELETE")
        self.assertEqual(status, 200)
        self.assertTrue(deleted["deleted"])


if __name__ == "__main__":
    unittest.main()
