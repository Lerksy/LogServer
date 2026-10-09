import tempfile
import unittest
from pathlib import Path

from logserver.alerts import (
    AlertDispatcher,
    AlertRepository,
    AlertValidationError,
    IPEnricher,
    IPInfo,
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
        "ip_lookup_field": "",
        "ip_provider": "ipapi",
        "ip_locale": "en",
        "country_filter": "",
        "country_filter_mode": "include",
        "additional_chat_ids": [],
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
        values = validate_rule(rule_payload(
            template="[[if message matches ^drop\\s+src=.{2,}$]]{message}[[/if]]"
        ))
        self.assertIn("[[if message matches", values["template"])
        values = validate_rule(rule_payload(additional_chat_ids=[" -1002 ", "-1002", "@ops"]))
        self.assertEqual(values["additional_chat_ids"], ["-1002", "@ops"])
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
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="[[if missing]]No[[/if]]"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="[[if severity]]No closing marker"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="[[if count > 1]]Many[[/if]]"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(
                template="[[if severity]]Header [[body]]Body[[/body]]Footer[[/if]]"
            ))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(additional_chat_ids="-1002"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(additional_chat_ids=[""]))

    def test_ip_enrichment_validation(self):
        values = validate_rule(rule_payload(
            ip_lookup_field="src_ip",
            ip_provider="2ip",
            ip_locale="ua",
            template=(
                "{src_ip}: {ip_country}, {ip_city} — {ip_company}; "
                "abuses={ip_abuse_count} {ip_abuse_summary} {ip_abuse_last_seen}"
            ),
        ))
        self.assertEqual(values["ip_lookup_field"], "src_ip")
        self.assertEqual(values["ip_provider"], "2ip")
        self.assertEqual(values["ip_locale"], "ua")
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(ip_lookup_field="missing"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(template="{ip_country}"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(ip_provider="unknown"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(ip_locale="uk"))

    def test_country_filter_validation(self):
        values = validate_rule(rule_payload(
            ip_lookup_field="src_ip",
            country_filter=r"^(United Kingdom|Germany)$",
            country_filter_mode="exclude",
        ))
        self.assertEqual(values["country_filter_mode"], "exclude")
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(country_filter="Germany"))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(ip_lookup_field="src_ip", country_filter="("))
        with self.assertRaises(AlertValidationError):
            validate_rule(rule_payload(
                ip_lookup_field="src_ip", country_filter="Germany", country_filter_mode="other",
            ))

    def test_ip_enrichment_is_added_to_alert_context(self):
        looked_up = []
        dispatcher = AlertDispatcher(
            self.database,
            self.repository,
            sender=lambda settings, text, mode: self.sent.append((settings, text, mode)),
            enricher=lambda ip, provider, locale: looked_up.append((ip, provider, locale))
            or IPInfo("United States", "Mountain View", "Google LLC"),
        )
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            ip_lookup_field="src_ip",
            template="{src_ip}: {ip_country}, {ip_city} — {ip_company}",
        )))
        record = self.database.insert(LogInput(
            message="drop src=8.8.8.8", source="router", severity="error",
        ))

        dispatcher.process(record)

        self.assertEqual(looked_up, [("8.8.8.8", "ipapi", "en")])
        self.assertEqual(self.sent[0][1], "8.8.8.8: United States, Mountain View — Google LLC")

    def test_conditional_abuse_block_uses_raw_values_and_escapes_output(self):
        dispatcher = AlertDispatcher(
            self.database,
            self.repository,
            sender=lambda settings, text, mode: self.sent.append((settings, text, mode)),
            enricher=lambda ip, provider, locale: IPInfo(
                "United States", "New York", "Example", "2", "Scan <reported>", "2026-10-01",
            ),
        )
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            ip_lookup_field="src_ip",
            parse_mode="HTML",
            template=(
                "{src_ip}\n[[if ip_abuse_count > 0]]"
                "Abuse: {ip_abuse_count} — {ip_abuse_summary}"
                "[[else]]No abuse reports[[/if]]"
            ),
        )))
        record = self.database.insert(LogInput(
            message="drop src=8.8.8.8", source="router", severity="error",
        ))

        dispatcher.process(record)

        self.assertEqual(self.sent[0][1], "8.8.8.8\nAbuse: 2 — Scan &lt;reported&gt;")

    def test_conditional_abuse_block_hides_unavailable_data(self):
        dispatcher = AlertDispatcher(
            self.database,
            self.repository,
            sender=lambda settings, text, mode: self.sent.append((settings, text, mode)),
            enricher=lambda ip, provider, locale: IPInfo(
                "Unknown", "Unknown", "Unknown", "Unavailable", "2ip token required", "",
            ),
        )
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            ip_lookup_field="src_ip",
            template=(
                "[[if ip_abuse_count]]Abuse: {ip_abuse_count}"
                "[[else]]Abuse information unavailable[[/if]]"
            ),
        )))
        record = self.database.insert(LogInput(
            message="drop src=8.8.8.8", source="router", severity="error",
        ))

        dispatcher.process(record)

        self.assertEqual(self.sent[0][1], "Abuse information unavailable")

    def test_ip_enrichment_cache_avoids_duplicate_requests(self):
        calls = []
        enricher = IPEnricher(
            self.database.path,
            fetcher=lambda ip: calls.append(ip) or {
                "country_name": "United States", "city": "Mountain View", "org": "Google LLC",
            },
            minimum_interval=0,
        )

        first = enricher.lookup("8.8.8.8")
        second = enricher.lookup("8.8.8.8")
        private = enricher.lookup("192.168.1.1")

        self.assertEqual(first, IPInfo("United States", "Mountain View", "Google LLC"))
        self.assertEqual(second, first)
        self.assertEqual(private, IPInfo("Unknown", "Unknown", "Unknown", "Unknown", "Unknown", ""))
        self.assertEqual(calls, ["8.8.8.8"])

    def test_twoip_enrichment_fetches_and_caches_abuse_reports(self):
        geo_calls = []
        abuse_calls = []
        enricher = IPEnricher(
            self.database.path,
            twoip_token_getter=lambda: "twoip-secret",
            twoip_geo_fetcher=lambda ip, token, language: geo_calls.append((ip, token, language)) or {
                "country": "United States",
                "city": "New York",
                "asn": {"name": "GOOGLE"},
            },
            twoip_abuse_fetcher=lambda ip, token: abuse_calls.append((ip, token)) or {
                "abuses": [
                    {"description": "Port Scan", "date": "2026-09-20 12:00:00"},
                    {"description": "DDoS Attack", "date": "2026-09-21 14:30:00"},
                ],
            },
            minimum_interval=0,
        )

        first = enricher.lookup("8.8.8.8", "2ip")
        second = enricher.lookup("8.8.8.8", "2ip")

        self.assertEqual(first.country, "United States")
        self.assertEqual(first.company, "GOOGLE")
        self.assertEqual(first.abuse_count, "2")
        self.assertEqual(first.abuse_summary, "Port Scan; DDoS Attack")
        self.assertEqual(first.abuse_last_seen, "2026-09-21 14:30:00")
        self.assertEqual(second, first)
        self.assertEqual(geo_calls, [("8.8.8.8", "twoip-secret", "en")])
        self.assertEqual(abuse_calls, [("8.8.8.8", "twoip-secret")])

    def test_twoip_without_token_skips_abuse_endpoint(self):
        abuse_calls = []
        enricher = IPEnricher(
            self.database.path,
            twoip_geo_fetcher=lambda ip, token, language: {
                "country": "Australia", "city": "Sydney", "asn": {"name": "CLOUDFLARENET"},
            },
            twoip_abuse_fetcher=lambda ip, token: abuse_calls.append((ip, token)) or {},
            minimum_interval=0,
        )

        result = enricher.lookup("1.1.1.1", "2ip")

        self.assertEqual(result.abuse_count, "Unavailable")
        self.assertEqual(result.abuse_summary, "2ip token required")
        self.assertEqual(abuse_calls, [])

    def test_provider_caches_are_independent_for_the_same_ip(self):
        ipapi_calls = []
        twoip_calls = []
        enricher = IPEnricher(
            self.database.path,
            fetcher=lambda ip: ipapi_calls.append(ip) or {
                "country_name": "United States", "city": "Chicago", "org": "Google LLC",
            },
            twoip_geo_fetcher=lambda ip, token, language: twoip_calls.append((ip, language)) or {
                "country": "United States", "city": "New York", "asn": {"name": "GOOGLE"},
            },
            minimum_interval=0,
        )

        ipapi = enricher.lookup("8.8.8.8", "ipapi")
        twoip = enricher.lookup("8.8.8.8", "2ip")
        enricher.lookup("8.8.8.8", "ipapi")
        enricher.lookup("8.8.8.8", "2ip")

        self.assertEqual(ipapi.city, "Chicago")
        self.assertEqual(twoip.city, "New York")
        self.assertEqual(ipapi_calls, ["8.8.8.8"])
        self.assertEqual(twoip_calls, [("8.8.8.8", "en")])

    def test_twoip_locale_has_an_independent_cache(self):
        calls = []

        def geo(ip, token, language):
            calls.append(language)
            country = "Ukraine" if language == "en" else "Україна"
            return {"country": country, "city": "Kyiv", "asn": {"name": "ISP"}}

        enricher = IPEnricher(
            self.database.path,
            twoip_geo_fetcher=geo,
            minimum_interval=0,
        )

        english = enricher.lookup("8.8.8.8", "2ip", "en")
        ukrainian = enricher.lookup("8.8.8.8", "2ip", "ua")
        enricher.lookup("8.8.8.8", "2ip", "en")
        enricher.lookup("8.8.8.8", "2ip", "ua")

        self.assertEqual(english.country, "Ukraine")
        self.assertEqual(ukrainian.country, "Україна")
        self.assertEqual(calls, ["en", "ua"])

    def test_country_filter_removes_entries_before_batching(self):
        countries = {
            "8.8.8.8": "United States",
            "1.1.1.1": "Australia",
            "9.9.9.9": "United States",
        }
        dispatcher = AlertDispatcher(
            self.database,
            self.repository,
            sender=lambda settings, text, mode: self.sent.append((settings, text, mode)),
            enricher=lambda ip, provider, locale: IPInfo(countries[ip], "City", "Company"),
        )
        self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=10,
            ip_lookup_field="src_ip",
            country_filter=r"^United States$",
            template="Count: {count}\n[[body]]\n{src_ip}: {ip_country}",
        )))
        for ip in countries:
            record = self.database.insert(LogInput(
                message=f"drop src={ip}", source="router", severity="error",
            ))
            dispatcher.process(record)

        dispatcher.flush_all()

        self.assertEqual(len(self.sent), 1)
        self.assertIn("Count: 2", self.sent[0][1])
        self.assertIn("8.8.8.8: United States", self.sent[0][1])
        self.assertIn("9.9.9.9: United States", self.sent[0][1])
        self.assertNotIn("1.1.1.1", self.sent[0][1])

    def test_empty_batch_after_country_filter_is_not_sent(self):
        dispatcher = AlertDispatcher(
            self.database,
            self.repository,
            sender=lambda settings, text, mode: self.sent.append((settings, text, mode)),
            enricher=lambda ip, provider, locale: IPInfo("Germany", "Berlin", "Company"),
        )
        rule = self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=10,
            ip_lookup_field="src_ip",
            country_filter=r"^Germany$",
            country_filter_mode="exclude",
        )))
        record = self.database.insert(LogInput(
            message="drop src=8.8.8.8", source="router", severity="error",
        ))

        dispatcher.process(record)
        dispatcher.flush_all()

        self.assertEqual(self.sent, [])
        self.assertEqual(self.repository.get_rule(rule.id).sent_count, 0)

    def test_batch_is_copied_to_unique_additional_chat_ids(self):
        rule = self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            additional_chat_ids=["-1001", "-1002", "-1002", "@operations"],
        )))
        record = self.database.insert(LogInput(
            message="drop src=8.8.8.8", source="router", severity="error",
        ))

        self.dispatcher.process(record)

        self.assertEqual(
            [settings.chat_id for settings, _text, _mode in self.sent],
            ["-1001", "-1002", "@operations"],
        )
        self.assertEqual(len({text for _settings, text, _mode in self.sent}), 1)
        saved = self.repository.get_rule(rule.id)
        self.assertEqual(saved.additional_chat_ids, ("-1001", "-1002", "@operations"))
        self.assertEqual(saved.sent_count, 1)

    def test_delivery_continues_when_one_additional_chat_fails(self):
        attempted = []

        def sender(settings, text, mode):
            attempted.append(settings.chat_id)
            if settings.chat_id == "-1002":
                raise RuntimeError("chat not found")

        dispatcher = AlertDispatcher(self.database, self.repository, sender=sender)
        rule = self.repository.create_rule(validate_rule(rule_payload(
            batch_window_seconds=0,
            additional_chat_ids=["-1002", "-1003"],
        )))
        record = self.database.insert(LogInput(
            message="drop src=8.8.8.8", source="router", severity="error",
        ))

        dispatcher.process(record)

        self.assertEqual(attempted, ["-1001", "-1002", "-1003"])
        saved = self.repository.get_rule(rule.id)
        self.assertEqual(saved.sent_count, 0)
        self.assertIn("-1002: chat not found", saved.last_error)

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
