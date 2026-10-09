import unittest

from logserver.message_template import ConditionalTemplateError, compile_conditional_template


class ConditionalTemplateTests(unittest.TestCase):
    def test_available_and_else(self):
        template = compile_conditional_template(
            "[[if ip_abuse_count]]Abuses: {ip_abuse_count}[[else]]No abuse data[[/if]]"
        )
        self.assertEqual(
            template.render({"ip_abuse_count": "2"}),
            "Abuses: {ip_abuse_count}",
        )
        self.assertEqual(template.render({"ip_abuse_count": "Unavailable"}), "No abuse data")
        self.assertEqual(template.render({"ip_abuse_count": "Unknown"}), "No abuse data")
        self.assertEqual(template.render({"ip_abuse_count": "0"}), "Abuses: {ip_abuse_count}")

    def test_comparisons_regex_and_nesting(self):
        template = compile_conditional_template(
            "[[if severity == error]]"
            "[[if ip_abuse_count > 0]]reported[[else]]clean[[/if]]"
            "[[else]]ignored[[/if]]/"
            "[[if ip_country matches ^(Ukraine|Poland)[a-z]*$]]regional[[/if]]"
        )
        self.assertEqual(
            template.render({
                "severity": "error", "ip_abuse_count": "3", "ip_country": "Ukraine",
            }),
            "reported/regional",
        )
        self.assertEqual(
            template.render({
                "severity": "error", "ip_abuse_count": "0", "ip_country": "Germany",
            }),
            "clean/",
        )
        self.assertEqual(
            template.render({"severity": "info", "ip_abuse_count": "3"}),
            "ignored/",
        )

    def test_missing_condition(self):
        template = compile_conditional_template("[[if not ip_city]]No city[[/if]]")
        self.assertEqual(template.render({"ip_city": ""}), "No city")
        self.assertEqual(template.render({"ip_city": "Kyiv"}), "")

    def test_rejects_invalid_structure_and_expression(self):
        invalid = (
            "[[else]]",
            "[[/if]]",
            "[[if severity]]missing end",
            "[[if severity]][[else]]one[[else]]two[[/if]]",
            "[[if severity matches (]]x[[/if]]",
            "[[if severity > high]]x[[/if]]",
            "[[if severity]x[[/if]]",
        )
        for template in invalid:
            with self.subTest(template=template), self.assertRaises(ConditionalTemplateError):
                compile_conditional_template(template)


if __name__ == "__main__":
    unittest.main()
