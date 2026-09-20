import unittest

from logserver.search import SearchSyntaxError, compile_search


class SearchTests(unittest.TestCase):
    def test_empty_query_matches_everything(self):
        result = compile_search("")
        self.assertEqual(result.clause, "1")
        self.assertEqual(result.params, ())

    def test_boolean_grouping_and_implicit_and(self):
        result = compile_search("(severity:error OR severity:critical) source:edge")
        self.assertIn("OR", result.clause)
        self.assertIn("AND", result.clause)
        self.assertEqual(result.params, ("%error%", "%critical%", "%edge%"))

    def test_negation_and_quoted_value(self):
        result = compile_search('NOT message:"login failed"')
        self.assertTrue(result.clause.startswith("NOT"))
        self.assertEqual(result.params, ("%login failed%",))

    def test_like_metacharacters_are_literal(self):
        result = compile_search("message:100%_done")
        self.assertEqual(result.params, (r"%100\%\_done%",))

    def test_numeric_id(self):
        result = compile_search("id>=42")
        self.assertEqual(result.clause, "id >= ?")
        self.assertEqual(result.params, (42,))

    def test_rejects_invalid_queries(self):
        invalid = ["unknown:value", "severity:", "(error", "id:abc", "error OR"]
        for query in invalid:
            with self.subTest(query=query), self.assertRaises(SearchSyntaxError):
                compile_search(query)


if __name__ == "__main__":
    unittest.main()

