"""Regression checks for source provenance and false empty responses."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from jf import osint


class SearchReliabilityTests(unittest.TestCase):
    def test_selected_page_encodes_unicode_request_and_redirect(self):
        from unittest.mock import Mock
        from jf import osint_contacts
        url = "https://public.org/Анна%20?name=Ахматова"
        expected = "https://public.org/%D0%90%D0%BD%D0%BD%D0%B0%20?name=%D0%90%D1%85%D0%BC%D0%B0%D1%82%D0%BE%D0%B2%D0%B0"
        response = Mock()
        response.headers.get_content_type.return_value = "text/html"
        response.headers.get_content_charset.return_value = "utf-8"
        response.read.return_value = "<title>Анна Ахматова</title>".encode()
        response.geturl.return_value = expected
        opener = Mock()
        def open_page(request, **kwargs):
            request.full_url.encode("ascii")
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            return context
        opener.open.side_effect = open_page
        with patch.object(osint_contacts.urllib.request, "build_opener", return_value=opener):
            final, page = osint_contacts._get(url, "public.org")
        self.assertEqual(final, expected)
        self.assertIn("Анна Ахматова", page)
        handler = osint_contacts._SameHostRedirect("public.org")
        request = osint_contacts.urllib.request.Request("https://public.org/")
        with patch.object(osint_contacts, "_public_host", return_value=True):
            redirect = handler.redirect_request(request, None, 302, "Found", {}, url)
        self.assertEqual(redirect.full_url, expected)

    def test_company_site_candidate_does_not_require_search_hint_in_page(self):
        import jobfind
        response = SimpleNamespace(body=b'''<rss><channel><item>
            <title>Web3tech</title><link>https://web3tech.org/</link><description>Software company</description>
            </item></channel></rss>''')
        with patch.object(osint.net, "get", return_value=response), patch.object(osint, "_engine", side_effect=lambda q, b, n: osint._web(q, n)):
            candidates, errors = jobfind._company_site_candidates("web3tech")
        self.assertEqual([row["domain"] for row in candidates], ["web3tech.org"])
        self.assertFalse(errors)

    def test_bing_multiword_query_excludes_results_for_first_name_only(self):
        response = SimpleNamespace(body=b'''<rss><channel>
            <item><title>Grace Fashion</title><link>https://example.org/shop</link><description>Grace clothing</description></item>
            <item><title>Grace Hopper</title><link>https://example.org/biography</link><description>Computer pioneer</description></item>
            </channel></rss>''')
        with patch.object(osint.net, "get", return_value=response):
            rows, errors, statuses = osint.search("Grace Hopper", ["bing"])
        self.assertEqual([row["title"] for row in rows], ["Grace Hopper"])
        self.assertEqual(statuses[0]["candidate_count"], 2)
        self.assertEqual(statuses[0]["filtered_count"], 1)
        self.assertFalse(errors)

    def test_plain_multiword_query_matches_all_words_in_public_evidence(self):
        row = {"title": "Анна", "snippet": "Поэт", "url": "https://example.org/"}
        self.assertFalse(osint._relevant(row, "Анна Ахматова"))
        row["snippet"] = "Ахматова: биография"
        self.assertTrue(osint._relevant(row, "  АННА  Ахматова  "))
        self.assertTrue(osint._relevant({"title": "Петр", "snippet": "Чайковский", "url": "https://example.org/"}, "Пётр Чайковский"))
        self.assertTrue(osint._relevant({"title": "Biography", "snippet": "", "url": "https://example.org/Grace_Hopper"}, "Grace Hopper"))

    def test_search_operator_query_keeps_existing_matching_policy(self):
        row = {"title": "Python guide", "snippet": "", "url": "https://example.org/"}
        for query in ("site:example.org Python", "Python OR Rust", "Python AND Rust", "Python NOT Rust"):
            with self.subTest(query=query):
                self.assertTrue(osint._relevant(row, query))

    def test_no_results_library_error_is_not_confirmed_empty(self):
        with patch.object(osint, "_engine", side_effect=RuntimeError("No results found.")):
            rows, errors, statuses = osint.search("example.org", ["brave"])
        self.assertFalse(rows)
        self.assertTrue(errors)
        self.assertTrue(statuses[0]["error"])

    def test_wikipedia_filters_unrelated_handle(self):
        with patch.object(osint, "_json", return_value={"query": {"search": [
            {"title": "Physics", "pageid": 1, "snippet": "Completely unrelated article"},
            {"title": "example.org", "pageid": 2, "snippet": "Documentation example.org"},
        ]}}):
            rows = osint._wikipedia("example.org", 80)
        self.assertEqual([row["title"] for row in rows], ["example.org"])

    def test_bing_never_requests_disabled_ddgs_auto(self):
        with patch("ddgs.DDGS") as ddgs, patch.object(osint, "_web", return_value=[]) as rss:
            osint._engine("example.org", "bing", 3)
        ddgs.assert_not_called()
        rss.assert_called_once_with("example.org", 3)

    def test_captcha_is_blocked_not_empty(self):
        document = {"url": "https://www.mojeek.com/search?q=example.org", "http_status": 200,
                    "html": "<title>Captcha</title><p>JavaScript is required to complete this challenge.</p>"}
        with patch("jf.evidence_capture.fetch_public", return_value=document):
            with self.assertRaisesRegex(RuntimeError, "CAPTCHA"):
                osint._engine_html("example.org", "mojeek")

    def test_exact_html_result_provenance_and_filtering(self):
        document = '<ul class="results"><li><h2><a href="https://example.org/a">example.org reference</a></h2></li><li><h2><a href="https://unrelated.org/">Unrelated</a></h2></li></ul>'
        rows = osint._engine_html_rows(document, "mojeek", "example.org", 3)
        self.assertEqual([row["source"] for row in rows], ["Mojeek"])
        self.assertEqual(rows.filtered, 1)
        self.assertEqual(rows.candidates, 2)

    def test_confirmed_empty_page_is_not_error(self):
        document = {"url": "https://www.mojeek.com/search?q=example.org", "http_status": 200,
                    "html": "<title>Search</title><p>No results found</p>"}
        with patch("jf.evidence_capture.fetch_public", return_value=document):
            self.assertEqual(osint._engine_html("example.org", "mojeek"), [])

    def test_unrecognized_page_is_error(self):
        document = {"url": "https://www.mojeek.com/search?q=example.org", "http_status": 200,
                    "html": "<title>Service unavailable</title><p>Try later</p>"}
        with patch("jf.evidence_capture.fetch_public", return_value=document):
            with self.assertRaisesRegex(RuntimeError, "not confirmed empty"):
                osint._engine_html("example.org", "mojeek")

    def test_wikipedia_caps_output_and_matches_person_words(self):
        values = [{"title": f"Ada Lovelace reference {n}", "pageid": n, "snippet": "Mathematician"} for n in range(30)]
        with patch.object(osint, "_json", return_value={"query": {"search": values}}):
            rows = osint._wikipedia("Ada Lovelace", 80)
        self.assertLessEqual(len(rows), 20)
        self.assertTrue(osint._relevant({"title": "", "snippet": "", "url": "https://www.example.org/"}, "example.org"))
        self.assertFalse(osint._relevant({"title": "example.org.in unrelated", "snippet": "", "url": "https://unrelated.org/"}, "example.org"))


if __name__ == "__main__":
    unittest.main()
