import json
import unittest
from unittest.mock import patch

from jf import extra_osint, osint, public_sources


class NativePublicSearchTests(unittest.TestCase):
    def test_rss_filters_wrong_hosts_and_keeps_matching_quote_and_date(self):
        document = '''<rss><channel><item><title>Поэзия</title><link>https://habr.com/ru/articles/1/</link>
        <description>Статья об Анне Ахматовой и поэзии.</description><pubDate>2026-10-01</pubDate></item>
        <item><title>Анна Ахматова</title><link>https://unrelated.org/</link></item>
        <item><title>Unrelated</title><link>https://habr.com/ru/articles/2/</link></item></channel></rss>'''
        rows = public_sources.rss_rows(document, "habr.com", "Анна Ахматова")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["published_at"], "2026-10-01")
        self.assertIn("Ахматовой", rows[0]["snippet"])
        self.assertEqual(rows.candidates, 3)

    def test_atom_links_dates_and_empty_feed(self):
        document = '<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Ada Lovelace poem</title><link href="https://www.reddit.com/r/poetry/1"/><content>Mathematician</content><updated>2026-10-01</updated></entry></feed>'
        rows = public_sources.rss_rows(document, "reddit.com", "Ada Lovelace")
        self.assertEqual(rows[0]["published_at"], "2026-10-01")
        self.assertEqual(public_sources.rss_rows('<rss><channel/></rss>', "habr.com", "name"), [])
        with self.assertRaises(RuntimeError):
            public_sources.rss_rows('<html/>', "habr.com", "name")
        with self.assertRaises(Exception):
            public_sources.rss_rows('<!DOCTYPE x [<!ENTITY a "test">]><rss>&a;</rss>', "habr.com", "name")

    def test_feed_limit_does_not_count_matching_omissions_as_unrelated(self):
        items = ''.join(f'<item><title>Ada Lovelace</title><link>https://habr.com/articles/{i}</link></item>' for i in range(12))
        rows = public_sources.rss_rows('<rss><channel>' + items + '</channel></rss>', "habr.com", "Ada Lovelace")
        self.assertEqual((len(rows), rows.candidates, rows.filtered), (8, 12, 0))

    def test_youtube_only_reads_search_results_and_filters_ads_and_wrong_names(self):
        video = lambda title, identifier: {"videoRenderer": {"videoId": identifier, "title": {"runs": [{"text": title}]}}}
        items = [video("Ada Lovelace biography", "abcdefghijk"), video("Ada shop", "12345678901"),
                 {"adSlotRenderer": video("Ada Lovelace advert", "23456789012")}, video("Ada Lovelace invalid URL", "https://bad")]
        payload = {"contents": {"twoColumnSearchResultsRenderer": {"primaryContents": {"contents": items}}},
                   "sidebar": video("Ada Lovelace related", "34567890123")}
        rows = public_sources.youtube_rows("var ytInitialData = " + json.dumps(payload) + ";", "Ada Lovelace")
        self.assertEqual([row["url"] for row in rows], ["https://www.youtube.com/watch?v=abcdefghijk"])
        self.assertEqual(rows.candidates, 2)
        for document in ("<html/>", "var ytInitialData = invalid", "var ytInitialData = {};"):
            with self.assertRaises(RuntimeError):
                public_sources.youtube_rows(document, "name")

    def test_directory_resolves_only_valid_public_usernames_with_attribution(self):
        search = '<div class="tg-channel"><div class="tg-channel__link"><a href="/join/123">Ada Lovelace</a></div></div>'
        page = lambda body: {"html": body, "body": body.encode(), "url": "https://tgramsearch.com/search", "observed_at": "now", "sha256": "HASH"}
        with patch.object(public_sources, "fetch_public", side_effect=[page(search), page('<a href="tg://resolve?domain=poetry_public">Open</a>')]) as fetch:
            rows = public_sources.search("Ada Lovelace", "t.me")
        self.assertEqual(rows[0]["url"], "https://t.me/poetry_public")
        self.assertEqual(rows[0]["discovery_url"], "https://tgramsearch.com/join/123")
        self.assertEqual(rows[0]["category"], "Public channel candidate")
        self.assertEqual(rows[0]["html_sha256"], "HASH")
        self.assertEqual(fetch.call_args.kwargs["allowed_hosts"], {"tgramsearch.com"})
        with patch.object(public_sources, "fetch_public", side_effect=[page(search), page('<a href="tg://resolve?domain=bad/name">Open</a>')]):
            rows = public_sources.search("Ada Lovelace", "t.me")
        self.assertFalse(rows)
        self.assertTrue(rows.warning)
        with self.assertRaises(RuntimeError):
            public_sources.telegram_directory_rows('<html>Service changed</html>', "name")

    def test_native_results_do_not_need_search_engine_and_reach_ledger(self):
        rows = osint.SearchRows([{"title": "Ada Lovelace", "snippet": "Poem", "url": "https://t.me/poetry_public", "source": "TgramSearch"}], candidates=1, method="native")
        with patch.object(public_sources, "search", return_value=rows), patch.object(osint, "search") as engines:
            result = extra_osint._indexed_site("Ada Lovelace", "t.me")
        engines.assert_not_called()
        self.assertEqual(result["statuses"][0]["state"], "ok")
        self.assertEqual(result["statuses"][0]["method"], "native")

    def test_native_failure_can_recover_through_index_without_hiding_attempt(self):
        row = {"title": "Ada Lovelace", "snippet": "Poem", "url": "https://www.youtube.com/watch?v=abcdefghijk", "source": "Duckduckgo"}
        with patch.object(public_sources, "search", side_effect=RuntimeError("HTTP 403")), \
                patch.object(osint, "search", return_value=([row], [], [{"state": "ok", "count": 1}])), patch("jf.net._polite_wait"):
            result = extra_osint._indexed_site("Ada Lovelace", "youtube.com")
        self.assertEqual(len(result["web"]), 1)
        self.assertEqual(result["statuses"][0]["state"], "blocked")
        self.assertFalse(result["errors"])

    def test_blocked_index_is_skipped_for_other_sites_in_same_search(self):
        def search(query, enabled, limit):
            if enabled == ["duckduckgo"]:
                return [], ["duckduckgo: HTTP 202"], [{"state": "blocked", "error": "HTTP 202"}]
            return [], [], [{"state": "empty", "candidate_count": 10, "filtered_count": 10}]
        blocks = {}
        with patch.object(public_sources, "search", return_value=None), patch.object(osint, "search", side_effect=search) as engines, \
                patch("jf.net._polite_wait"), patch("jf.search_api.configured", return_value=False):
            first = extra_osint._indexed_site("Ada Lovelace", "vk.com", blocks)
            second = extra_osint._indexed_site("Ada Lovelace", "ok.ru", blocks)
        self.assertEqual([call.args[1] for call in engines.call_args_list], [["duckduckgo"], ["bing"], ["yahoo"], ["bing"], ["yahoo"]])
        self.assertEqual(second["statuses"][0]["state"], "skipped")
        self.assertEqual(first["statuses"][-2]["state"], "error")
        self.assertTrue(second["errors"])

    def test_telegram_count_uses_returned_posts_despite_username_case_and_deduplicates(self):
        parsed = {"profiles": [{"username": "ofakhmatova"}], "posts": [
            {"url": "https://t.me/ofAkhmatova/1", "snippet": "Анна Ахматова"},
            {"url": "https://t.me/ofAkhmatova/1", "snippet": "Анна Ахматова"}]}
        with patch("jf.evidence_capture.fetch_public", return_value={}), patch("jf.evidence_capture.parse_evidence", return_value=parsed):
            result = extra_osint._telegram_posts("Анна Ахматова", [{"url": "https://t.me/ofakhmatova"}])
        self.assertEqual(len(result["web"]), 1)
        self.assertEqual(result["statuses"][0]["count"], 1)
        self.assertEqual(result["statuses"][0]["state"], "ok")

    def test_russian_name_cases_do_not_turn_other_people_into_matches(self):
        for text in ("Анне Ахматовой", "Анну Ахматову", "Анной Ахматовой", "Анны Ахматовой"):
            self.assertTrue(osint._relevant({"title": text, "snippet": "", "url": "https://example.org/"}, "Анна Ахматова"))
        for text in ("Анна Иванова", "Антон Ахматов", "Анна shop"):
            self.assertFalse(osint._relevant({"title": text, "snippet": "", "url": "https://example.org/"}, "Анна Ахматова"))

    def test_unrelated_bing_results_are_not_confirmed_empty(self):
        from types import SimpleNamespace
        response = SimpleNamespace(body=b'<rss><channel><item><title>Unrelated shop</title><link>https://example.org/</link></item></channel></rss>')
        with patch.object(osint.net, "get", return_value=response):
            _, errors, statuses = osint.search("Ada Lovelace", ["bing"])
        self.assertTrue(errors)
        self.assertEqual(statuses[0]["state"], "error")


if __name__ == "__main__":
    unittest.main()
