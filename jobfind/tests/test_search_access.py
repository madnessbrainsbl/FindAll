"""Public sources and official API contracts, without real credentials or network."""
import base64
import io
import json
import tempfile
import unittest
import urllib.request
from argparse import Namespace
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from jf import diagnostics, dossier, extra_osint, net, osint, search_api


class SearchAccessTests(unittest.TestCase):
    def test_onion_failure_is_not_a_completed_integration(self):
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path
        from types import SimpleNamespace
        import jobfind
        for rows, expected in (([], "error"), ([{"title": "Poetry", "url": "https://example.org/poetry", "snippet": "Анна Ахматова"}], "partial")):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp, \
                    patch.object(osint, "search", return_value=([], [], [])), \
                    patch.object(jobfind.github_tools, "onion_search", return_value={"rows": rows,
                        "warnings": ["ahmia: unrelated entries"], "statuses": [{"name": "onion:ahmia", "state": "error", "count": 0}]}), \
                    patch.object(jobfind.spiderfoot_scan, "scan", return_value={"status": "empty", "event_count": 0}):
                output = io.StringIO()
                args = SimpleNamespace(query="Анна Ахматова", mode="full", sources="public", domain="", username="",
                                       onion=True, db=str(Path(temp) / "test.db"), out=temp)
                with redirect_stdout(output):
                    jobfind.cmd_osint_search(args)
                result = json.loads(output.getvalue())
                self.assertEqual(result["integrations"]["onion"]["status"], expected)
                self.assertTrue(result["integrations"]["onion"]["error"])
                self.assertTrue(any(item["source"] == "onion:ahmia" for item in result["statuses"]))
                self.assertFalse(any("source" in item and "name" in item for item in result["statuses"]))

    def setUp(self):
        direct = patch("jf.public_sources.search", return_value=None)
        direct.start()
        self.addCleanup(direct.stop)

    def test_api_credentials_are_not_copied_to_redirects(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'{}'
        captured = []
        def open_request(request, timeout):
            captured.append(request)
            return Response()
        with patch.object(urllib.request, "urlopen", side_effect=open_request), patch.object(net, "_polite_wait"):
            net.get("https://api.example.org/search", retries=0,
                    extra_headers={"Authorization": "Api-Key SECRET", "X-Subscription-Token": "SECRET"})
        request = captured[0]
        self.assertEqual(request.get_header("Authorization"), "Api-Key SECRET")
        redirected = urllib.request.HTTPRedirectHandler().redirect_request(request, None, 302, "Moved", {}, "https://other.example.org/")
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertIsNone(redirected.get_header("X-subscription-token"))

    def test_official_api_is_selected_before_scraping(self):
        with patch.object(search_api, "configured", return_value=True), \
                patch.object(search_api, "search", return_value=[]) as api, \
                patch.object(osint, "_engine_html") as html:
            osint._engine("Анна Ахматова", "yandex", 8)
        api.assert_called_once_with("Анна Ахматова", "yandex", 8)
        html.assert_not_called()

    def test_brave_api_filters_and_keeps_partial_results_without_key_leak(self):
        data = {"web": {"results": [
            {"title": "Анна Ахматова", "url": "https://example.org/poet", "description": "Biography"},
            {"title": "Anna shop", "url": "https://example.org/shop", "description": "Unrelated"}]},
            "query": {"more_results_available": True}}
        with patch.object(search_api, "settings", return_value={"BRAVE_SEARCH_API_KEY": "SECRET"}), \
                patch.object(net, "get", side_effect=[net.HttpResult(200, json.dumps(data).encode(), ""), net.HttpResult(429, b"", "")]) as get:
            rows = search_api.search("Анна Ахматова", "brave", 40)
        self.assertEqual([row["url"] for row in rows], ["https://example.org/poet"])
        self.assertEqual(rows.filtered, 1)
        self.assertIn("HTTP 429", rows[0]["_source_warning"])
        self.assertNotIn("SECRET", str(rows))
        self.assertEqual(get.call_args.kwargs["extra_headers"]["X-Subscription-Token"], "SECRET")

    def test_yandex_api_decodes_xml_and_sends_auth_only_in_header(self):
        xml = b'<yandexsearch><response><results><group><doc><url>https://example.org/ada</url><title>Ada <hl>Lovelace</hl></title><passages><passage>Mathematician</passage></passages></doc></group></results></response></yandexsearch>'
        response = net.HttpResult(200, json.dumps({"rawData": base64.b64encode(xml).decode()}).encode(), "")
        values = {"YANDEX_SEARCH_API_KEY": "SECRET", "YANDEX_SEARCH_FOLDER_ID": "folder"}
        with patch.object(search_api, "settings", return_value=values), patch.object(net, "post_json", return_value=response) as post:
            rows = search_api.search("Ada Lovelace", "yandex", 8)
        self.assertEqual(rows[0]["title"], "Ada Lovelace")
        self.assertEqual(rows[0]["source"], "Yandex")
        self.assertEqual(post.call_args.kwargs["retries"], 0)
        self.assertEqual(post.call_args.kwargs["extra_headers"], {"Authorization": "Api-Key SECRET"})
        self.assertNotIn("SECRET", json.dumps(post.call_args.args[1]))

    def test_yandex_bad_payload_and_xml_entities_are_errors(self):
        bad = ["not-base64", base64.b64encode(b'<!DOCTYPE x [<!ENTITY a "secret">]><x>&a;</x>').decode()]
        for value in bad:
            with self.subTest(value=value), patch.object(search_api, "settings", return_value={"YANDEX_SEARCH_API_KEY": "S", "YANDEX_SEARCH_FOLDER_ID": "F"}), \
                    patch.object(net, "post_json", return_value=net.HttpResult(200, json.dumps({"rawData": value}).encode(), "")):
                with self.assertRaisesRegex(RuntimeError, "invalid XML"):
                    search_api.search("name", "yandex", 8)

    def test_public_site_fallback_preserves_actual_provider_and_filters_junk(self):
        row = {"title": "Анна Ахматова", "snippet": "Poems", "url": "https://t.me/poems", "source": "Bing RSS"}
        wrong = {**row, "url": "https://unrelated.org/"}
        calls = [([], ["HTTP 202"], [{"source": "duckduckgo", "state": "blocked", "count": 0}]),
                 ([row, wrong], [], [{"source": "bing", "state": "ok", "count": 2}])]
        with patch.object(osint, "search", side_effect=calls) as search, patch.object(net, "_polite_wait"):
            result = extra_osint._indexed_site("Анна Ахматова", "t.me")
        self.assertEqual(search.call_count, 2)
        self.assertEqual(result["web"][0]["source"], "Public page · t.me via Bing RSS")
        self.assertEqual(len(result["web"]), 1)
        self.assertEqual(result["statuses"][-1]["filtered_count"], 1)
        self.assertEqual(result["statuses"][0]["state"], "blocked")
        self.assertFalse(result["errors"])

    def test_yahoo_recovers_public_site_after_other_indexes_fail(self):
        row = {"title": "Анна Ахматова", "snippet": "Poems", "url": "https://vk.com/poetry", "source": "Yahoo"}
        def collect(query, enabled, limit):
            if enabled == ["yahoo"]:
                return [row, {**row, "url": "https://unrelated.org/"}], [], [{"state": "ok", "count": 2}]
            return [], ["HTTP 429"], [{"state": "blocked", "error": "HTTP 429"}]
        with patch.object(osint, "search", side_effect=collect), patch.object(search_api, "configured", return_value=False), \
                patch.object(net, "_polite_wait"):
            data = extra_osint._indexed_site("Анна Ахматова", "vk.com")
        self.assertEqual([item["url"] for item in data["web"]], [row["url"]])
        self.assertIn("Yahoo", data["web"][0]["source"])
        self.assertEqual(data["statuses"][-1]["source"], "Public pages vk.com / yahoo")
        self.assertEqual(data["statuses"][-1]["state"], "ok")
        self.assertFalse(data["errors"])

    def test_telegram_posts_do_not_inherit_relevance_from_channel_name(self):
        from jf import evidence_capture
        html = '''<title>Анна Ахматова</title><div class="tgme_channel_info_header_title">Анна Ахматова</div>
        <div class="tgme_widget_message" data-post="poetry_public/42"><div class="tgme_widget_message_text">Анна Ахматова: музей и поэзия</div><time datetime="2026-01-02T10:00:00Z"></time></div>
        <div class="tgme_widget_message" data-post="poetry_public/43"><div class="tgme_widget_message_text">Unrelated advert</div></div>'''
        page = {"html": html, "url": "https://t.me/s/poetry_public", "observed_at": "2026-10-12T10:00:00Z", "sha256": "HASH"}
        with patch.object(evidence_capture, "fetch_public", return_value=page) as fetch:
            data = extra_osint._telegram_posts("Анна Ахматова", [{"url": "https://t.me/poetry_public/42"}, {"url": "https://t.me/s/poetry_public?before=50"}])
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([row["url"] for row in data["web"]], ["https://t.me/poetry_public/42"])
        self.assertEqual(data["web"][0]["published_at"], "2026-01-02T10:00:00Z")
        self.assertEqual(data["web"][0]["html_sha256"], "HASH")
        self.assertIn("?q=", fetch.call_args.args[0])

    def test_public_sites_can_use_configured_official_api_after_index_blocks(self):
        row = {"title": "Анна Ахматова", "snippet": "Poems", "url": "https://t.me/poems", "source": "Brave"}
        blocked = ([], ["HTTP 429"], [{"source": "index", "state": "blocked", "error": "HTTP 429", "count": 0}])
        with patch.object(search_api, "configured", side_effect=lambda name: name == "brave"), \
                patch.object(osint, "search", side_effect=[blocked, blocked, ([row], [], [{"state": "ok", "count": 1}])]) as search, \
                patch.object(net, "_polite_wait"):
            result = extra_osint._indexed_site("Анна Ахматова", "t.me")
        self.assertEqual(search.call_args.args[1], ["brave"])
        self.assertEqual(result["web"][0]["source"], "Public page · t.me via Brave")
        self.assertFalse(result["errors"])

    def test_unified_username_supplement_does_not_repeat_public_collection(self):
        with ExitStack() as stack:
            for name in ("whatsmyname", "github_user", "sherlock", "social_analyzer", "blackbird"):
                stack.enter_context(patch.object(extra_osint, name, return_value={"profiles": [], "errors": []}))
            public = stack.enter_context(patch.object(extra_osint, "public_pages"))
            extra_osint.supplement("poetry_public", "username", include_public=False)
        public.assert_not_called()

    def test_telegram_unreadable_preview_is_error_not_empty(self):
        from jf import evidence_capture
        page = {"html": "<html><title>Unavailable</title></html>", "url": "https://t.me/s/poetry_public", "observed_at": "now", "sha256": "HASH"}
        with patch.object(evidence_capture, "fetch_public", return_value=page):
            data = extra_osint._telegram_posts("Анна Ахматова", [{"url": "https://t.me/poetry_public"}])
        self.assertEqual(data["statuses"][0]["state"], "error")
        self.assertTrue(data["errors"])

    def test_composite_blocked_ledger_survives_empty_result(self):
        payload = {"web": [], "errors": ["CAPTCHA"], "statuses": [{"source": "Public pages t.me", "state": "blocked", "count": 0}]}
        with patch.object(extra_osint, "public_pages", return_value=payload):
            rows, errors, checks = osint.search("Анна Ахматова", ["public"])
        self.assertFalse(rows)
        self.assertTrue(errors)
        self.assertEqual(checks[-1]["source"], "Public pages t.me")
        self.assertEqual(checks[-1]["state"], "blocked")

    def test_public_worker_diagnostics_keep_context(self):
        def discover(query, site):
            diagnostics.record_network({"host": "example.org", "method": "GET", "state": "ok"})
            return []
        with patch.object(extra_osint, "_telegram_posts", return_value={"web": [], "statuses": [], "errors": []}), diagnostics.trace_run() as trace:
            extra_osint.public_pages("Ada Lovelace", searcher=discover)
        self.assertEqual(trace.summary()["network_requests"], len(extra_osint.PUBLIC_SITES))

    def test_public_rows_reach_native_cli_json_csv_and_dossier_evidence(self):
        import jobfind
        row = {"title": "Poetry", "snippet": "Анна Ахматова: музей", "url": "https://t.me/poetry_public/42",
               "source": "Telegram public web", "category": "Public post", "published_at": "2026-01-02T10:00:00Z"}
        payload = {"web": [row], "errors": [], "statuses": [{"source": "Telegram public web", "state": "ok", "count": 1}]}
        with tempfile.TemporaryDirectory() as folder, patch.object(extra_osint, "public_pages", return_value=payload), \
                patch.object(jobfind, "_spiderfoot_entry", return_value={"data": {"event_count": 0, "rows": []}, "error": "", "status": "ok"}):
            args = Namespace(query="Анна Ахматова", sources="public", mode="full", domain="", username="", onion=False,
                             out=folder, db=str(Path(folder) / "test.db"))
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(jobfind.cmd_osint_search(args), 0)
            result = json.loads(stream.getvalue())
            self.assertEqual(result["results"][0]["url"], row["url"])
            graph = Path(result["graph_path"]).read_text(encoding="utf-8")
            self.assertIn(row["url"], graph)
            self.assertIn(row["published_at"], graph)
            self.assertEqual(result["csv"], "")
            self.assertFalse(list(Path(folder).glob("osint_*.json")))
            self.assertFalse(list(Path(folder).glob("osint_*.csv")))
            self.assertEqual(result["results"][0]["published_at"], row["published_at"])
        result = {"query": "Анна Ахматова", "observed_at": "now", "sections": {"web": [], "profiles": [], "emails": []}, "errors": []}
        dossier.merge_delta(result, payload)
        self.assertEqual(result["sections"]["web"][0]["published_at"], row["published_at"])
        self.assertEqual(result["source_checks"][0]["source"], "Telegram public web")


if __name__ == "__main__":
    unittest.main()
