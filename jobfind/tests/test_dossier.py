"""Offline contract check for the consolidated dossier export."""

import csv
import io
import json
import os
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jf import dossier
from jobfind import cmd_dossier_analyze

RUN_TOOL = dossier.run_tool


class DossierTest(unittest.TestCase):
    def setUp(self):
        self.tools = patch.object(dossier, "run_tool", return_value={"errors": [], "statuses": []})
        self.tools.start()
        self.spiderfoot = patch.object(dossier.spiderfoot_scan, "scan", return_value={"status": "skipped"})
        self.spiderfoot.start()
        self.public = patch.object(dossier.extra_osint, "supplement", return_value={
            "profiles": [], "web": [], "findings": [], "hostnames": [], "errors": []})
        self.public.start()

    def tearDown(self):
        self.tools.stop()
        self.public.stop()
        self.spiderfoot.stop()

    def test_person_candidate_and_single_export(self):
        with tempfile.TemporaryDirectory() as root:
            events = []
            row = {"title": "Alex Smith", "url": "https://example.org/alex",
                   "snippet": "Public page", "source": "Web", "category": "Web"}
            with patch.object(dossier.osint, "search", return_value=([row], [], [])):
                result = dossier.collect("Alex Smith", "person", "full", Path(root), events.append)
            self.assertEqual([events[0]["percent"], events[-1]["percent"]], [0, 100])
            self.assertEqual(result["sections"]["web"][0]["status"], "candidate; identity unverified")
            self.assertEqual(json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))["kind"], "person")
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                self.assertEqual(list(csv.DictReader(stream))[0]["url"], row["url"])
            self.assertEqual(sorted(p.name for p in Path(root).rglob("*.*") if p.is_file()), ["diagnostics.jsonl", "dossier.csv", "dossier.json", "dossier.md", "graph.sqlite3", "relationship_graph.html"])

    def test_reanalyzing_saved_dossier_replaces_answer_and_csv_claims(self):
        with tempfile.TemporaryDirectory() as root:
            row = {"title": "Example", "url": "https://example.org/about",
                   "snippet": "Published profile", "source": "Web"}
            with patch.object(dossier.osint, "search", return_value=([row], [], [])):
                result = dossier.collect("Alex Smith", "person", "full", Path(root) / "dossiers")
            analysis = {"status": "ok", "answer": "Найден публичный профиль.",
                        "answer_language": "ru", "claims": [{"category": "profile",
                        "statement": "Профиль опубликован.", "quote": "Published profile",
                        "source_url": row["url"]}]}
            dossier.save_ai_analysis(result, analysis)
            dossier.save_ai_analysis(result, analysis)
            saved = json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(saved["ai_analysis"]["answer_language"], "ru")
            self.assertEqual(saved["counts"]["table_rows"], len(rows))
            self.assertEqual(sum(row["source"] == "AI analysis" for row in rows), 1)

            out = io.StringIO()
            with patch("jf.ai_agents.analyze_dossier", return_value=analysis), redirect_stdout(out):
                code = cmd_dossier_analyze(Namespace(path=result["report_json"], out=root,
                    ai_provider="groq", ai_model="example"))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["ai_analysis"]["answer"], analysis["answer"])

    def test_progress_counts_completed_sources(self):
        def search(_query, sources, on_source=None, limit=10):
            for source in sources:
                on_source(source, 0, "blocked" if source == "google" else "")
            return [], ["google: blocked"], []

        with tempfile.TemporaryDirectory() as root:
            events = []
            with patch.object(dossier.osint, "search", side_effect=search):
                result = dossier.collect("Alex Smith", "person", "full", Path(root), events.append)
        source_events = [event for event in events if event.get("stage") == "web" and event.get("source")]
        self.assertEqual(len(source_events), 11)
        self.assertEqual([event["completed"] for event in source_events], list(range(1, 12)))
        self.assertIn("yahoo", [event["source"] for event in source_events])
        self.assertEqual(source_events[0]["state"], "error")
        self.assertEqual(events[-1]["percent"], 100)
        self.assertEqual(result["errors"], ["google: blocked"])

    def test_single_cyrillic_word_is_a_name_and_skips_profile_checks(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(dossier.osint, "search", return_value=([], [], [])):
                result = dossier.collect("говно", "auto", "full", Path(root))
        self.assertEqual(result["kind"], "person")
        self.assertTrue(any("Latin username" in error for error in result["errors"]))

    def test_google_unparseable_results_are_visible_as_source_issue(self):
        with patch.object(dossier.osint, "_engine", side_effect=RuntimeError("No results found.")):
            found, errors, statuses = dossier.osint.search("unknown", ["google"])
        self.assertEqual(found, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("unconfirmed empty response", errors[0])
        self.assertEqual(statuses[0]["state"], "error")
        self.assertEqual(statuses[0]["source"], "google")
        self.assertEqual(statuses[0]["count"], 0)

    def test_domain_asset_provenance_and_partial_error(self):
        data = {"domain": "example.org", "dns": {"domain": "example.org", "mx": []},
                "subdomains": [], "assets": [{"ip": "93.184.215.14", "port": "443",
                "product": "Web", "url": "https://internetdb.shodan.io/93.184.215.14",
                "provider": "Shodan InternetDB"}], "technologies": [], "web_results": [],
                "statuses": [{"name": "crt.sh", "state": "error", "detail": "HTTP 503"}],
                "report": "disposable.json", "csv": "disposable.csv"}
        with tempfile.TemporaryDirectory() as root:
            with patch.object(dossier.domain_recon, "investigate", return_value=data):
                result = dossier.collect("https://example.org/about", "auto", "domain", Path(root))
            self.assertEqual(result["kind"], "domain")
            self.assertNotIn("report", result["sections"]["domain"])
            self.assertIn("crt.sh: HTTP 503", result["errors"])
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertTrue(any(row["kind"] == "resolved_ip_service" and row["url"] == data["assets"][0]["url"]
                                for row in rows))
            self.assertTrue(any(row["error"] == "crt.sh: HTTP 503" for row in rows))

    def test_surname_auto_is_person_with_unverified_profile_candidates(self):
        self.assertEqual(dossier.identify("Smith", "auto"), ("Smith", "person"))
        self.assertEqual(dossier.identify("@smith", "auto"), ("smith", "username"))
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier.osint, "search", return_value=([], [], [])),
                  patch.object(dossier.github_tools, "maigret_search", return_value={
                      "rows": [{"site": "Example", "url": "https://example.org/smith"}],
                      "warnings": []})):
                result = dossier.collect("Smith", "auto", "full", Path(root))
            self.assertEqual(result["kind"], "person")
            self.assertIn("identity unverified", result["sections"]["profiles"][0]["status"])
            self.assertEqual(result["sections"]["emails"], [])

    def test_cyrillic_surname_keeps_readable_export_directory(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(dossier.osint, "search", return_value=([], [], [])):
                result = dossier.collect("Иванов", "auto", "email", Path(root))
            self.assertEqual(Path(result["report_json"]).parent.parent.name, "Иванов")

    def test_username_full_combines_profiles_commit_email_and_tiktok(self):
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier.osint, "search", return_value=([], [], [])),
                  patch.object(dossier.github_tools, "maigret_search", return_value={
                      "rows": [{"site": "GitHub", "url": "https://github.com/madnessbrains"}],
                      "warnings": []}),
                  patch.object(dossier.github_tools, "github_email", return_value={
                      "email": "public@example.org", "source_url": "https://github.com/x/y/commit/abc",
                      "errors": []}),
                  patch.object(dossier.github_tools, "tiktok_profile", return_value={
                      "url": "https://www.tiktok.com/@madnessbrains", "source": "TikTok oEmbed"})):
                result = dossier.collect("@madnessbrains", "auto", "full", Path(root))
        self.assertEqual(result["kind"], "username")
        self.assertEqual(len(result["sections"]["profiles"]), 2)
        self.assertEqual(result["sections"]["emails"][0]["email"], "public@example.org")

    def test_domain_full_adds_archive_notices_and_opt_in_onion(self):
        domain_data = {"domain": "example.org", "dns": {}, "subdomains": [], "assets": [],
                       "technologies": [], "web_results": [], "statuses": []}
        archive = {"title": "Archive", "url": "https://web.archive.org/example.org",
                   "snippet": "snapshot", "source": "Internet Archive"}
        notice = {"title": "Breach notice", "url": "https://haveibeenpwned.com/example",
                  "snippet": "public notice", "source": "Have I Been Pwned"}
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier.osint, "search", return_value=([], [], [])),
                  patch.object(dossier.domain_recon, "investigate", return_value=domain_data),
                  patch.object(dossier.osint, "archived_homepage", return_value=archive),
                  patch.object(dossier.osint, "breach_catalogue", return_value=[notice]),
                  patch.object(dossier.osint_contacts, "find_public_emails", return_value=[]),
                  patch.object(dossier.github_tools, "onion_search", return_value={
                      "rows": [{"title": "Index result", "url": "http://sample.onion/", "engine": "ahmia",
                                "snippet": "Published source excerpt", "index_sha256": "INDEX_HASH"}],
                      "warnings": []})):
                result = dossier.collect("example.org", "auto", "full", Path(root), include_onion=True)
        self.assertEqual({row["source"] for row in result["sections"]["web"]},
                         {"Internet Archive", "Have I Been Pwned", "OnionSearch"})
        self.assertEqual(result["errors"], [])
        onion = next(row for row in result["sections"]["web"] if row["source"] == "OnionSearch")
        self.assertEqual((onion["snippet"], onion["index_sha256"]), ("Published source excerpt", "INDEX_HASH"))

    def test_public_checks_join_the_same_dossier(self):
        profile = {"profiles": [{"site": "Example", "url": "https://example.org/u/ada",
                                 "username": "ada", "source": "WhatsMyName",
                                 "status": "candidate; same handle only, identity unverified"}],
                   "web": [], "findings": [], "hostnames": [], "errors": []}
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier.github_tools, "maigret_search", return_value={"rows": [], "warnings": []}),
                  patch.object(dossier.github_tools, "tiktok_profile", return_value={}),
                  patch.object(dossier.extra_osint, "supplement", return_value=profile)):
                result = dossier.collect("@ada", "auto", "profiles", Path(root))
        self.assertEqual(result["sections"]["profiles"][0]["source"], "WhatsMyName")
        self.assertIn("identity unverified", result["sections"]["profiles"][0]["status"])

        extra = {"profiles": [], "web": [{"title": "Scan", "url": "https://example.org/path",
                 "snippet": "Existing public urlscan.io result", "source": "urlscan.io",
                 "category": "Public scan"}], "findings": [{"event_type": "PHONE_NUMBER",
                 "value": "United States; fixed line; carrier not published", "module": "numbering plan"}],
                 "hostnames": ["www.example.org"], "errors": []}
        domain_data = {"domain": "example.org", "dns": {}, "subdomains": [], "assets": [],
                       "technologies": [], "web_results": [], "statuses": []}
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier.domain_recon, "investigate", return_value=domain_data),
                  patch.object(dossier.extra_osint, "supplement", return_value=extra)):
                result = dossier.collect("example.org", "domain", "domain", Path(root))
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
        self.assertEqual(result["sections"]["domain"]["subdomains"],
                         [{"name": "www.example.org", "ips": [], "sources": ["Subfinder"]}])
        self.assertEqual(result["sections"]["web"][0]["source"], "urlscan.io")
        self.assertEqual(result["sections"]["findings"][0]["source"], "numbering plan")
        self.assertTrue(any(row["source"] == "Subfinder" and "Passive hostname" in row["details"] for row in rows))
        self.assertTrue(any(row["source"] == "numbering plan" for row in rows))

    def test_web_check_log_outlives_disposable_dossier_folder(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            vendor = base / "vendor"
            (vendor / "node_modules" / "express").mkdir(parents=True)
            paths = []

            def start(*_args, **kwargs):
                paths.append(Path(kwargs["stdout"].name))
                return SimpleNamespace(poll=lambda: None)

            with (patch.object(dossier.github_tools, "WEB_CHECK", vendor),
                  patch.object(dossier.github_tools, "_health",
                               side_effect=[None, {"ready": True}]),
                  patch.object(dossier.github_tools.shutil, "which", return_value="node"),
                  patch.object(dossier.github_tools.subprocess, "Popen", side_effect=start),
                  patch.object(dossier.domain_recon, "configured_keys",
                               return_value={"SHODAN_API_KEY": ""}),
                  patch.dict(os.environ, {"LOCALAPPDATA": str(base / "stable-runtime")})):
                with tempfile.TemporaryDirectory(dir=base) as scratch:
                    dossier.github_tools._start_web_check(Path(scratch))
                    self.assertEqual(len(paths), 1)
                    self.assertFalse(paths[0].is_relative_to(Path(scratch)))
                    retained = paths[0].open("ab")
                retained.close()
            self.assertTrue(paths[0].is_file())

    def test_optional_tools_join_dossier_and_preserve_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            def tool(result, name, _params, progress=None):
                if name == "webcheck":
                    artifact = Path(result["report_json"]).parent / "artifacts" / "webcheck.json"
                    artifact.write_text('{"headers":{"server":"example"}}', encoding="utf-8")
                    return {"webcheck_modules": [{"name": "headers", "status": "ok", "data": {"server": "example"},
                        "url": "https://example.org/"}], "artifacts": [{"path": str(artifact), "source": "Web-Check"}],
                        "statuses": [{"name": "Web-Check/headers", "state": "ok", "count": 1}]}
                if name == "businesses":
                    return {"businesses": [{"name": "Example Business", "address": "Example City",
                        "url": "https://2gis.com/firm/100"}], "statuses": [{"name": "2GIS", "state": "ok", "count": 1}]}
                return {"statuses": [{"name": name, "state": "skipped", "detail": "test fixture"}]}
            with (patch.object(dossier.domain_recon, "investigate", return_value={"domain": "example.org", "statuses": []}),
                  patch.object(dossier, "run_tool", side_effect=tool)):
                result = dossier.collect("example.org", "domain", "domain", Path(root),
                    city="example", coverage="deep", include_spiderfoot=False)
            saved = json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["sections"]["webcheck_modules"][0]["data"]["server"], "example")
            self.assertEqual(len(saved["sections"]["businesses"]), 1)
            self.assertTrue(Path(saved["artifacts"][0]["path"]).is_file())
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                sections = {row["section"] for row in csv.DictReader(stream)}
            self.assertTrue({"webcheck", "businesses", "source_checks"} <= sections)

    def test_ai_merge_retains_domain_assets_and_separates_source_states(self):
        result = {"query": "example.org", "observed_at": "2026-01-01", "errors": [],
                  "sections": {"domain": {"domain": "example.org", "assets": [{"ip": "192.0.2.1"}], "dns": {"mx": []}}}}
        dossier.merge_delta(result, {"domain": {"domain": "example.org", "assets": [{"ip": "192.0.2.2"}], "dns": {"txt": []}},
            "statuses": [{"source": "API", "status": "skipped", "detail": "missing key"}]})
        self.assertEqual(len(result["sections"]["domain"]["assets"]), 2)
        self.assertEqual(result["sections"]["domain"]["dns"], {"mx": [], "txt": []})
        self.assertEqual(result["source_checks"][0]["state"], "skipped")

    def test_page_capture_merges_parsed_email_and_keeps_artifacts(self):
        from jf import evidence_capture
        body = b'<html><title>Example fixture</title><p>Contact fixture@findall-fixture.org</p></html>'
        page = {"url": "https://example.org/about", "body": body, "html": body.decode(),
                "sha256": "a" * 64, "content_type": "text/html", "observed_at": "2026-01-01"}
        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier, "run_tool", wraps=RUN_TOOL),
                  patch.object(dossier.osint, "search", return_value=([{"title": "Example", "url": page["url"],
                      "source": "Synthetic search", "snippet": "Example"}], [], [])),
                  patch.object(evidence_capture, "validated_url", return_value=(page["url"], "example.org", [])),
                  patch.object(evidence_capture, "fetch_public", return_value=page),
                  patch.dict(os.environ, {"FINDALL_SINGLEFILE": "0"})):
                result = dossier.collect("Example Fixture", "person", "full", Path(root),
                    include_spiderfoot=False, include_extra_tools=False, capture_pages=1)
            self.assertEqual(len(result["sections"]["web"]), 1)
            self.assertEqual(result["sections"]["web"][0]["source"], "Synthetic search")
            self.assertEqual(result["sections"]["emails"][0]["email"], "fixture@findall-fixture.org")
            self.assertTrue(any(row["state"] == "ok" and row["source"].startswith("capture:")
                                for row in result["source_checks"]))
            self.assertTrue(all(Path(entry["path"] if isinstance(entry, dict) else entry).is_file()
                                for entry in result["artifacts"]))


if __name__ == "__main__":
    unittest.main()
