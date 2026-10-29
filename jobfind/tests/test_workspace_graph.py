"""The common diagram retains independent searches and verified page evidence."""
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jobfind
from jf import db, dossier, evidence_graph


class WorkspaceGraphTests(unittest.TestCase):
    def test_discovery_and_index_provenance_survive_common_graph(self):
        graph = evidence_graph.build_graph({"query": "Ada Lovelace", "sections": {"web": [
            {"url": "https://t.me/public_poetry", "title": "Ada Lovelace", "snippet": "Published text",
             "discovery_url": "https://tgramsearch.com/join/123", "html_sha256": "a" * 64},
            {"url": "https://example.org/poetry", "title": "Poetry", "index_url": "https://ahmia.fi/search/",
             "index_sha256": "b" * 64}]}})
        matches = [row for row in graph["edges"] if row["kind"] == "SearchMatch"]
        self.assertTrue(any("https://tgramsearch.com/join/123" in row["source_urls"] and "a" * 64 in row["evidence_hashes"] for row in matches))
        self.assertTrue(any("https://ahmia.fi/search/" in row["source_urls"] and "b" * 64 in row["evidence_hashes"] for row in matches))

    def test_standalone_spiderfoot_uses_common_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            args = SimpleNamespace(target="example.org", kind="domain", use_case="passive", modules="", timeout=1,
                                   out=folder, db=str(Path(folder) / "test.db"))
            result = {"status": "ok", "error": "", "target": args.target, "target_type": "INTERNET_NAME",
                      "use_case": "passive", "modules": 1, "scan_id": "test", "database": "", "timed_out": False,
                      "event_count": 1, "rows": [], "emails": [], "errors": [], "events": [
                          {"type": "LINKED_URL_EXTERNAL", "data": "https://example.org/about", "module": "sfp_fixture"}]}
            with patch.object(jobfind.spiderfoot_scan, "scan", return_value=result), redirect_stdout(io.StringIO()):
                self.assertEqual(jobfind.cmd_spiderfoot(args), 0)
            self.assertIn("https://example.org/about", (Path(folder) / "relationship_graph.html").read_text(encoding="utf-8"))

    def test_repeat_merge_keeps_other_queries_and_evidence_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            report = {"query": "First", "observed_at": "2026-01-01", "sections": {"web": [
                {"url": "https://example.org/page", "title": "First", "snippet": "Published text",
                 "html_sha256": "a" * 64, "source": "Fixture"}]}}
            first = evidence_graph.accumulate(report, out)
            report["query"] = "Second"
            evidence_graph.accumulate(report, out)
            report["sections"]["web"][0]["html_sha256"] = "b" * 64
            evidence_graph.accumulate(report, out)
            second = evidence_graph.accumulate(report, out)
            self.assertEqual(first["graph_path"], second["graph_path"])
            with closing(sqlite3.connect(out / ".research" / "graph.sqlite3")) as conn:
                rows = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM graph_items")]
            self.assertTrue({"First", "Second", "FindAll workspace"}.issubset({r.get("label") for r in rows}))
            match = next(r for r in rows if r.get("kind") == "SearchMatch" and len(r["evidence_hashes"]) == 2)
            self.assertEqual(match["certainty"], "candidate")
            self.assertEqual(match["source_urls"], ["https://example.org/page"])
            self.assertEqual(list(out.glob("*.html")), [Path(first["graph_path"])])
            self.assertFalse(list(out.glob("*.json")))
            self.assertFalse(list(out.glob("*.csv")))

    def test_page_parse_deduplicates_snapshots_and_adds_published_email(self):
        with tempfile.TemporaryDirectory() as folder:
            args = SimpleNamespace(query="Example", url="https://example.org/contact", out=folder,
                                   db=str(Path(folder) / "test.db"))
            page = {"title": "Contact", "url": args.url, "excerpt": "Contact us", "emails": ["hello@example.org"],
                    "html_sha256": "c" * 64, "observed_at": "2026-01-01", "_snapshot_html": "<p>Contact us</p>"}
            with patch.object(jobfind.osint_contacts, "parse_public_page", side_effect=lambda *a, **k: dict(page)):
                with redirect_stdout(io.StringIO()):
                    jobfind.cmd_osint_page(args)
                    jobfind.cmd_osint_page(args)
            self.assertEqual(len(list(Path(folder).rglob("*.html.txt"))), 1)
            with closing(sqlite3.connect(Path(folder) / ".research" / "graph.sqlite3")) as conn:
                edges = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM graph_items WHERE kind='edge'")]
            published = next(r for r in edges if r["kind"] == "PublishedEmail")
            self.assertEqual(published["evidence_hashes"], ["c" * 64])
            self.assertFalse(list(Path(folder).glob("osint_page_*")))

    def test_saved_search_and_dossier_share_graph_and_explicit_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            conn = db.connect(out / "test.db")
            db.save_osint_results(conn, "Old", [{"url": "https://example.org/old", "title": "Old page",
                                 "snippet": "Public page", "source": "Fixture", "category": "Web"}])
            conn.close()
            path = out / "dossiers" / "new" / "run" / "dossier.json"
            path.parent.mkdir(parents=True)
            saved = {"query": "New", "observed_at": "2026-01-01", "kind": "person", "sections": {"web": [
                {"url": "https://example.org/new", "title": "New page"}]}, "report_json": str(path)}
            path.write_text(json.dumps(saved), encoding="utf-8")
            args = SimpleNamespace(db=str(out / "test.db"), out=folder, export=False)
            with redirect_stdout(io.StringIO()):
                jobfind.cmd_workspace_graph(args)
            graph = (out / "relationship_graph.html").read_text(encoding="utf-8")
            self.assertIn("https://example.org/old", graph)
            self.assertIn("https://example.org/new", graph)
            self.assertFalse((out / "exports").exists())
            args.export = True
            with redirect_stdout(io.StringIO()):
                jobfind.cmd_workspace_graph(args)
            self.assertEqual({p.name for p in (out / "exports").iterdir()}, {"research.csv", "research.json"})

    def test_spiderfoot_seed_event_is_not_a_successful_match(self):
        result = {"status": "partial", "error": "", "target": "Анна Ахматова", "target_type": "HUMAN_NAME",
                  "use_case": "passive", "modules": 1, "scan_id": "test", "database": "", "timed_out": True,
                  "event_count": 1, "rows": [], "emails": []}
        with patch.object(jobfind.spiderfoot_scan, "scan", return_value=result) as scanner:
            entry = jobfind._spiderfoot_entry("Анна Ахматова", Path("unused"), "person")
        self.assertEqual(scanner.call_args.kwargs["modules"], jobfind.spiderfoot_scan.DOSSIER_MODULES)
        self.assertEqual(entry["status"], "timeout")
        result["rows"] = [{"url": "https://example.org/poet"}]
        with patch.object(jobfind.spiderfoot_scan, "scan", return_value=result):
            self.assertEqual(jobfind._spiderfoot_entry("Анна Ахматова", Path("unused"), "person")["status"], "partial")
