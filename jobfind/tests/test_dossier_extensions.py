"""Offline integration contracts for the report's company/domain additions."""
import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from jf import ai_agents, db, dossier, evidence_graph
from jobfind import main


class ExtensionIntegrationTests(unittest.TestCase):
    def fixture(self, root):
        with patch.object(dossier.osint, "search", return_value=([], [], [])), \
             patch.object(dossier.extra_osint, "supplement", return_value={}), \
             patch.object(dossier, "run_tool", return_value={"errors": [], "statuses": []}), \
             patch.object(dossier.domain_recon, "investigate", return_value={"domain": "company.example", "dns": {}, "statuses": []}):
            return dossier.collect("company.example", "domain", "domain", Path(root) / "dossiers", include_spiderfoot=False)

    def test_careers_provenance_limits_graph_csv_ai_and_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.fixture(root)
            publication = "https://api.ashbyhq.com/posting-api/job-board/fixture"
            association = "https://company.example/careers"
            job = {"url": "https://jobs.ashbyhq.com/fixture/1", "title": "Engineer", "company": "Fixture",
                   "description": "A public engineering vacancy.", "source": "Ashby", "source_url": publication,
                   "company_source_url": association, "found_emails": ["hr@fixture.example"]}
            lead = {"url": "https://company.example/private-api", "source_url": "https://company.example/app.js",
                    "title": "Static JS candidate", "source": "Careers JS", "certainty": "candidate", "verification": "candidate"}
            dossier.merge_delta(result, {"jobs": [job], "careers": [{"url": "https://jobs.ashbyhq.com/fixture",
                "company_source_url": association, "source": "Company page"}], "findings": [lead],
                "emails": [{"email": "hr@fixture.example", "verification": "published", "source": "Company page",
                            "url": association, "evidence": [association]},
                           {"email": "guess@fixture.example", "verification": "hypothesis"}],
                "web": [{"url": association, "title": "Careers", "source": "Company page"}],
                "limits": {"partial": True, "cancelled": False, "pages_attempted": 12}, "js_candidates": [lead],
                "errors": [], "statuses": []})
            dossier.save_relationship_graph(result)
            self.assertTrue(result["career_discovery"][0]["limits"]["partial"])
            self.assertTrue(Path(result["exported_paths"]["markdown"]).is_file())
            markdown = Path(result["exported_paths"]["markdown"]).read_text(encoding="utf-8")
            self.assertIn(publication, markdown)
            self.assertIn("candidate", markdown)
            self.assertIn("A public engineering vacancy", markdown)
            graph = result["relationship_graph"]
            findings = [edge for edge in graph["edges"] if edge["kind"] == "CollectedFinding"]
            self.assertTrue(findings and all(edge["certainty"] == "candidate" for edge in findings))
            self.assertTrue(all(lead["url"] not in edge["source_urls"] for edge in findings))
            cited_pages = {node["properties"].get("url") for node in graph["nodes"] if node["kind"] == "Page"}
            self.assertIn(publication, cited_pages)
            self.assertNotIn(lead["url"], cited_pages)
            sample = ai_agents._evidence(result)
            self.assertEqual(next(row["url"] for row in sample if row["section"] == "jobs"), publication)
            self.assertEqual(next(row["attribution"] for row in sample if row["section"] == "findings"), "candidate")
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                jobs = [row for row in csv.DictReader(stream) if row["section"] == "jobs"]
            self.assertIn(publication, jobs[0]["details"])
            args = ["--db", str(root / "test.sqlite"), "--out", str(root), "--network", "direct", "dossier",
                    "--query", "company.example", "--no-spiderfoot"]
            with patch.object(dossier, "collect", return_value=result), redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 0)
            connection = db.connect(root / "test.sqlite")
            try:
                self.assertEqual(connection.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT count(*) FROM people_contacts").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT count(*) FROM osint_results").fetchone()[0], 1)
            finally:
                connection.close()
            self.assertEqual(result["database_jobs"], {"new": 0, "updated": 1})

    def test_current_and_archived_page_are_not_merged(self):
        report = {"query": "fixture", "observed_at": "2026-10-03T00:00:00Z", "sections": {}, "errors": []}
        url = "https://fixture.example/contact"
        dossier.merge_delta(report, {"web": [{"url": url, "snippet": "Current contact", "source": "Company"}]})
        dossier.merge_delta(report, {"web": [{"url": url, "snippet": "Old contact", "source": "Wayback",
                    "archived": True, "snapshot_at": "2020-01-01T00:00:00Z"}]})
        self.assertEqual(len(report["sections"]["web"]), 2)
        self.assertEqual(report["sections"]["web"][0]["snippet"], "Current contact")

    def test_nested_domain_card_drives_history_and_csv(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.fixture(Path(temporary))
            result["sections"]["domain"]["domain_card"] = {"domain": "company.example",
                "records": {"AAAA": {"state": "success", "checked_at": result["observed_at"], "url": "https://dns.example/query",
                    "records": [{"value": "2001:db8::1", "ttl": 60}]}},
                "registration": {"state": "success", "created": "2001-01-01T00:00:00Z", "source": "RDAP",
                    "url": "https://rdap.example/domain/company.example", "checked_at": result["observed_at"]}}
            dossier.save_relationship_graph(result)
            self.assertTrue(any(event["event"] == "domain_registration_created" for event in result["history"]["timeline"]))
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertTrue(any(row["kind"] == "dns_record" and row["value"] == "2001:db8::1" for row in rows))

    def test_export_cli_versions_vault_and_preserves_manual_notes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.fixture(root)
            args = ["--out", str(root), "dossier-export", "--path", result["report_json"], "--vault", str(root / "vault")]
            outputs = []
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(args), 0)
                outputs.append(json.loads(output.getvalue()))
                if len(outputs) == 1:
                    note = Path(outputs[0]["exported_paths"]["obsidian_directory"]) / "manual.md"
                    note.write_text("My own notes", encoding="utf-8")
            self.assertNotEqual(outputs[0]["exported_paths"]["obsidian_directory"], outputs[1]["exported_paths"]["obsidian_directory"])
            self.assertEqual(note.read_text(encoding="utf-8"), "My own notes")


if __name__ == "__main__":
    unittest.main()
