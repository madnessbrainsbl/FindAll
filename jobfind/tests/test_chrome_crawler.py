import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

from jf import ai_agents, chrome_crawler, dossier, library


def sample():
    return dict(schema="findall.chrome-crawler.v1", url="https://example.org/listings", title="Public listings",
        text="Analyst bicycle 1200 RUB. Contact shown on the selected page.", observed_at="2026-10-22T08:00:00Z",
        extension_version="0.7.5", text_truncated=False,
        items=dict(method="json-ld", total=1, items=[dict(title="Analyst bicycle", url="https://example.org/item/1",
            details="Observed listing", price=1200, currency="RUB")]))


class ChromeCrawlerChecks(unittest.TestCase):
    def write(self, root, data):
        path = Path(root) / "page.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def test_import_preserves_bytes_source_status_ai_graph_and_exports_without_network(self):
        with tempfile.TemporaryDirectory() as temp, patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
                patch("jf.evidence_capture.fetch_public", side_effect=AssertionError("No network")):
            path = self.write(temp, sample())
            original = path.read_bytes()
            result = chrome_crawler.import_page(path, Path(temp) / "out", query="Compare bicycles")
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(result["source_checks"][0]["state"], "ok")
            self.assertEqual(result["sections"]["findings"][0]["url"], sample()["url"])
            self.assertEqual(result["sections"]["findings"][0]["linked_url"], "https://example.org/item/1")
            artifact = result["artifacts"][0]
            self.assertEqual(Path(artifact["path"]).read_bytes(), original)
            self.assertEqual(artifact["sha256"], hashlib.sha256(original).hexdigest())
            self.assertNotIn("html_sha256", result["sections"]["web"][0])
            evidence = ai_agents._evidence(result, complete=True)
            imported = [row for row in evidence if row["provenance"] == "browser_import"]
            self.assertTrue(imported)
            self.assertTrue(all("not independently verified" in row["attribution"] for row in imported))
            self.assertTrue(any("1200" in row["text"] for row in imported))
            self.assertTrue(result["relationship_graph"]["nodes"])
            self.assertTrue(Path(result["report_json"]).is_file())
            self.assertIn("Analyst bicycle", Path(result["report_csv"]).read_text(encoding="utf-8-sig"))
            self.assertTrue(result["exported_paths"])
            self.assertEqual(result["quality_report"]["diagnostic_counts"].get("invalid_sections", 0), 0)
            again = chrome_crawler.import_page(path, Path(temp) / "out")
            self.assertNotEqual(result["report_json"], again["report_json"])
            self.assertEqual(json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))["query"], "Compare bicycles")

    def test_partial_empty_and_blocked_are_distinct(self):
        for state in ("partial", "empty", "blocked"):
            data = sample()
            if state == "partial":
                data["text_truncated"] = True
                data["items"]["total"] = 120
            elif state == "empty":
                data["text"] = ""
                data["items"].update(total=0, items=[])
            else:
                data["title"] = "Just a moment"
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                result = chrome_crawler.import_page(self.write(temp, data), Path(temp) / "out")
                self.assertEqual(result["source_checks"][0]["state"], state)
                if state != "partial":
                    self.assertEqual(result["sections"]["web"], [])
                    self.assertEqual(result["sections"]["findings"], [])

    def test_full_text_beyond_preview_reaches_library_with_browser_attribution(self):
        with tempfile.TemporaryDirectory() as temp:
            data = sample()
            data["text"] = "prefix " * 1000 + "Unique phrase beyond the preview"
            result = chrome_crawler.import_page(self.write(temp, data), Path(temp) / "out")
            path = Path(result["report_json"])
            rows = list(library._dossier_rows(path, result, "a" * 64, path))
            full = [row for row in rows if "Unique phrase" in row["text"]]
            self.assertTrue(full)
            self.assertTrue(all(row["provenance"] == "browser_import" for row in full))
            self.assertTrue(all("not independently verified" in row["attribution"] for row in full))

    def test_rejects_malformed_limits_urls_and_nonfinite_prices_before_creating_output(self):
        changes = [dict(schema="unknown"), dict(text=17), dict(text="x" * 100001), dict(observed_at="yesterday"),
            dict(observed_at="2026-10-22T08:00:00"), dict(text_truncated="yes"), dict(items=[]),
            dict(url="https://user:pass@example.org/"), dict(url="https://localhost/"),
            dict(url="https://127.0.0.1/"), dict(url="file:///private"), dict(url="https://example.org/?token=secret"),
            dict(url="https://example.invalid/"), dict(url="https://example.org:9222/"), dict(extra="forbidden")]
        for price in (float("nan"), float("inf"), -1, True, "12"):
            data = sample()
            data["items"]["items"][0]["price"] = price
            changes.append(dict(items=data["items"]))
        data = sample()
        data["items"]["items"] *= 101
        data["items"]["total"] = 101
        changes.append(dict(items=data["items"]))
        for change in changes:
            with self.subTest(fields=list(change)), tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "out"
                with self.assertRaises(ValueError):
                    chrome_crawler.import_page(self.write(temp, {**sample(), **change}), output)
                self.assertFalse(output.exists())

    def test_rejects_oversized_and_non_json_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            for content in (b"x" * (chrome_crawler.MAX_BYTES + 1), b"not json", b"\xff"):
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    chrome_crawler.load(path)

    def test_selected_files_join_research_keep_other_sources_and_isolate_errors(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(dossier.extra_osint, "supplement", return_value={
                "web": [dict(url="https://example.org/other", source="Synthetic public source", snippet="Existing evidence")]}), \
                patch("socket.getaddrinfo", side_effect=AssertionError("No network")):
            selected = self.write(temp, sample())
            bad = Path(temp) / "bad.json"
            bad.write_text("bad JSON", encoding="utf-8")
            events = []
            result = dossier.collect("fixture@example.org", "email", "email", Path(temp) / "out" / "dossiers",
                progress=events.append, include_spiderfoot=False, include_extra_tools=False, capture_pages=-1,
                browser_files=[selected, bad, selected])
            self.assertEqual({row["url"] for row in result["sections"]["web"]}, {sample()["url"], "https://example.org/other"})
            self.assertEqual(len(result["sections"]["findings"]), 1)
            self.assertEqual(next(row["state"] for row in result["source_checks"] if row["source"] == "browser_import"), "partial")
            self.assertEqual([row["state"] for row in events if row.get("stage") == "browser_import" and row.get("source")], ["partial"])
            self.assertTrue(result["errors"])
            self.assertIn("Analyst bicycle", Path(result["report_csv"]).read_text(encoding="utf-8-sig"))
            self.assertTrue(all(Path(row["path"]).is_file() for row in result["artifacts"]))
            self.assertEqual(len(list(Path(temp).rglob("dossier.json"))), 1)

    def test_truncated_files_keep_partial_in_progress_and_terminal_source_check(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(dossier.extra_osint, "supplement", return_value={}):
            data = sample()
            data["text_truncated"] = True
            events = []
            result = dossier.collect("fixture@example.org", "email", "email", Path(temp) / "out" / "dossiers",
                progress=events.append, include_spiderfoot=False, include_extra_tools=False, capture_pages=-1,
                browser_files=[self.write(temp, data)])
            self.assertEqual(next(row["state"] for row in result["source_checks"] if row["source"] == "browser_import"), "partial")
            self.assertEqual([row["state"] for row in events if row.get("stage") == "browser_import" and row.get("source")], ["partial"])

    def test_file_limit_is_rejected_before_starting_research(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(dossier.extra_osint, "supplement") as collect:
            with self.assertRaises(ValueError):
                dossier.collect("fixture@example.org", "email", "email", Path(temp) / "out", browser_files=["unused"] * 11)
            collect.assert_not_called()
            self.assertFalse((Path(temp) / "out").exists())

    def test_independent_browser_collector_is_not_mislabeled_as_an_import(self):
        for kind in ("browser_jsonld", {"untrusted": "kind"}, ["untrusted"]):
            evidence = ai_agents._evidence(dict(sections=dict(findings=[dict(kind=kind, source="Browser research",
                url="https://example.org", title="Live browser observation", value="Observed data")])))
            self.assertTrue(evidence)
            self.assertNotEqual(evidence[0]["provenance"], "browser_import")

    def test_dossier_cli_passes_selected_paths_without_enabling_browser_automation(self):
        import jobfind
        with tempfile.TemporaryDirectory() as temp, patch.object(dossier, "collect", return_value={
                "sections": {}, "report_json": str(Path(temp) / "dossier.json")}) as collect, \
                patch.object(dossier, "save_relationship_graph"), redirect_stdout(io.StringIO()):
            self.assertEqual(jobfind.main(["--out", temp, "dossier", "--query", "Test query",
                "--browser-file", "C:\\Selected exports\\one.json", "--browser-file", "C:\\two.json"]), 0)
            self.assertEqual(collect.call_args.kwargs["browser_files"], ["C:\\Selected exports\\one.json", "C:\\two.json"])

    def test_real_dossier_cli_keeps_import_category_and_uses_only_disposable_database(self):
        import jobfind
        with tempfile.TemporaryDirectory() as temp, patch.object(dossier.extra_osint, "supplement", return_value={}), \
                patch("socket.getaddrinfo", side_effect=AssertionError("No network")), redirect_stdout(io.StringIO()) as stdout:
            path = self.write(temp, sample())
            self.assertEqual(jobfind.main(["--out", str(Path(temp) / "out"), "--db", str(Path(temp) / "test.db"),
                "dossier", "--query", "fixture@example.org", "--kind", "email", "--scope", "email",
                "--no-spiderfoot", "--no-extra-tools", "--capture-pages", "-1", "--browser-file", str(path)]), 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["sections"]["web"][0]["category"], "Imported browser observation")
            self.assertEqual(result["database_pages"]["new"], 1)
            self.assertTrue(Path(result["report_json"]).is_file())

    def test_empty_blocked_and_omitted_exports_keep_distinct_aggregate_states(self):
        for state in ("empty", "blocked", "partial"):
            data = sample()
            data.update(text="", items=dict(method="none", total=0, items=[]))
            if state == "blocked":
                data["title"] = "Verify you are human"
            elif state == "partial":
                data["text_truncated"] = True
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                result = chrome_crawler.collect([self.write(temp, data)], Path(temp) / "out")
                self.assertEqual(result["status"], state)
                self.assertEqual(result["statuses"][0]["state"], state)

    def test_cli_outputs_a_standard_dossier_and_bounded_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.write(temp, sample())
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / "jobfind.py"),
                       "--out", str(Path(temp) / "out"), "browser-import", "--file", str(path)]
            run = subprocess.run(command, capture_output=True, encoding="utf-8", timeout=40)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertEqual(json.loads(run.stdout)["browser_import"]["status"], "ok")
            path.write_text('{"schema":"bad"}', encoding="utf-8")
            run = subprocess.run(command, capture_output=True, encoding="utf-8", timeout=40)
            self.assertEqual(run.returncode, 1)
            self.assertEqual(set(json.loads(run.stdout)), {"error"})


if __name__ == "__main__":
    unittest.main()
