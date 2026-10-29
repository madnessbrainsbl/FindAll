"""Keyword filtering must precede the per-source result limit."""
import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jobfind
from jf import sources


class ArbeitnowSearchTests(unittest.TestCase):
    def response(self):
        rows = [dict(title="Marketing Specialist", company_name="Example", description="Campaigns",
                     url=f"https://example.org/job/{index}") for index in range(15)]
        rows.extend([
            dict(title="Backend Engineer", company_name="Example", description="Python services",
                 url="https://example.org/job/python"),
            dict(title="Backend Engineer", company_name="Example", description="Java services",
                 url="https://example.org/job/java"),
        ])
        return SimpleNamespace(error="", json=lambda: {"data": rows})

    def test_matching_job_after_unrelated_rows_is_not_cut_off(self):
        with patch.object(sources.net, "get", return_value=self.response()):
            rows = sources.arbeitnow("backend Python", 1)
        self.assertEqual([row["url"] for row in rows], ["https://example.org/job/python"])

    def test_all_terms_are_required_and_case_insensitive(self):
        with patch.object(sources.net, "get", return_value=self.response()):
            rows = sources.arbeitnow("  BACKEND   python  ", 10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "Python services")

    def test_empty_query_retains_unfiltered_scan(self):
        with patch.object(sources.net, "get", return_value=self.response()):
            rows = sources.arbeitnow("  ", 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["url"], "https://example.org/job/0")

    def test_unified_search_persists_and_diagrams_late_match(self):
        with tempfile.TemporaryDirectory() as temp:
            args = SimpleNamespace(kw="backend Python", sources="arbeitnow", per_source=1,
                                   project_limit=1, db=str(Path(temp)/"search.db"), out=temp)
            output = io.StringIO()
            with patch.object(sources.net, "get", return_value=self.response()), \
                    patch.object(jobfind.projects_mod, "search", return_value=[]), \
                    patch.object(jobfind, "_search_web", return_value=([], "")), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(jobfind.cmd_search(args), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["counts"]["jobs"], 1)
            self.assertEqual(result["reports"], {})
            self.assertIn("https://example.org/job/python", Path(result["graph_path"]).read_text(encoding="utf-8"))
            self.assertFalse(list(Path(temp).glob("search_*.csv")))
            conn = jobfind.db.connect(Path(args.db))
            try:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
