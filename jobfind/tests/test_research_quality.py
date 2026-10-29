"""Deterministic synthetic evaluation; no external services or model calls."""

from copy import deepcopy
import json
import unittest

from jf import research_quality


class ResearchQualityChecks(unittest.TestCase):
    def test_synthetic_benchmark_passes(self):
        report = research_quality.run_benchmark()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["cases_passed"], 8)

    def test_evaluation_never_mutates_or_discloses_input(self):
        dossier = {"query": "private-query", "api_key": "private-key", "sections": {},
                   "source_checks": [{"source": "private-name", "url": "https://user:private-pass@example.org/?token=private-token",
                                      "state": "error", "detail": "private-diagnostic"}],
                   "ai_analysis": {"claims": [{"evidence_id": "private-id", "statement": "private-statement"}]}}
        before = deepcopy(dossier)
        report = research_quality.evaluate(dossier)
        self.assertEqual(dossier, before)
        self.assertNotIn("private-", json.dumps(report))
        self.assertNotIn("accuracy", report["metrics"])

    def test_invalid_input_is_reported_without_exception(self):
        for dossier in (None, [], "invalid", {"sections": [], "ai_analysis": "invalid"}):
            with self.subTest(dossier=dossier):
                self.assertEqual(research_quality.evaluate(dossier)["status"], "invariant_failures")

    def test_urls_keep_distinct_source_checks_and_terminal_replaces_pending(self):
        report = research_quality.evaluate({"sections": {}, "source_checks": [
            {"source": "capture", "url": "https://example.org/a", "state": "running"},
            {"source": "capture", "url": "https://example.org/a", "state": "ok"},
            {"source": "capture", "url": "https://example.org/b", "state": "timeout"}]})
        self.assertEqual(report["metrics"]["source_checks_total"], 2)
        self.assertEqual(report["coverage"]["unfinished_sources"], 0)
        self.assertEqual(report["coverage"]["sources_with_gaps"], 1)

    def test_diagnostic_cap_does_not_hide_late_error(self):
        report = research_quality.evaluate({"sections": {}, "source_checks": [
            {"source": str(index), "state": "blocked"} for index in range(110)],
            "ai_analysis": {"status": "ok", "claims": []}})
        self.assertEqual(len(report["diagnostics"]), 100)
        self.assertTrue(report["diagnostics_truncated"])
        self.assertEqual(report["status"], "invariant_failures")

    def test_whitespace_matching_is_allowed_but_quote_case_is_exact(self):
        dossier = {"sections": {"web": [{"url": "https://example.org/", "snippet": "Example   Studio"}]}}
        dossier["ai_analysis"] = {"claims": [{"evidence_id": "E1", "quote": "Example Studio", "statement": "The page mentions Example Studio.",
            "source_url": "https://example.org/", "section": "web", "provenance": "search_match",
            "attribution": "Search match; target identity unverified"}]}
        self.assertEqual(research_quality.evaluate(dossier)["metrics"]["citation_checks_passed"], 1)
        dossier["ai_analysis"]["claims"][0]["quote"] = "example studio"
        self.assertIn("quote_not_found", research_quality.evaluate(dossier)["diagnostic_counts"])

    def test_ownership_findings_require_review_even_with_matching_quote(self):
        dossier = {"sections": {"findings": [{"url": "https://example.org/", "description": "Sample owns this device."}]},
                   "ai_analysis": {"claims": [{"evidence_id": "E1", "quote": "Sample owns this device.",
                       "statement": "Sample owns this device.", "source_url": "https://example.org/", "section": "findings",
                       "provenance": "collector_report", "attribution": ""}]}}
        report = research_quality.evaluate(dossier)
        self.assertEqual(report["metrics"]["citation_checks_passed"], 1)
        self.assertEqual(report["status"], "needs_review")
        self.assertIn("identity_assertion_requires_review", report["diagnostic_counts"])


if __name__ == "__main__":
    unittest.main()
