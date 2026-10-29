import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jf import dossier, evidence_capture as capture


class CollectionStatusChecks(unittest.TestCase):
    def test_unselected_pages_are_one_notice_not_many_failed_sources(self):
        body = b"<html><title>Example</title><p>Public example</p></html>"
        page = {"body": body, "html": body.decode(), "url": "https://example.org/",
                "requested_url": "https://example.org/", "content_type": "text/html",
                "http_status": 200, "observed_at": "2026-10-03T00:00:00Z", "sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as output, patch.object(capture, "validated_url", return_value=(
                "https://example.org/", "example.org", ["93.184.215.14"])), patch.object(
                capture, "fetch_public", return_value=page) as fetch:
            result = capture.capture_results([{"url": f"https://example.org/{i}"} for i in range(40)],
                                             Path(output), limit=1, singlefile=False)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual([row["state"] for row in result["statuses"]], ["ok", "limited"])
        self.assertEqual(result["selection"]["unselected"], 39)
        self.assertEqual(result["errors"], [])

    def test_selection_diversifies_hosts_and_removes_fragments_duplicates(self):
        rows = [{"url": f"https://a.example.org/{i}"} for i in range(20)]
        rows.extend([{"url": "https://b.example.org/one"}, {"url": "https://a.example.org/0#copy"}])
        selected, summary = capture._select_pages(rows, 2, False)
        self.assertEqual([row["url"] for row in selected], ["https://a.example.org/0", "https://b.example.org/one"])
        self.assertEqual(summary["duplicates"], 1)

    def test_unsupported_ports_do_not_consume_capture_limit(self):
        selected, summary = capture._select_pages([
            {"url": "http://example.org:9090/"}, {"url": "https://example.org:80/"},
            {"url": "https://example.org:bad/"}, {"url": "https://example.org/"}], 1, False)
        self.assertEqual([row["url"] for row in selected], ["https://example.org/"])
        self.assertEqual(summary["unsupported"], 3)

    def test_terminal_status_replaces_running_but_retains_history(self):
        report = {}
        dossier._record_check(report, {"source": "onion:onionland", "state": "running"})
        dossier._record_check(report, {"source": "onion:onionland", "state": "error", "detail": "HTTP 429"})
        self.assertEqual(len(report["source_checks"]), 1)
        self.assertEqual(report["source_checks"][0]["state"], "blocked")
        self.assertEqual(len(report["source_events"]), 2)

    def test_distinct_capture_urls_retain_distinct_checks(self):
        report = {}
        for url in ("https://a.example.org/", "https://b.example.org/"):
            dossier._record_check(report, {"source": "capture:1", "url": url, "state": "ok", "count": 1})
        self.assertEqual(len(report["source_checks"]), 2)


if __name__ == "__main__":
    unittest.main()
