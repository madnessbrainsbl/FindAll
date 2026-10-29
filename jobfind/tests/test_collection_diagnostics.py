"""Offline collection tracing contracts using disposable output directories."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jf import diagnostics, dossier


class CollectionDiagnosticsTests(unittest.TestCase):
    def test_allowlist_and_retry_counters(self):
        with tempfile.TemporaryDirectory() as folder, diagnostics.trace_run() as trace:
            result = {"report_json": str(Path(folder) / "dossier.json")}
            diagnostics.attach(result)
            diagnostics.record_network({"host": "example.org", "method": "GET", "status": 503,
                "state": "error", "attempts": 3, "retry_count": 2, "elapsed_seconds": 0.2,
                "url": "secret-url", "body": "secret-body", "Authorization": "secret-key"})
            diagnostics.record_source({"source": "web", "state": "running", "detail": "secret-detail"})
            diagnostics.record_source({"source": "web", "state": "ok", "count": 2})
            rows = Path(result["diagnostics"]["trace_path"]).read_text(encoding="utf-8")
            self.assertNotIn("secret-", rows)
            self.assertEqual(trace.summary()["network_retries"], 2)
            self.assertEqual(trace.summary()["network_failures"], 1)
            self.assertEqual(trace.summary()["source_states"], {"ok": 1})
            self.assertIn("elapsed_seconds", json.loads(rows.splitlines()[-1]))

    def test_event_buffer_is_bounded(self):
        with diagnostics.trace_run() as trace:
            for _ in range(1003):
                trace.emit("source", {})
            self.assertEqual(len(trace.pending), 1000)
            self.assertEqual(trace.summary()["omitted_events"], 3)

    def test_collect_saves_trace_and_quality_in_same_dossier(self):
        row = {"title": "Synthetic subject", "url": "https://example.org/", "snippet": "Public text", "source": "web"}
        with tempfile.TemporaryDirectory() as folder:
            with (patch.object(dossier.osint, "search", return_value=([row], [], [])),
                  patch.object(dossier, "run_tool", return_value={"errors": [], "statuses": []}),
                  patch.object(dossier.extra_osint, "supplement", return_value={
                      "profiles": [], "web": [], "findings": [], "hostnames": [], "errors": []}),
                  patch.object(dossier.spiderfoot_scan, "scan", return_value={"status": "skipped"})):
                result = dossier.collect("Synthetic subject", "person", "full", Path(folder))
            saved = json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["diagnostics"], result["diagnostics"])
            self.assertEqual(saved["quality_report"]["metrics"]["candidate_evidence_items"], 1)
            events = [json.loads(line) for line in Path(saved["diagnostics"]["trace_path"]).read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events[-1]["event"], "collection_completed")

    def test_no_trace_is_a_noop(self):
        diagnostics.record_network({"retry_count": 1})
        diagnostics.record_source({"source": "web", "state": "ok"})


if __name__ == "__main__":
    unittest.main()
