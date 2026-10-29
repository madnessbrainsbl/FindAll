"""Offline checks for the bounded 2GIS worker and complete-record recovery."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jf import two_gis

URL = "https://2gis.ru/moscow/search/museum"
ITEM = {"id": "100_1", "name_ex": {"primary": "Synthetic Museum"},
        "address_name": "Synthetic address", "point": {"lat": 1, "lon": 2},
        "contact_groups": [None, {"contacts": [None, {"type": "email", "value": "museum@example.org"},
            {"type": "website", "value": "https://museum.example.org"}]}], "rubrics": [{"name": "Museum"}]}


class TwoGisTest(unittest.TestCase):
    def test_normalization_preserves_business_provenance_and_skips_malformed_fields(self):
        row = two_gis.normalize(ITEM, URL)
        self.assertEqual(row["name"], "Synthetic Museum")
        self.assertEqual(row["url"], "https://2gis.ru/moscow/firm/100")
        self.assertEqual(row["emails"], ["museum@example.org"])
        self.assertEqual(row["websites"], ["https://museum.example.org"])
        self.assertIsNone(two_gis.normalize(None, URL))
        self.assertIsNone(two_gis.normalize({**ITEM, "is_deleted": True}, URL))
        row = two_gis.normalize({"id": "101", "name": "Fixture", "name_ex": "bad", "point": "bad"}, URL)
        self.assertIsNone(row["latitude"])

    def test_interrupted_json_recovers_only_complete_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "raw.json"
            path.write_text("[" + json.dumps(ITEM) + ', {"id": ', encoding="utf-8")
            self.assertEqual(two_gis._read_raw(path), [ITEM])

    def test_timeout_terminates_only_worker_tree_and_keeps_partial_rows(self):
        class Worker:
            pid, returncode = 987654, None
            def wait(self, timeout):
                if self.returncode is None:
                    raise subprocess.TimeoutExpired("synthetic worker", timeout)
                return self.returncode
            def poll(self):
                return self.returncode
            def kill(self):
                self.returncode = -9
        def start(command, **_kwargs):
            Path(command[5]).write_text("[" + json.dumps(ITEM), encoding="utf-8")
            return Worker()
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "partial.json"
            with patch.object(two_gis.subprocess, "Popen", side_effect=start), patch.object(two_gis.subprocess, "run") as kill:
                rows = two_gis.collect(URL, raw, 1, timeout=1)
            self.assertEqual(rows.status, "timeout")
            self.assertEqual(rows[0]["collection_status"], "timeout")
            self.assertEqual(json.loads(raw.with_suffix(".status.json").read_text())["count"], 1)
            if two_gis.os.name == "nt":
                self.assertEqual(kill.call_args.args[0], ["taskkill", "/PID", "987654", "/T", "/F"])

    def test_empty_worker_failure_is_diagnostic_and_does_not_claim_success(self):
        class Worker:
            returncode, pid = 1, 987654
            def wait(self, timeout):
                return 1
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "empty.json"
            with patch.object(two_gis.subprocess, "Popen", return_value=Worker()):
                with self.assertRaisesRegex(RuntimeError, "Diagnostics"):
                    two_gis.collect(URL, raw, 1, timeout=1)
            self.assertEqual(json.loads(raw.with_suffix(".status.json").read_text())["state"], "error")


if __name__ == "__main__":
    unittest.main()
