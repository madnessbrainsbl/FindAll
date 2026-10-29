"""Synthetic audit outputs; raw scanner findings do not reach exports."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from jf import local_audit


class LocalAuditTests(unittest.TestCase):
    def test_allowlisted_report_and_cli_flags(self):
        def run(argv, **kwargs):
            self.assertIn("--redact=100", argv)
            self.assertNotIn("shell", kwargs)
            raw = Path(argv[argv.index("--report-path") + 1])
            raw.write_text(json.dumps([{"RuleID": "synthetic", "File": "sample.py", "StartLine": 3,
                "Secret": "FAKE_PRIVATE_VALUE", "Match": "FAKE_PRIVATE_VALUE", "Author": "PRIVATE_AUTHOR",
                "Email": "PRIVATE_EMAIL"}]), encoding="utf-8")
            return SimpleNamespace(returncode=1)
        with tempfile.TemporaryDirectory() as temp, patch.object(local_audit.shutil, "which", return_value="gitleaks"), patch.object(local_audit.subprocess, "run", side_effect=run):
            report = local_audit.scan(temp, Path(temp) / "out")
            text = Path(report["report"]).read_text(encoding="utf-8")
            self.assertNotIn("PRIVATE", text)
            self.assertEqual(report["status"], "findings")
            self.assertEqual(report["findings"][0]["StartLine"], 3)

    def test_history_requires_git_and_missing_directory_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                local_audit.scan(temp, temp, history=True)
            with self.assertRaises(ValueError):
                local_audit.scan(Path(temp) / "absent", temp)

    def test_clean_local_scan_real_installed_binary(self):
        if not local_audit.BIN.exists():
            self.skipTest("Portable Gitleaks not installed")
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "sample.py").write_text("print('synthetic fixture')\n", encoding="utf-8")
            report = local_audit.scan(temp, Path(temp) / "audit")
            self.assertEqual(report["status"], "no_findings")

    def test_missing_or_invalid_scanner_report_is_partial(self):
        for payload in (None, {"invalid": "format"}):
            def run(argv, **kwargs):
                if payload is not None:
                    Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(payload), encoding="utf-8")
                return SimpleNamespace(returncode=0)
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temp, \
                 patch.object(local_audit.shutil, "which", return_value="gitleaks"), \
                 patch.object(local_audit.subprocess, "run", side_effect=run):
                self.assertEqual(local_audit.scan(temp, Path(temp) / "out")["status"], "partial")


if __name__ == "__main__":
    unittest.main()
