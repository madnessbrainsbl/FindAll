"""Offline checks of added engine adapters and local evidence provenance."""

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from jf import additional_tools as tools


class AdditionalToolsCheck(unittest.TestCase):
    def test_selected_document_metadata_hash_and_rejected_xml_entities(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            document = folder / "selected.docx"
            with zipfile.ZipFile(document, "w") as archive:
                archive.writestr("docProps/core.xml", '<core><creator>Example Author</creator></core>')
            result = tools.local_metadata([document], folder / "evidence")
            digest = hashlib.sha256(document.read_bytes()).hexdigest()
            self.assertEqual(result["statuses"][0]["status"], "ok")
            self.assertEqual(result["findings"][0]["sha256"], digest)
            self.assertEqual(result["findings"][0]["metadata"]["document"]["creator"], "Example Author")
            self.assertEqual(result["findings"][0]["url"], "")
            self.assertNotIn(str(folder), result["findings"][0]["value"])
            saved = json.loads(Path(result["artifacts"][0]["path"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["sha256"], digest)
            unsafe = folder / "unsafe.docx"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("docProps/core.xml", '<!DOCTYPE core [<!ENTITY x "example">]><core>&x;</core>')
            rejected = tools.local_metadata([unsafe], folder / "evidence")
            self.assertEqual(rejected["statuses"][0]["status"], "error")
            self.assertFalse(rejected["findings"])
            encoded = folder / "unsafe-utf16.docx"
            with zipfile.ZipFile(encoded, "w") as archive:
                archive.writestr("docProps/core.xml", ('<?xml version="1.0" encoding="UTF-16"?>'
                    '<!DOCTYPE core [<!ENTITY x "example">]><core>&x;</core>').encode("utf-16"))
            rejected = tools.local_metadata([encoded], folder / "evidence")
            self.assertEqual(rejected["statuses"][0]["status"], "error")
            self.assertFalse(rejected["findings"])

    def test_map_results_keep_object_contact_provenance_and_escape_query(self):
        payload = {"elements": [{"type": "node", "id": 123, "lat": 10.0, "lon": 20.0,
                    "tags": {"name": "Example Studio", "addr:city": "Example City",
                             "email": "studio@example.org", "phone": "+14155552671"}}]}
        with tempfile.TemporaryDirectory() as directory, patch.object(tools.urllib.request, "urlopen",
                return_value=io.BytesIO(json.dumps(payload).encode())) as request:
            result = tools.map_search('Studio";out;', "Example City", directory)
            self.assertEqual(result["businesses"][0]["url"], "https://www.openstreetmap.org/node/123")
            self.assertEqual(result["emails"][0]["email"], "studio@example.org")
            self.assertEqual(result["emails"][0]["url"], result["businesses"][0]["url"])
            self.assertEqual(result["businesses"][0]["location"], {"lat": 10.0, "lon": 20.0})
            self.assertEqual(result["statuses"][0]["status"], "ok")
            body = tools.urllib.parse.parse_qs(request.call_args.args[0].data.decode())["data"][0]
            self.assertIn(json.dumps('Studio";out;'), body)
            artifact = result["artifacts"][0]
            self.assertEqual(hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest(), artifact["sha256"])

    def test_phone_engine_timeout_and_output_keep_subscriber_unverified(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, "exists", return_value=True), patch.object(
                Path, 'is_file', return_value=True), patch.object(
                tools, "_run", side_effect=lambda command, *args, **kw: (0, json.dumps(
                    {'state': 'ok', 'data': {'e164': '+14155552671', 'country': 'US'}}
                    if command[1] == 'local' else {'state': 'skipped', 'detail': 'Fixture scanner unavailable'}))) as run:
            result = tools._phone("+14155552671", Path(directory))
            command = run.call_args_list[0].args[0]
            self.assertEqual(command[1:], ["local", "+14155552671"])
            finding = result["findings"][0]
            self.assertIn("no subscriber identity", finding["status"])
            self.assertEqual(finding["url"], "")
            raw = Path(result["artifacts"][0]["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), finding["sha256"])
            with patch.object(tools, "_run", return_value=(124, "Timed out")):
                timed_out = tools._phone("+14155552671", Path(directory))
            self.assertEqual(timed_out["statuses"][0]["status"], "timeout")
            self.assertFalse(timed_out["findings"])
            self.assertTrue(timed_out["errors"])

    def test_engine_subprocess_utf8_output_limit_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            code, text = tools._run([sys.executable, "-c", "print('x'*140000);print('Unicode: café')"], Path(directory), 10)
            self.assertEqual(code, 0)
            self.assertLessEqual(len(text), 120000)
            self.assertTrue(text.rstrip().endswith("Unicode: café"))
            code, text = tools._run([sys.executable, "-c", "import time;print('started',flush=True);time.sleep(10)"], Path(directory), 0.2)
            self.assertEqual(code, 124)
            self.assertIn("started", text)

    def test_harvester_source_failures_and_retry_do_not_reuse_or_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(tools, "HARVESTER", Path(sys.executable)):
            invocation = 0
            def engine(command, cwd, timeout):
                nonlocal invocation
                invocation += 1
                if invocation > 1:
                    return 1, "Failed before exporting"
                payload = [{"type": "summary", "evidence_status": "partial",
                            "source_executions": [{"source": "crtsh", "status": "failed", "result_count": 0,
                                                   "stop_reason": "http-403"},
                                                  {"source": "certspotter", "status": "completed", "result_count": 1}]},
                           {"type": "hostname", "value": "www.example.org", "sources": ["certspotter"]}]
                (Path(cwd) / "result.jsonl").write_text("\n".join(json.dumps(row) for row in payload), encoding="utf-8")
                return 0, "Partial source results"
            with patch.object(tools, "_run", side_effect=engine):
                first = tools._harvest("example.org", Path(directory), "quick")
                artifact = next(row for row in first["artifacts"] if row["path"].endswith("result.jsonl"))
                second = tools._harvest("example.org", Path(directory), "quick")
            self.assertEqual(len(first["findings"]), 1)
            self.assertFalse(second["findings"])
            self.assertTrue(any("crtsh" in row["source"] and row["status"] in ("failed", "error", "blocked")
                                for row in first["statuses"]))
            self.assertEqual(hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest(), artifact["sha256"])

    def test_map_email_list_is_normalized_and_invalid_address_not_exported(self):
        payload = {"elements": [{"type": "node", "id": 123,
                    "tags": {"name": "Example Studio", "email": "first@example.org; second@example.org; garbage"}}]}
        with tempfile.TemporaryDirectory() as directory, patch.object(tools.urllib.request, "urlopen",
                return_value=io.BytesIO(json.dumps(payload).encode())):
            result = tools.map_search("Studio", "Example City", directory)
        self.assertEqual([row["email"] for row in result["emails"]], ["first@example.org", "second@example.org"])

    def test_ip_indexed_service_provenance_key_skips_and_private_target_rejection(self):
        from jf import domain_recon
        with tempfile.TemporaryDirectory() as directory, patch.object(domain_recon, "configured_keys", return_value={}), patch.object(
                domain_recon, "_api", return_value={"ports": [443], "cpes": ["cpe:/a:example:server"]}) as api:
            result = tools._ip_services("8.8.8.8", Path(directory))
            self.assertEqual(api.call_count, 1)
            self.assertEqual(result["findings"][0]["url"], "https://internetdb.shodan.io/8.8.8.8")
            self.assertIn("ownership unverified", result["findings"][0]["status"])
            self.assertEqual(sum(row["status"] == "skipped" for row in result["statuses"]), 3)
            with self.assertRaises(ValueError):
                tools._ip_services("127.0.0.1", Path(directory))
            self.assertEqual(api.call_count, 1)
        with tempfile.TemporaryDirectory() as directory, patch.object(domain_recon, "configured_keys",
                return_value={"SHODAN_API_KEY": "fake-secret"}), patch.object(domain_recon, "_api",
                side_effect=[{"ports": []}, RuntimeError("response mentions fake-secret")]):
            result = tools._ip_services("8.8.8.8", Path(directory))
            self.assertNotIn("fake-secret", json.dumps(result))
            self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
