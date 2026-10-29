"""Local synthetic snapshot and optional history API contracts."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jf import dossier_history, evidence_graph, extra_osint, net


def report(date="2026-10-03T00:00:00+00:00", emails=None, checks=None):
    return {"query": "example.org", "kind": "domain", "observed_at": date,
            "sections": {"web": [], "emails": emails or [], "domain": {}}, "source_checks": checks or []}


class HistoryTest(unittest.TestCase):
    def test_incomplete_missing_is_not_deletion(self):
        old = report(emails=[{"email": "hello@example.org", "source": "Contacts", "url": "https://example.org/contact"}])
        for state in ("blocked", "timeout", "partial", "skipped", "error", "ok"):
            current = report(checks=[{"source": "Contacts", "state": state}])
            diff = dossier_history.compare(current, old)
            self.assertEqual(diff["missing"][0]["change"], "not_observed")
            self.assertEqual(diff["status"], "partial")

    def test_complete_inventory_reports_absence_not_deleted(self):
        old = report(emails=[{"email": "hello@example.org", "source": "Contacts"}])
        now = report(checks=[{"source": "Contacts", "state": "empty", "complete": True}])
        missing = dossier_history.compare(now, old)["missing"][0]
        self.assertEqual(missing["change"], "absent_from_complete_snapshot")
        self.assertTrue(missing["coverage_complete"])

    def test_stable_ids_and_url_case_sensitive_paths(self):
        old = report(emails=[{"email": "hello@example.org", "observed_at": "2026-09-01"}])
        now = report(emails=[{"email": "hello@example.org", "observed_at": "2026-10-03"}])
        self.assertEqual(dossier_history.compare(now, old)["unchanged_count"], 1)
        old["sections"]["web"] = [{"url": "https://example.org/Case"}]
        now["sections"]["web"] = [{"url": "https://example.org/case"}]
        self.assertEqual(len(dossier_history.compare(now, old)["added"]), 1)

    def test_archived_contact_never_current(self):
        old = report(emails=[{"email": "old@example.org", "archived": True, "source": "Internet Archive"}])
        now = report(emails=[{"email": "old@example.org", "source": "Contacts"}])
        diff = dossier_history.compare(now, old)
        self.assertTrue(diff["missing"][0]["archived"])
        self.assertFalse(diff["added"][0]["archived"])
        self.assertIn("current validity unverified", diff["missing"][0]["meaning"])
        graph = evidence_graph.build_graph(old)
        self.assertTrue(any(edge["kind"] == "HistoricalEmail" for edge in graph["edges"]))
        self.assertFalse(any(edge["kind"] == "PublishedEmail" for edge in graph["edges"]))

    def test_archive_and_commoncrawl_preserve_source_date(self):
        archive = extra_osint.archive_rows("example.org", [["https://example.org/", "20200102030405", "200"]])[0]
        crawl = extra_osint.commoncrawl_rows("example.org", json.dumps({"url": "https://example.org/about", "timestamp": "20210203040506"}))[0][0]
        now = report()
        now["sections"]["web"] = [archive, crawl]
        dates = {row["date"] for row in dossier_history.timeline(now)}
        self.assertEqual(dates, {"2020-01-02T03:04:05+00:00", "2021-02-03T04:05:06+00:00"})
        self.assertEqual(archive["original_url"], "https://example.org/")
        self.assertTrue(crawl["archived"])

    def test_enrich_reads_previous_same_query_without_rewriting(self):
        with tempfile.TemporaryDirectory() as root:
            old_path = Path(root) / "example.org" / "old" / "dossier.json"
            old_path.parent.mkdir(parents=True)
            old = report("2026-09-01T00:00:00+00:00", emails=[{"email": "old@example.org", "source": "Contacts"}])
            old_path.write_text(json.dumps(old), encoding="utf-8")
            original = old_path.read_bytes()
            path = Path(root) / "example.org" / "new" / "dossier.json"
            now = report(emails=[{"email": "new@example.org", "source": "Contacts"}])
            now["report_json"] = str(path)
            dossier_history.enrich(now, Path(root))
            self.assertEqual(now["history"]["comparison"]["previous_report"], str(old_path))
            self.assertEqual(old_path.read_bytes(), original)
            self.assertEqual(now["history"]["comparison"]["added"][0]["value"], "new@example.org")

    def test_missing_key_sends_no_requests(self):
        with patch("jf.domain_recon.configured_keys", return_value={}), patch("jf.net.get") as getter:
            data = dossier_history.get_securitytrails_history("example.org")
        getter.assert_not_called()
        self.assertEqual(data["statuses"][0]["state"], "skipped")

    def test_securitytrails_dates_and_partial_first_page(self):
        response = net.HttpResult(200, json.dumps({"records": [{"first_seen": "2020-01-01", "last_seen": "2021-01-01", "values": [{"ip": "203.0.113.1"}]}]}).encode(), "https://api.securitytrails.com/")
        with patch("jf.domain_recon.configured_keys", return_value={"SECURITY_TRAILS_API_KEY": "fixture-secret"}), patch("jf.net.get", return_value=response) as getter:
            data = dossier_history.get_securitytrails_history("example.org", ("a",))
        self.assertEqual(data["statuses"][-1]["state"], "partial")
        self.assertTrue(data["findings"][0]["archived"])
        self.assertEqual(data["findings"][0]["first_seen"], "2020-01-01")
        self.assertNotIn("fixture-secret", json.dumps(data))
        self.assertNotIn("fixture-secret", getter.call_args.args[0])

    def test_securitytrails_access_failure_not_absence(self):
        response = net.HttpResult(403, b"", "https://api.securitytrails.com/")
        with patch("jf.domain_recon.configured_keys", return_value={"SECURITY_TRAILS_API_KEY": "fixture"}), patch("jf.net.get", return_value=response):
            data = dossier_history.get_securitytrails_history("example.org", ("mx",))
        self.assertEqual(data["statuses"][-1]["state"], "blocked")
        self.assertEqual(len(data["errors"]), 1)

    def test_normalized_dns_history_and_graph_dates(self):
        old = report()
        old["sections"]["domain_card"] = {"records": {"MX": {"state": "success", "records": [{"value": "10 old.example.org"}], "checked_at": old["observed_at"], "source": "DoH"}}}
        now = report()
        now["sections"]["domain_card"] = {"records": {"MX": {"state": "no_records", "records": []}},
            "registration": {"created": "2000-01-01T00:00:00Z", "checked_at": now["observed_at"], "source": "RDAP", "url": "https://rdap.org/domain/example.org"}}
        self.assertEqual(dossier_history.compare(now, old)["missing"][0]["change"], "absent_from_complete_snapshot")
        now["history"] = {"timeline": dossier_history.timeline(now)}
        graph = evidence_graph.build_graph(now)
        historical = next(row for row in graph["nodes"] if row["kind"] == "HistoryEvent")
        self.assertEqual(historical["properties"]["event_date"], "2000-01-01T00:00:00+00:00")
        self.assertIn("not a company founding date", historical["label"])


if __name__ == "__main__":
    unittest.main()
