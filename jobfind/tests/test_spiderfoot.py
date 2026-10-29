"""Offline checks for the SpiderFoot events that FindAll keeps."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jf import dossier, spiderfoot_scan


class SpiderFootNormalizeTest(unittest.TestCase):
    def test_profile_events_reach_search_rows_without_becoming_identity_proof(self):
        result = spiderfoot_scan.normalize_events([
            {"type": "HUMAN_NAME", "data": "Anna Example", "module": "seed"},
            {"type": "SOCIAL_MEDIA", "data": "GitHub: https://github.com/anna-example", "module": "sfp_fixture"},
            {"type": "PASSWORD_COMPROMISED", "data": "private", "module": "sfp_fixture"}])
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["url"], "https://github.com/anna-example")
        self.assertIn("identity unverified", result["rows"][0]["snippet"])

    def test_merge_preserves_findings_from_previous_collectors(self):
        prior = {"event_type": "IP_ADDRESS", "value": "Public registration",
                 "url": "https://rdap.org/ip/8.8.8.8", "module": "rdap"}
        sections = {"web": [], "profiles": [], "emails": [], "domain": None,
                    "findings": [prior]}
        report = {"status": "ok", "events": [{"type": "INTERNET_NAME",
                  "data": "www.example.org", "module": "sfp_dns", "source_data": ""}]}
        spiderfoot_scan.merge_dossier(sections, report, "2026-10-03T00:00:00+00:00")
        self.assertEqual(sections["findings"][0], prior)
        self.assertTrue(any(row["value"] == "www.example.org" for row in sections["findings"]))

    def test_target_types_follow_spiderfoot_seed_rules(self):
        self.assertEqual(spiderfoot_scan.prepare_target("example.org"), ("example.org", "INTERNET_NAME"))
        self.assertEqual(spiderfoot_scan.prepare_target("Alex Smith", "person"), ("Alex Smith", "HUMAN_NAME"))
        self.assertEqual(spiderfoot_scan.prepare_target("smith", "username"), ("smith", "USERNAME"))
        self.assertEqual(spiderfoot_scan.prepare_target("name@example.org"), ("name@example.org", "EMAILADDR"))
        self.assertEqual(spiderfoot_scan.prepare_target("8.8.8.8"), ("8.8.8.8", "IP_ADDRESS"))
        self.assertEqual(spiderfoot_scan.prepare_target("8.8.8.0/24"), ("8.8.8.0/24", "NETBLOCK_OWNER"))
        self.assertEqual(spiderfoot_scan.prepare_target("+14155552671"), ("+14155552671", "PHONE_NUMBER"))
        self.assertEqual(spiderfoot_scan.prepare_target("15169"), ("15169", "BGP_AS_OWNER"))
        self.assertEqual(spiderfoot_scan.prepare_target("cafe"), ("cafe", "USERNAME"))
        self.assertEqual(spiderfoot_scan.prepare_target("2001:db8::1"), ("2001:db8::1", "IPV6_ADDRESS"))

    def test_use_case_keeps_database_storage_and_drops_the_stdout_module(self):
        modules = {
            "sfp_dnsresolve": {"group": ["Passive", "Footprint"]},
            "sfp_nmap": {"group": ["Footprint"]},
            "sfp__stor_stdout": {"group": []},
            "sfp__stor_db": {"group": []},
        }
        self.assertEqual(spiderfoot_scan.select_modules(modules, "passive"), ["sfp_dnsresolve", "sfp__stor_db"])
        self.assertIn("sfp_nmap", spiderfoot_scan.select_modules(modules, "footprint"))
        folder = spiderfoot_scan.VENDOR / "modules"
        banned = {"sfp_nmap", "sfp_portscan_tcp", "sfp_dnsbrute", "sfp_hackertarget",
                  "sfp_dehashed", "sfp_psbdmp", "sfp_leakix", "sfp_accounts", "sfp_callername"}
        self.assertTrue(banned.isdisjoint(spiderfoot_scan.DOSSIER_MODULES))
        self.assertGreaterEqual(len(spiderfoot_scan.DOSSIER_MODULES), 10)
        for name in spiderfoot_scan.DOSSIER_MODULES:
            self.assertTrue((folder / f"{name}.py").is_file(), name)

    def test_published_email_joins_the_dossier_and_secrets_stay_out(self):
        self.assertFalse(spiderfoot_scan.publishable("PASSWORD_COMPROMISED"))
        report = {"status": "partial", "timed_out": True, "event_count": 2, "modules": 3,
                  "scan_id": "ABC", "database": "spiderfoot.db", "target_type": "INTERNET_NAME",
                  "use_case": "passive", "error": "", "errors": [],
                  "events": [
                      {"type": "EMAILADDR", "data": "jobs@example.org", "module": "sfp_test",
                       "source_data": "https://example.org/contact"},
                      {"type": "PASSWORD_COMPROMISED", "data": "secret-value", "module": "sfp_test",
                       "source_data": ""},
                      {"type": "INTERNET_NAME", "data": "www.example.org", "module": "sfp_dns",
                       "source_data": ""},
                  ]}
        sections = {"web": [], "profiles": [], "emails": [], "domain": None}
        spiderfoot_scan.merge_dossier(sections, report, "2026-10-02T00:00:00+00:00")
        self.assertEqual(sections["emails"][0]["url"], "https://example.org/contact")
        self.assertEqual(sections["findings"][0]["value"], "www.example.org")
        self.assertNotIn("secret-value", str(sections))
        self.assertEqual(sections["spiderfoot"]["scan_id"], "ABC")

        with tempfile.TemporaryDirectory() as root:
            with (patch.object(dossier.osint, "search", return_value=([], [], [])),
                  patch.object(dossier.extra_osint, "supplement", return_value={"errors": []}),
                  patch.object(dossier, "run_tool", return_value={"errors": [], "statuses": []}),
                  patch.object(dossier.spiderfoot_scan, "scan", return_value=report)):
                result = dossier.collect("Alex Smith", "person", "full", Path(root))
        self.assertEqual(result["sections"]["emails"][0]["email"], "jobs@example.org")
        self.assertTrue(any("time limit" in error for error in result["errors"]))
        self.assertEqual(dossier.identify("name@example.org", "auto")[1], "email")
        self.assertEqual(dossier.identify("8.8.8.8", "auto")[1], "ip")
        self.assertEqual(dossier.identify("cafe", "auto")[1], "person")
