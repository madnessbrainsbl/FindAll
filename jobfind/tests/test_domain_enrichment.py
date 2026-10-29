import json
import unittest
from unittest.mock import patch

from jf import domain_enrichment as enrichment, domains, extra_osint, net


def response(data=None, status=200, error="", url="https://example.org"):
    return net.HttpResult(status, json.dumps(data).encode() if data is not None else b"", url, error)


class DomainEnrichmentTests(unittest.TestCase):
    def test_distinct_dns_outcomes(self):
        fixtures = [({"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.1", "TTL": 60}]}, "success"),
                    ({"Status": 0}, "no_records"), ({"Status": 3}, "nxdomain"),
                    ({"Status": 2}, "error"), ({"wrong": True}, "error"),
                    ({"Status": 0, "Answer": {}}, "error")]
        for data, expected in fixtures:
            with self.subTest(expected=expected), patch.object(net, "get", return_value=response(data)):
                self.assertEqual(enrichment.dns_query("example.org", "A")["state"], expected)
        with patch.object(net, "get", return_value=response(status=0, error="Request timed out")):
            self.assertEqual(enrichment.dns_query("example.org", "A")["state"], "timeout")

    def test_ipv6_only_registration_and_null_mx(self):
        calls = []
        def fake(url, params=None, **kwargs):
            calls.append((url, params))
            if url.startswith(enrichment.RDAP):
                return response({"events": [{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}],
                                 "redacted": [{"name": {"description": "Registrant"}}]})
            kind = params["type"]
            answer = [{"type": 28, "data": "2001:db8::1"}] if kind == "AAAA" else [{"type": 15, "data": "0 ."}] if kind == "MX" else []
            return response({"Status": 0, "Answer": answer})
        with patch.object(net, "get", side_effect=fake):
            card = domains.domain_report("example.org")
        self.assertTrue(card["alive"])
        self.assertGreater(card["age_years"], 20)
        self.assertTrue(card["registration"]["redacted"])
        self.assertTrue(card["null_mx"])
        self.assertEqual(card["mx"], [])
        self.assertFalse(card["email_plausible"])
        self.assertEqual(card["addresses"], ["2001:db8::1"])
        self.assertNotIn("PTR", [params["type"] for _, params in calls if params])

    def test_ptr_uses_reverse_address(self):
        calls = []
        def fake(url, params=None, **kwargs):
            if not params:
                return response({})
            calls.append(params)
            if params["type"] == "A":
                return response({"Status": 0, "Answer": [{"type": 1, "data": "1.1.1.1"}]})
            if params["type"] == "PTR":
                return response({"Status": 0, "Answer": [{"type": 12, "data": "one.one.one.one."}]})
            return response({"Status": 0})
        with patch.object(net, "get", side_effect=fake):
            result = enrichment.domain_card("example.org")
        self.assertEqual([entry["name"] for entry in calls if entry["type"] == "PTR"], ["1.1.1.1.in-addr.arpa"])
        self.assertEqual(result["records"]["PTR"]["state"], "success")

    def test_existing_complete_card_reused_without_requests(self):
        existing = {"records": {kind: {"state": "no_records", "records": [], "type": kind, "name": "example.org", "checked_at": "2026-01-01"} for kind in enrichment.TYPES},
                    "registration": {"state": "success", "created": None, "updated": None, "expires": None,
                                     "registrar": None, "redacted": True, "age_years": None, "source": "RDAP", "url": "https://rdap.org/domain/example.org", "checked_at": "2026-01-01"}}
        existing["records"]["DMARC"] = {"records": [], "state": "no_records", "checked_at": "2026-01-01"}
        with patch.object(net, "get", side_effect=AssertionError("No repeated lookups")):
            result = enrichment.collect("example.org", existing_card=existing, include_dnsdumpster=False)
        self.assertEqual(result["domain_card"]["registration"]["source"], "RDAP")

    def test_webcheck_nonempty_reused_empty_rechecked(self):
        queried = []
        def fake(url, params=None, **kwargs):
            queried.append(params["type"] if params else "RDAP")
            return response({"Status": 0})
        webcheck = {"data": {"dns": {"A": [], "AAAA": ["2001:db8::1"], "MX": [{"priority": 0, "exchange": "."}]},
                             "whois": {"created": "2002-01-01T00:00:00Z", "registrar": "Fixture"},
                             "tech-stack": {"technologies": [{"name": "Fixture", "version": "1"}]}}}
        with patch.object(net, "get", side_effect=fake):
            result = enrichment.collect("example.org", webcheck=webcheck, include_dnsdumpster=False)
        self.assertNotIn("AAAA", queried)
        self.assertNotIn("MX", queried)
        self.assertNotIn("RDAP", queried)
        self.assertIn("A", queried)
        self.assertEqual(result["technologies"][0]["version"], "1")

    def test_dnsdumpster_missing_key_and_rate_limit(self):
        with patch.object(enrichment, "_key", return_value=""), patch.object(net, "get", side_effect=AssertionError("No request")):
            self.assertEqual(enrichment.dnsdumpster("example.org")["statuses"][0]["state"], "missing_key")
        with patch.object(enrichment, "_key", return_value="fixture-key"), patch.object(net, "get", return_value=response(status=429, error="HTTP 429")), patch.object(enrichment.time, "sleep"):
            result = enrichment.dnsdumpster("example.org")
        self.assertEqual(result["statuses"][0]["state"], "rate_limited")
        self.assertNotIn("fixture-key", json.dumps(result))

    def test_dnsdumpster_unique_scoped_hosts_and_provider_spacing(self):
        fixture = {"a": [{"host": "api.example.org", "ips": [{"ip": "1.1.1.1", "asn": "1", "banners": {"https": {"apps": ["Fixture"]}}}]},
                         {"host": "api.example.org", "ips": []}, {"host": "x.example.org.attacker.net", "ips": []},
                         {"host": "jobs.example.org", "ips": []}], "total_a_recs": 7}
        with patch.object(enrichment, "_key", return_value="fixture-key"), patch.object(net, "get", return_value=response(fixture)) as get, patch.object(enrichment.time, "monotonic", return_value=50), patch.object(enrichment.time, "sleep") as sleep, patch.object(enrichment, "_dumpster_next", 51):
            result = enrichment.dnsdumpster("example.org", ["api.example.org"])
        sleep.assert_called_once_with(1)
        self.assertEqual(get.call_args.kwargs["retries"], 0)
        self.assertEqual([row["name"] for row in result["subdomains"]], ["api.example.org", "jobs.example.org"])
        self.assertEqual(result["statuses"][0]["unique_count"], 1)
        self.assertTrue(result["statuses"][0]["truncated"])
        self.assertIsNone(result["findings"][0]["observed_at"])

    def test_httpx_structured_fields_and_sensitive_header_exclusion(self):
        fixture = {"url": "https://example.org", "status_code": 200, "title": "Example", "tech": ["Fixture:1.2"],
                   "header": {"server": "fixture/1.2", "set-cookie": "session=SECRET", "authorization": "SECRET"},
                   "tls": {"tls_version": "tls13", "issuer_cn": "Fixture CA", "not_after": "2027-01-01"}}
        row = extra_osint.httpx_page("example.org", json.dumps(fixture))[0]
        self.assertEqual(row["http_observation"]["tls"]["tls_version"], "tls13")
        self.assertEqual(row["http_observation"]["technologies"], ["Fixture:1.2"])
        self.assertNotIn("SECRET", json.dumps(row))
        fixture["url"] = "https://elsewhere.org"
        self.assertEqual(extra_osint.httpx_page("example.org", json.dumps(fixture)), [])

    def test_httpx_limits_route_and_no_extra_probes(self):
        with patch.object(extra_osint, "_proxy", return_value="http://127.0.0.1:20000"):
            command = extra_osint.httpx_command("example.org")
        self.assertIn("-json", command)
        self.assertEqual(command[command.index("-proxy") + 1], "http://127.0.0.1:20000")
        self.assertIn("-rstr", command)
        for flag in ("-tls-probe", "-ports", "-path", "-jarm", "-dashboard"):
            self.assertNotIn(flag, command)

    def test_httpx_silent_failure_is_reported(self):
        with patch.object(extra_osint.HTTPX.__class__, "is_file", return_value=True), patch.object(extra_osint, "_run", return_value=("", "", False)):
            result = extra_osint.httpx_probe("example.org")
        self.assertEqual(result["web"], [])
        self.assertIn("no parseable", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
