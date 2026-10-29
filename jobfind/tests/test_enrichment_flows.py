import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jf import ai_agents, evidence_graph, flowsint


class EnrichmentFlowTests(unittest.TestCase):
    def test_type_mismatch_cycle_unknown_code_and_duplicate_ids_rejected_before_collection(self):
        invalid = [
            flowsint._flow("wrong", "Domain", [("ip", "ip_asn", "seed")]),
            flowsint._flow("cycle", "Domain", [("one", "domain_root", "two"), ("two", "domain_root", "one")]),
            flowsint._flow("code", "Domain", [("code", "python_eval", "seed")]),
            flowsint._flow("duplicate", "Domain", [("one", "domain_root", "seed"), ("one", "domain_root", "seed")]),
            {**flowsint.FLOWS["domain-network"], "command": "anything"},
        ]
        with patch.object(flowsint.net, "get") as request, tempfile.TemporaryDirectory() as folder:
            for flow in invalid:
                with self.subTest(flow=flow), self.assertRaises(ValueError):
                    flowsint.run("example.org", flow, Path(folder))
            request.assert_not_called()
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_topological_sort_allows_forward_references(self):
        flow = flowsint._flow("forward", "Domain", [("web", "domain_website", "root"), ("root", "domain_root", "seed")])
        self.assertEqual([row["id"] for row in flowsint.validate_flow(flow)["steps"]], ["root", "web"])

    def test_inputs_reject_private_targets_credentials_sensitive_queries_and_unsupported_types(self):
        for kind, value in [("IP", "127.0.0.1"), ("IP", "::1"), ("CIDR", "10.0.0.0/8"),
                            ("Website", "https://u:p@example.org/"), ("Website", "https://example.org/?token=secret"),
                            ("Website", "file:///C:/windows"), ("Website", "https://example.org:8443/"),
                            ("Website", "https://localhost/"), ("Domain", "example.local"), ("Command", "calc.exe")]:
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                flowsint.entity(kind, value)

    def test_psl_uses_real_multi_label_and_private_suffixes_offline(self):
        with patch.object(flowsint.net, "get") as request:
            for host, expected in [("www.company.co.uk", "company.co.uk"),
                                   ("x.project.github.io", "project.github.io"), ("www.example.com.au", "example.com.au")]:
                rows, _ = flowsint.enrich("domain_root", flowsint.entity("Domain", host), 20, {})
                self.assertEqual(rows[0]["output"]["value"], expected)
            request.assert_not_called()

    def test_ipv6_cidr_sample_is_bounded_and_offline(self):
        with patch.object(flowsint.net, "get") as request:
            rows, checks = flowsint.enrich("cidr_addresses", flowsint.entity("CIDR", "2606:4700::/32"), 3, {})
            self.assertEqual(len(rows), 3)
            self.assertEqual(checks[0]["state"], "partial")
            self.assertIn("activity", rows[0]["attribution"])
            request.assert_not_called()

    def test_dns_partial_failure_keeps_a_record_and_does_not_invent_private_ip(self):
        responses = [{"state": "success", "records": [{"value": "1.1.1.1"}, {"value": "192.168.1.1"}],
                      "source": "Cloudflare DoH", "url": "https://cloudflare-dns.com/dns-query?name=example.org&type=A"},
                     {"state": "timeout", "records": [], "detail": "DNS transport timeout"}]
        with patch.object(flowsint.domain_enrichment, "dns_query", side_effect=responses):
            rows, checks = flowsint.enrich("domain_dns", flowsint.entity("Domain", "example.org"), 20, {})
        self.assertEqual([row["output"]["value"] for row in rows], ["1.1.1.1"])
        self.assertEqual(checks[-1]["state"], "timeout")

    def test_ripe_rejects_bad_schema_and_rate_limit_is_blocked(self):
        for response, state in [(SimpleNamespace(status=429, error="", text=""), "blocked"),
                                (SimpleNamespace(status=200, error="", text='{"status":"ok","data":[]}'), "error"),
                                (SimpleNamespace(status=0, error="timed out", text=""), "timeout")]:
            with patch.object(flowsint.net, "get", return_value=response), self.assertRaises(flowsint.SourceError) as raised:
                flowsint._ripe("network-info", "1.1.1.1")
            self.assertEqual(raised.exception.state, state)

    def test_website_branches_fetch_once_skip_unsafe_links_and_keep_tracker_uncertain(self):
        html = '<a href="/about">about</a><a href="javascript:alert(1)">bad</a><a href="https://example.org/?token=secret">secret</a><script>GTM-ABCDE G-ABCDEF UA-12345-1 ym(123456,"init",{})</script>'
        page = {"url": "https://example.org/", "_snapshot_html": html, "html_sha256": hashlib.sha256(html.encode()).hexdigest()}
        cache = {}
        with patch.object(flowsint.osint_contacts, "parse_public_page", return_value=page) as fetch:
            links, _ = flowsint.enrich("website_links", flowsint.entity("Website", page["url"]), 20, cache)
            trackers, _ = flowsint.enrich("website_trackers", flowsint.entity("Website", page["url"]), 20, cache)
            fetch.assert_called_once()
        self.assertEqual([row["output"]["value"] for row in links], ["https://example.org/about"])
        self.assertEqual(len(trackers), 4)
        self.assertTrue(all(row["certainty"] == "candidate" for row in trackers))

    def test_prefix_query_window_is_preserved_instead_of_claiming_current_announcement(self):
        data = {"query_starttime": "2026-09-29T08:00:00", "query_endtime": "2026-10-13T08:00:00",
                "prefixes": [{"prefix": "1.1.1.0/24", "timelines": [{"starttime": "2026-10-01T08:00:00", "endtime": "2026-10-02T08:00:00"}]}]}
        with patch.object(flowsint, "_ripe", return_value=(data, "https://stat.ripe.net/data/announced-prefixes/data.json")):
            rows, _ = flowsint.enrich("asn_prefixes", flowsint.entity("ASN", "AS13335"), 20, {})
        self.assertEqual(rows[0]["metadata"]["query_endtime"], data["query_endtime"])
        self.assertEqual(rows[0]["metadata"]["visible_periods"][0]["endtime"], "2026-10-02T08:00:00")
        self.assertIn("current announcement", rows[0]["attribution"])
        report = {"query": "AS13335", "kind": "asn", "flow": {"definition": {"input_kind": "ASN"}},
                  "sections": {"enrichments": rows}}
        graph = evidence_graph.build_graph(report)
        cidr = next(node for node in graph["nodes"] if node["kind"] == "CIDR")
        self.assertEqual(cidr["properties"]["query_starttime"], data["query_starttime"])

    def test_flow_partial_data_exports_and_ai_evidence_share_typed_graph(self):
        flow = flowsint._flow("two branches", "IP", [("one", "ip_asn", "seed"), ("two", "ip_asn", "seed"),
                                                   ("prefixes", "asn_prefixes", "one")])
        calls = []
        def collect(name, item, limit, cache):
            calls.append(name)
            if name == "ip_asn":
                return [flowsint._relation(item, "ASN", "AS13335", "RoutingASN", "RIPE Stat", "https://stat.ripe.net/data/network-info/data.json")], []
            raise flowsint.SourceError("blocked", "RIPE Stat returned HTTP 429")
        with tempfile.TemporaryDirectory() as folder, patch.object(flowsint, "enrich", side_effect=collect):
            result = flowsint.run("1.1.1.1", flow, Path(folder))
            self.assertEqual(calls, ["ip_asn", "asn_prefixes"])
            self.assertEqual(result["flow"]["status"], "partial")
            self.assertTrue(result["flow"]["trace"][1]["reused"])
            self.assertIn("RoutingASN", Path(result["report_csv"]).read_text(encoding="utf-8-sig"))
            self.assertTrue(Path(result["graph_path"]).is_file())
            graph = result["relationship_graph"]
            self.assertTrue(any(edge["kind"] == "RoutingASN" and edge["source_urls"] for edge in graph["edges"]))
            self.assertFalse(any(node["kind"] == "Finding" for node in graph["nodes"]))
            self.assertFalse(any(node["kind"] == "HistoryEvent" for node in graph["nodes"]))
            self.assertTrue(any("AS13335" in row["text"] for row in ai_agents._evidence(result)))
            diagnostic = Path(result["diagnostics"]["trace_path"]).read_text()
            self.assertNotIn("1.1.1.1", diagnostic)
            self.assertNotIn("stat.ripe.net/data", diagnostic)

    def test_task_budget_preserves_inputs_and_marks_unexecuted_branches(self):
        flow = flowsint._flow("budget", "Domain", [("root", "domain_root", "seed"), ("web", "domain_website", "seed")])
        with tempfile.TemporaryDirectory() as folder:
            result = flowsint.run("www.example.org", flow, Path(folder), max_tasks=1)
        self.assertEqual(result["counts"]["flow_tasks"], 1)
        self.assertEqual(result["flow"]["trace"][-1]["state"], "skipped")
        self.assertEqual(result["flow"]["status"], "partial")

    def test_blocked_duplicate_requests_are_not_replayed_and_empty_dependency_is_not_an_error(self):
        flow = flowsint._flow("duplicate", "IP", [("one", "ip_asn", "seed"), ("two", "ip_asn", "seed")])
        with tempfile.TemporaryDirectory() as folder, patch.object(flowsint, "enrich", side_effect=flowsint.SourceError("blocked", "HTTP 429")) as collect:
            result = flowsint.run("1.1.1.1", flow, Path(folder))
            collect.assert_called_once()
            self.assertEqual(result["flow"]["status"], "blocked")
            self.assertTrue(result["flow"]["trace"][-1]["reused"])
        with tempfile.TemporaryDirectory() as folder, patch.object(flowsint, "enrich", return_value=([], [])):
            result = flowsint.run("1.1.1.1", flowsint.FLOWS["ip-network"], Path(folder))
            self.assertEqual(result["flow"]["status"], "empty")
            self.assertFalse(result["errors"])

    def test_native_catalog_matches_callable_python_enrichers(self):
        source = Path(__file__).parents[1].joinpath("rust-ui/src/enrichment.rs").read_text()
        for name in flowsint.FLOWS:
            self.assertIn('"' + name + '"', source)
        for name in flowsint.ENRICHERS:
            self.assertIn('"' + name + '"', source)


if __name__ == "__main__":
    unittest.main()
