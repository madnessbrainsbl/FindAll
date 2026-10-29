"""Offline numerical invariants, missing-data semantics and product integration."""
import csv
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jf import analytics, ai_agents
from jobfind import main


def fixture():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    return [{"id": str(i), "actor": "actor" + str(i % 2), "timestamp": (start + timedelta(hours=i//2)).isoformat(),
             "value": i, "second": 2*i+1, "constant": 7, "latitude": 55+i%2*.001, "longitude": 37+i%2*.001,
             "text": "This is a synthetic shared narrative in a fictional public dataset.", "label": "A" if i % 2 else "B",
             "source_url": "https://example.org/" + str(i), "source": "Fixture",
             "relation_source": "actor" + str(i % 2), "relation_target": "shared"} for i in range(100)]


class AnalyticsTests(unittest.TestCase):
    def test_statistics_and_missing_values_are_not_zero(self):
        rows, _ = analytics.normalize([{"value": x, "second": x*2, "constant": 7} for x in range(10)] + [{"text": "unknown measurement"}])
        result = analytics.describe(rows)["fields"]["value"]
        self.assertEqual(result["n"], 10)
        self.assertEqual(result["missing"], 1)
        self.assertEqual(result["mean"], 4.5)
        self.assertAlmostEqual(result["variance_sample"], 55/6)
        pairs = analytics.correlations(rows)["pairs"]
        self.assertEqual(len(pairs), 1)
        self.assertAlmostEqual(pairs[0]["pearson"], 1)
        self.assertLess(pairs[0]["q_bh"], .001)

    def test_failed_observations_duplicates_and_collection_times(self):
        data = {"sections": {"web": [{"text": "one", "url": "https://example.org/one", "observed_at": "2025-01-01T00:00:00Z"}]*2 +
                                    [{"text": "failure", "status": "blocked", "value": 999},
                                     {"text": "bad", "timestamp": "not a date", "latitude": 999, "longitude": 20}]}}
        rows, coverage = analytics.normalize(data)
        self.assertEqual(len(rows), 2)
        self.assertEqual(coverage["failed_records"], 1)
        self.assertEqual(coverage["duplicates"], 1)
        self.assertFalse(rows[0]["timestamp"])
        self.assertEqual(coverage["invalid_times"], 1)
        self.assertIsNone(rows[1]["latitude"])
        measurements, _ = analytics.normalize([{"value": 7}] * 10)
        self.assertEqual(analytics.describe(measurements)["fields"]["value"]["n"], 10)

    def test_temporal_counts_and_lexical_signals(self):
        rows, _ = analytics.normalize(fixture())
        result = analytics.temporal(rows, 12)
        self.assertEqual(result["dated"], 100)
        self.assertEqual(sum(result["counts"]), 100)
        self.assertEqual(result["stl"]["status"], "ok")
        self.assertEqual(analytics.texts(rows)["similar_pairs"][0]["cosine"], 1)

    def test_communities_and_geo_do_not_claim_identity(self):
        rows, _ = analytics.normalize(fixture())
        network = analytics.networks(rows, None)
        self.assertEqual(network["nodes"], 3)
        self.assertEqual(network["edges"], 2)
        self.assertEqual(network["girvan_newman"]["status"], "ok")
        points = analytics.spatial(rows, 1)
        self.assertEqual(points["clusters"], 1)
        self.assertEqual(points["located"], 100)
        self.assertEqual(points["moran"]["status"], "ok")
        self.assertEqual(points, analytics.spatial(rows, 1))

    def test_forecast_and_cusum_on_a_structural_break(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        events = [{"id": str(i)+"-"+str(j), "timestamp": (start+timedelta(hours=i)).isoformat()}
                  for i in range(60) for j in range(1 if i < 20 else 5+i%3)]
        rows, _ = analytics.normalize(events)
        result = analytics.temporal(rows, 12)
        self.assertEqual(result["forecast"]["status"], "ok")
        self.assertEqual(len(result["forecast"]["interval_95"]), 5)
        self.assertTrue(result["cusum"]["alarms"])
        self.assertEqual(result["cusum"]["alarms"][0]["direction"], "increase")

    def test_isolation_pca_tsne_and_labelled_classifiers(self):
        rows, _ = analytics.normalize(fixture())
        result = analytics.multivariate(rows)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["n"], 100)
        self.assertEqual(len(result["pca"]), 100)
        self.assertEqual(result["tsne"]["status"], "ok")
        self.assertEqual(result["classification"]["test"], 30)
        self.assertEqual(set(result["classification"]["models"]), {"random_forest", "gradient_boosting"})

    def test_insufficient_data_and_invalid_parameters(self):
        result = analytics.analyze([])
        self.assertEqual(result["status"], "empty")
        self.assertTrue(all(m["status"] == "insufficient_data" for m in result["methods"].values()))
        with self.assertRaises(ValueError):
            analytics.analyze([], radius_km=float("nan"))
        self.assertIsNone(analytics.number(float("inf")))
        self.assertIsNone(analytics.number(True))
        extreme = analytics.analyze([{"id": str(i), "value": 1e308} for i in range(10)])
        self.assertEqual(extreme["status"], "partial")
        json.dumps(extreme, allow_nan=False)

    def test_cli_exports_ai_evidence_escape_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.json"
            source.write_text(json.dumps([{"value": i, "text": "<script>alert(1)</script>"} for i in range(10)]))
            original = hashlib.sha256(source.read_bytes()).hexdigest()
            stdout = io.StringIO()
            with patch("jf.apex_network.route", side_effect=AssertionError("Statistics must be offline")), redirect_stdout(stdout):
                self.assertEqual(main(["--out", str(root / "out"), "statistics", "--path", str(source)]), 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["artifacts"][0]["sha256"], original)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)
            self.assertTrue(Path(result["report_json"]).is_file())
            for name in ("analytics_json", "analytics_html", "analytics_markdown", "markdown"):
                self.assertTrue(Path(result["exported_paths"][name]).is_file())
            page = Path(result["exported_paths"]["analytics_html"]).read_text(encoding="utf-8")
            self.assertNotIn("<script>", page)
            evidence = [row for row in ai_agents._evidence(result) if row["section"] == "statistics"]
            self.assertTrue(evidence)
            self.assertTrue(all(r["attribution"].startswith("interpretation") for r in evidence))
            with Path(result["report_csv"]).open(encoding="utf-8-sig", newline="") as stream:
                self.assertIn("statistics", {r["section"] for r in csv.DictReader(stream)})
            recalculated = analytics.analyze(result)
            self.assertEqual(recalculated["coverage"]["retained"], 10)
            self.assertEqual(recalculated["methods"]["descriptive"]["fields"]["value"]["mean"], 4.5)
            self.assertTrue(any(n["kind"] == "StatisticalCalculation" for n in result["relationship_graph"]["nodes"]))

    def test_imported_relation_graph_is_candidate_and_dataset_scoped(self):
        from jf import evidence_graph
        row = {"relation_source": "actor", "relation_target": "publisher", "sha256": "a"*64,
               "source_url": "https://example.org/evidence"}
        graph = evidence_graph.build_graph({"query": "fixture", "sections": {"analysis_observations": [row]}})
        relation = next(e for e in graph["edges"] if e["kind"] == "ImportedRelation")
        self.assertEqual(relation["certainty"], "candidate")
        self.assertEqual(relation["evidence_hashes"], ["a"*64])
        self.assertEqual(relation["source_urls"], [row["source_url"]])
        other = evidence_graph.build_graph({"query": "fixture", "sections": {"analysis_observations": [{**row, "sha256": "b"*64}]}})
        self.assertNotEqual({n["id"] for n in graph["nodes"] if n["kind"] == "ImportedEntity"},
                            {n["id"] for n in other["nodes"] if n["kind"] == "ImportedEntity"})

    def test_saved_dossier_is_a_new_version_without_stale_ai(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dossier.json"
            source.write_text(json.dumps({"query": "fixture", "kind": "domain", "scope": "domain",
                "observed_at": "2025-01-01T00:00:00Z", "sections": {"web": [{"url": "https://example.org/", "text": "Observed public source"}]},
                "ai_analysis": {"answer": "Old answer must not be recycled"}}))
            before = source.read_bytes()
            result = analytics.run(source, root / "out")
            self.assertNotEqual(Path(result["report_json"]), source)
            self.assertEqual(source.read_bytes(), before)
            self.assertNotIn("ai_analysis", result)
            self.assertEqual(result["sections"]["web"][0]["url"], "https://example.org/")
            self.assertEqual(result["analytics"]["methods"]["temporal"]["status"], "insufficient_data")

    def test_import_rejects_invalid_structure_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text('{"command":"do not run"}')
            with self.assertRaises(ValueError): analytics.load(path)
            path.write_text('{"sections":{},"artifacts":"invalid"}')
            with self.assertRaises(ValueError): analytics.load(path)
            path.write_text("[1,2]")
            with patch.object(analytics, "MAX_BYTES", 2):
                with self.assertRaises(ValueError): analytics.load(path)
        rows, coverage = analytics.normalize([{"value": i} for i in range(5010)])
        self.assertEqual(len(rows), 5000)
        self.assertEqual(coverage["truncated"], 10)


if __name__ == "__main__":
    unittest.main()
