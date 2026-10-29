"""Real local model inference and numerical ground-truth fixtures."""
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from jf import analytics
from jf import analytics_models as models


def bearings_fixture(ranges=False):
    target_lat, target_lon = .01, .01
    rows = []
    for i, (lat, lon) in enumerate(((0, 0), (0, .02), (.02, 0), (.02, .02))):
        a, b, dl = math.radians(lat), math.radians(target_lat), math.radians(target_lon-lon)
        bearing = math.degrees(math.atan2(math.sin(dl)*math.cos(b), math.cos(a)*math.sin(b)-math.sin(a)*math.cos(b)*math.cos(dl))) % 360
        hav = math.sin((b-a)/2)**2+math.cos(a)*math.cos(b)*math.sin(dl/2)**2
        row = {"id": "station-"+str(i), "target_id": "synthetic beacon", "observer_latitude": lat,
               "observer_longitude": lon, "source_url": "https://example.org/station/"+str(i),
               "source": "Synthetic calibrated observation"}
        if ranges:
            row.update(range_m=2*6371008.8*math.asin(math.sqrt(hav)), range_error_m=5)
        else:
            row.update(bearing_deg=bearing, bearing_error_deg=.5)
        rows.append(row)
    return rows


def kriging_fixture():
    return [{"id": "field-"+str(i), "latitude": 55+(i//3)*.01, "longitude": 37+(i%3)*.01,
             "value": float(i%3+2*(i//3)), "source": "Synthetic measured field"} for i in range(9)]


class ModelTests(unittest.TestCase):
    def test_projection_round_trip_at_dateline(self):
        coordinates = np.array([[10, 179.9], [10.1, -179.9], [9.9, 179.95]])
        points = models.project(coordinates, 10, 180)
        recovered = models.unproject(points, 10, 180)
        self.assertTrue(np.allclose(coordinates, recovered, atol=1e-8))

    def test_bearing_triangulation_known_location(self):
        rows, _ = analytics.normalize(bearings_fixture())
        result = models.triangulation(rows)
        self.assertEqual(result["status"], "ok")
        target = result["targets"][0]
        self.assertAlmostEqual(target["latitude"], .01, places=5)
        self.assertAlmostEqual(target["longitude"], .01, places=5)
        self.assertTrue(all(0 < axis < 100 for axis in target["ellipse_95_semi_axes_m"]))
        self.assertEqual(target["input_refs"], [0, 1, 2, 3])

    def test_range_multilateration_and_inconsistent_bearings(self):
        rows, _ = analytics.normalize(bearings_fixture(ranges=True))
        target = models.triangulation(rows)["targets"][0]
        self.assertEqual(target["status"], "ok")
        self.assertAlmostEqual(target["latitude"], .01, places=5)
        bad = bearings_fixture()
        bad[0]["bearing_deg"] += 35
        rows, _ = analytics.normalize(bad)
        self.assertEqual(models.triangulation(rows)["targets"][0]["status"], "partial")

    def test_missing_errors_and_parallel_geometry_are_not_locations(self):
        bad = bearings_fixture()
        for row in bad: row.pop("bearing_error_deg")
        rows, _ = analytics.normalize(bad)
        result = models.triangulation(rows)
        self.assertEqual(result["invalid_measurements"], 4)
        self.assertFalse(result["targets"])
        parallel = bearings_fixture()
        for row in parallel: row["bearing_deg"] = 90
        rows, _ = analytics.normalize(parallel)
        result = models.triangulation(rows)["targets"][0]
        self.assertEqual(result["status"], "insufficient_data")
        self.assertNotIn("latitude", result)

    def test_kriging_interpolates_corner_measurements_inside_hull(self):
        rows, _ = analytics.normalize(kriging_fixture())
        result = models.kriging(rows)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["distinct_locations"], 9)
        self.assertTrue(result["points"])
        self.assertTrue(all(p["variance"] >= 0 and 54.999 <= p["latitude"] <= 55.021 for p in result["points"]))
        self.assertTrue(all(36.999 <= p["longitude"] <= 37.021 for p in result["points"]))
        constant, _ = analytics.normalize([{**r, "value": 1} for r in kriging_fixture()])
        self.assertEqual(models.kriging(constant)["status"], "insufficient_data")

    def test_umap_preserves_row_references_and_seed(self):
        rows, _ = analytics.normalize([{"id": str(i), "value": i, "other": i%3} for i in range(16)])
        one = models.umap_projection(rows, {})
        two = models.umap_projection(rows, {})
        self.assertEqual(one["status"], "ok")
        self.assertEqual(one, two)
        self.assertEqual([p["ref"] for p in one["spaces"]["numeric"]["points"]], list(range(16)))

    def test_lstm_trains_without_future_leakage_and_exports_safe_weights(self):
        counts = [2+i%4 for i in range(160)]
        counts[-8:] = [50]*8
        with tempfile.TemporaryDirectory() as directory:
            result = models.lstm_autoencoder({"counts": counts}, directory)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["training_bins"], [0, 96])
            self.assertEqual(result["calibration_bins"], [96, 128])
            self.assertEqual(result["test_bins"], [128, 160])
            self.assertTrue(any(s["candidate_anomaly"] for s in result["scores"] if s["end_bin"] >= 155))
            path = Path(result["weights"]["path"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), result["weights"]["sha256"])
            from safetensors.torch import load_file
            self.assertIn("encoder.weight_ih_l0", load_file(path))
        self.assertEqual(models.lstm_autoencoder({"counts": [2]*160})["status"], "insufficient_data")

    @unittest.skipUnless((models.BERT_DIR / "findall-model.json").is_file(), "Pinned local model not installed")
    def test_real_bert_multilingual_inference_is_offline(self):
        rows, _ = analytics.normalize([
            {"text": "A cat is sitting on the mat."},
            {"text": "Кот сидит на коврике."},
            {"text": "The company published its annual financial report."}])
        with patch("requests.sessions.Session.request", side_effect=AssertionError("No dataset network requests")):
            result = models.bert(rows)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["architecture"], "BertModel")
        vectors = np.array([r["vector"] for r in result["embeddings"]])
        self.assertEqual(vectors.shape, (3, 384))
        self.assertTrue(np.allclose(np.linalg.norm(vectors, axis=1), 1, atol=1e-5))
        self.assertGreater(vectors[0] @ vectors[1], vectors[0] @ vectors[2])

    def test_incomplete_and_tampered_model_is_not_loaded(self):
        rows, _ = analytics.normalize([{"text": "First example sentence"}, {"text": "Second example sentence"}])
        with tempfile.TemporaryDirectory() as directory, patch.object(models, "BERT_DIR", Path(directory)):
            self.assertEqual(models.bert(rows)["status"], "unavailable")
            (Path(directory)/"findall-model.json").write_text(json.dumps({"repository": models.BERT_REPO,
                "revision": "wrong", "files": {}}))
            with self.assertRaises(ValueError): models.bert(rows)

    def test_markdown_exports_estimates_without_executing_target_markup(self):
        result = {"status": "ok", "coverage": {"retained": 4}, "versions": {}, "parameters": {}, "methods": {
            "triangulation": {"status": "ok", "targets": [{"target_id": "<script>alert(1)</script>",
                "status": "ok", "latitude": .01, "longitude": .01, "ellipse_95_semi_axes_m": [10, 20]}]}}}
        text = analytics.summary(result)
        self.assertIn("0.010000, 0.010000", text)
        self.assertIn("Conditional 95%", text)
        self.assertNotIn("<script>", text)


if __name__ == "__main__":
    unittest.main()
