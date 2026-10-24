"""
Test Suite for ScamShield AI URL Phishing ML Integration
Tests feature extraction consistency, model loading, in-memory inference speed,
held-out test accuracy on real samples, and FastAPI endpoint schemas.
"""

import time
import unittest
from fastapi.testclient import TestClient

from main import app
from url_features import extract_url_features, FEATURE_COLUMNS, NUMERIC_FEATURES
from url_model_service import get_url_model_service


class TestUrlMlIntegration(unittest.TestCase):
    """Verifies end-to-end Machine Learning URL scanner pipeline and endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()
        cls.url_service = get_url_model_service()
        cls.url_service.load_model()
        # Warmup Loky / multi-threading / scikit-learn
        cls.url_service.predict_url("https://example.com/warmup")
        cls.client.post("/api/url-scan", json={"url": "https://example.com/warmup", "fast_scan_only": True})

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_url_features_schema_compliance(self):
        """Verifies that extract_url_features returns all 11 required columns matching dataset."""
        features = extract_url_features("https://www.example.com/path?arg=1&val=2")
        self.assertIsInstance(features, dict)
        for col in FEATURE_COLUMNS:
            self.assertIn(col, features, f"Missing feature column: {col}")

        # Check types
        self.assertIsInstance(features["url_length"], int)
        self.assertIsInstance(features["num_dots"], int)
        self.assertIsInstance(features["has_https"], int)
        self.assertIsInstance(features["has_ip"], int)
        self.assertIsInstance(features["num_subdirs"], int)
        self.assertIsInstance(features["num_params"], int)
        self.assertIsInstance(features["suspicious_words"], int)
        self.assertIsInstance(features["tld"], str)
        self.assertIsInstance(features["special_char_count"], int)
        self.assertIsInstance(features["digits_count"], int)
        self.assertIsInstance(features["entropy"], float)

    def test_url_model_service_loaded(self):
        """Verifies that the URL classifier pipeline and metadata are successfully loaded."""
        self.assertTrue(self.url_service.is_loaded)
        self.assertIsNotNone(self.url_service.pipeline)
        self.assertEqual(self.url_service.classifier_name, "HistGradientBoosting (Balanced)")

    def test_ml_predictions_benign_urls(self):
        """Verifies that legitimate everyday websites are correctly classified as benign."""
        benign_samples = [
            "https://www.google.com",
            "https://www.wikipedia.org",
            "https://github.com/explore",
            "https://stackoverflow.com/questions"
        ]
        for url in benign_samples:
            res = self.url_service.predict_url(url)
            self.assertTrue(res["available"])
            self.assertFalse(res["is_phishing"], f"Benign URL was falsely predicted as phishing: {url}")
            self.assertEqual(res["predicted_class"], "Benign")
            self.assertLess(res["phishing_probability"], 0.40, f"Phishing probability too high for {url}")

    def test_ml_predictions_phishing_urls(self):
        """Verifies that confirmed phishing URLs are classified as phishing with high probability."""
        phishing_samples = [
            "http://78.51.220.142:8080/sshd",
            "http://forum.uk.securebankinggroup.com/107519/8af662/phish",
            "https://logiin--metsa-autho.webflow.io/",
            "http://paypal.verification-portal.badsite.com/login"
        ]
        for url in phishing_samples:
            res = self.url_service.predict_url(url)
            self.assertTrue(res["available"])
            self.assertTrue(res["is_phishing"], f"Phishing URL was not caught: {url}")
            self.assertEqual(res["predicted_class"], "Phishing")
            self.assertGreater(res["phishing_probability"], 0.60, f"Phishing probability too low for {url}")

    def test_ml_inference_speed(self):
        """Verifies that in-memory ML prediction runs without external network latency (<250ms)."""
        t0 = time.perf_counter()
        for _ in range(50):
            self.url_service.predict_url("https://example.com/test-path-speed")
        avg_duration_ms = (time.perf_counter() - t0) * 1000 / 50
        self.assertLess(avg_duration_ms, 250.0, f"Inference took too long: {avg_duration_ms:.2f}ms per call")

    def test_api_health_endpoint_url_model(self):
        """Verifies /api/health reports the URL phishing model status."""
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("url_model_loaded"))
        self.assertIn("HistGradientBoosting", data.get("url_classifier", ""))

    def test_api_url_model_info_endpoint(self):
        """Verifies /api/url-model/info returns dataset info, license, and training schema."""
        resp = self.client.get("/api/url-model/info")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("dataset_verification", data)
        self.assertIn("CC0", data["dataset_verification"]["dataset_license"])
        self.assertEqual(data["dataset_verification"]["total_rows"], 160064)
        self.assertIn("feature_schema", data)

    def test_api_url_model_metrics_endpoint(self):
        """Verifies /api/url-model/metrics returns held-out test set performance."""
        resp = self.client.get("/api/url-model/metrics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("heldout_test_metrics", data)
        metrics = data["heldout_test_metrics"]
        self.assertGreaterEqual(metrics["test_f1"], 0.95)
        self.assertLessEqual(metrics["test_fpr"], 0.03)

    def test_api_fast_scan_only(self):
        """Verifies that fast_scan_only=True returns results in milliseconds without live network calls."""
        # Initial warm-up call so internal feature extractors and threadpools are initialized
        self.client.post("/api/url-scan", json={"url": "https://www.example.com", "fast_scan_only": True})
        t0 = time.perf_counter()
        resp = self.client.post("/api/url-scan", json={"url": "https://www.google.com", "fast_scan_only": True})
        elapsed_ms = (time.perf_counter() - t0) * 1000

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["classification"], "Low Risk")
        self.assertIn("ml_prediction", data)
        self.assertIsNotNone(data["ml_prediction"])
        self.assertFalse(data["ml_prediction"]["is_phishing"])
        self.assertLess(elapsed_ms, 500.0, f"Fast scan took {elapsed_ms:.1f}ms, expected < 500ms")


if __name__ == "__main__":
    unittest.main()
