
import unittest

from src.ml_detector import predict_anomaly, MODEL_VERSION


class TestMLDetector(unittest.TestCase):
    def test_benign_sequence(self):
        result = predict_anomaly(["OTHER", "OTHER", "OTHER"])
        self.assertFalse(result["anomaly"])
        self.assertEqual(result["score"], 0.0)

    def test_risky_order(self):
        result = predict_anomaly([
            "SENSITIVE_READ",
            "STAGE_DATA",
            "OUTBOUND_TRANSFER",
        ])
        self.assertTrue(result["anomaly"])
        self.assertGreaterEqual(result["score"], 0.9)

    def test_risky_order_with_noise(self):
        result = predict_anomaly([
            "SENSITIVE_READ",
            "OTHER",
            "STAGE_DATA",
            "OTHER",
            "OUTBOUND_TRANSFER",
        ])
        self.assertTrue(result["anomaly"])

    def test_reordered_sequence(self):
        result = predict_anomaly([
            "OUTBOUND_TRANSFER",
            "STAGE_DATA",
            "SENSITIVE_READ",
        ])
        self.assertFalse(result["anomaly"])

    def test_unseen_role_uses_safe_fallback(self):
        result = predict_anomaly(["OTHER", "UNKNOWN_ROLE"])
        self.assertIsNone(result["score"])
        self.assertFalse(result["anomaly"])

    def test_empty_sequence(self):
        result = predict_anomaly([])
        self.assertFalse(result["anomaly"])
        self.assertEqual(result["score"], 0.0)

    def test_model_version_present(self):
        self.assertEqual(
            predict_anomaly(["OTHER"])["model_version"],
            MODEL_VERSION,
        )


if __name__ == "__main__":
    unittest.main()