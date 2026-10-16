"""Basic unit tests. Run from the project folder:  python -m unittest discover -s tests"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import joblib

from feature_extraction import FEATURE_NAMES, extract_features, features_to_dataframe, predict_url

MODEL_PATH = os.path.join(ROOT, "model", "phishing_model.joblib")


class TestFeatureExtraction(unittest.TestCase):
    def test_https_simple_url(self):
        f = extract_features("https://www.google.com")
        self.assertEqual(f["url_length"], len("https://www.google.com"))
        self.assertEqual(f["num_dots"], 2)
        self.assertEqual(f["num_hyphens"], 0)
        self.assertEqual(f["has_ip_address"], 0)
        self.assertEqual(f["has_at_symbol"], 0)
        self.assertEqual(f["uses_https"], 1)

    def test_ip_address_hostname(self):
        self.assertEqual(extract_features("http://192.168.1.1/login")["has_ip_address"], 1)
        self.assertEqual(extract_features("http://192.168.1.1:8080/login")["has_ip_address"], 1)

    def test_domain_is_not_ip(self):
        self.assertEqual(extract_features("http://www.example.com/1.2.3.4")["has_ip_address"], 0)

    def test_at_symbol_and_hyphens(self):
        f = extract_features("http://secure-login-bank.com@evil.com")
        self.assertEqual(f["has_at_symbol"], 1)
        self.assertEqual(f["num_hyphens"], 2)
        self.assertEqual(f["uses_https"], 0)

    def test_url_without_scheme(self):
        f = extract_features("  example.com  ")
        self.assertEqual(f["url_length"], len("example.com"))
        self.assertEqual(f["uses_https"], 0)

    def test_dataframe_column_order(self):
        df = features_to_dataframe(["https://a.com", "http://b.com"])
        self.assertEqual(list(df.columns), FEATURE_NAMES)
        self.assertEqual(len(df), 2)


@unittest.skipUnless(os.path.exists(MODEL_PATH), "model not trained yet (run python train_model.py)")
class TestPrediction(unittest.TestCase):
    def test_prediction_output_format(self):
        model = joblib.load(MODEL_PATH)
        label, prob, features = predict_url(model, "https://www.python.org")
        self.assertIn(label, (0, 1))
        self.assertTrue(0.0 <= prob <= 1.0)
        self.assertEqual(set(features), set(FEATURE_NAMES))


if __name__ == "__main__":
    unittest.main()
