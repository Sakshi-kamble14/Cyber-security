import unittest
from ml.feature_extraction import FEATURE_NAMES, InvalidURLError, extract_features, parse_url

# Illustrative sample URLs. None is ever fetched.
LEGIT_LOOKING = ["https://www.wikipedia.org/wiki/Phishing", "https://github.com/"]
MALFORMED = ["", "   ", "ftp://example.com", "javascript:alert(1)", "http://", "http://exa mple.com",
             "http://-bad-.com", "http://nodot", "x" * 3000, None, 123]


class FeatureExtractionTests(unittest.TestCase):
    def test_vector_complete_and_ordered(self):
        f = extract_features("https://www.wikipedia.org/wiki/Phishing")
        self.assertEqual(list(f.keys()), FEATURE_NAMES)
        self.assertTrue(all(isinstance(v, (int, float)) for v in f.values()))

    def test_legit_looking_has_no_strong_indicators(self):
        for url in LEGIT_LOOKING:
            with self.subTest(url=url):
                f = extract_features(url)
                self.assertEqual((f["has_ip_address"], f["has_at_symbol"], f["is_shortener"]), (0, 0, 0))

    def test_ip_host_detected(self):
        self.assertEqual(extract_features("http://192.168.10.5/secure/login.php")["has_ip_address"], 1)
        self.assertEqual(extract_features("http://3232235777/x")["has_ip_address"], 1)

    def test_credentials_stripped_from_normalized_url(self):
        p = parse_url("http://user:pw@evil.example.com/login")
        self.assertNotIn("pw", p.normalized)
        self.assertNotIn("@", p.normalized)
        self.assertEqual(extract_features("http://user@evil.example.com/login")["has_at_symbol"], 1)

    def test_subdomains_keywords_tld(self):
        f = extract_features("http://paypal.com.account-verify.example.tk/update?id=1")
        self.assertGreaterEqual(f["num_subdomains"], 2)
        self.assertGreaterEqual(f["num_suspicious_keywords"], 2)
        self.assertEqual(f["has_suspicious_tld"], 1)
        self.assertEqual(f["num_hyphens_host"], 1)

    def test_two_part_tld(self):
        self.assertEqual(extract_features("https://www.example.co.uk/")["num_subdomains"], 1)

    def test_port_and_shortener(self):
        self.assertEqual(extract_features("http://example.com:8081/verify")["has_nonstandard_port"], 1)
        self.assertEqual(extract_features("https://example.com:443/")["has_nonstandard_port"], 0)
        self.assertEqual(extract_features("http://bit.ly/abc123")["is_shortener"], 1)

    def test_https_is_a_feature_not_a_verdict(self):
        f = extract_features("https://secure-login-verify.example.xyz/")
        self.assertEqual(f["is_https"], 1)
        self.assertGreaterEqual(f["num_suspicious_keywords"], 2)

    def test_scheme_less_url_accepted(self):
        self.assertEqual(parse_url("example.com/path").scheme, "http")

    def test_malformed_urls_rejected(self):
        for bad in MALFORMED:
            with self.subTest(bad=str(bad)[:30]):
                with self.assertRaises(InvalidURLError):
                    extract_features(bad)


if __name__ == "__main__":
    unittest.main()
