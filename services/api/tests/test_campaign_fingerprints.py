import unittest

from app.campaign_intelligence.fingerprints import normalize_url_template, url_hostname


class CampaignFingerprintTests(unittest.TestCase):
    def test_path_values_are_generalized_but_parameter_names_remain(self):
        first = normalize_url_template("https://one.example/RO/login/918273?session=abc&email=x")
        second = normalize_url_template("https://two.example/ro/login/123456?email=y&session=def")
        self.assertEqual(first, "/ro/login/{integer}?email&session")
        self.assertEqual(first, second)

    def test_root_path_is_not_a_campaign_fingerprint(self):
        self.assertIsNone(normalize_url_template("https://example.com/"))

    def test_hostname_is_normalized_from_url(self):
        self.assertEqual(url_hostname("https://Login.Example/path"), "login.example")


if __name__ == "__main__":
    unittest.main()
