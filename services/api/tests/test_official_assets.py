import unittest

from app.official_assets import normalize_official_asset


class OfficialAssetTests(unittest.TestCase):
    def test_normalizes_url_and_idna(self):
        self.assertEqual(normalize_official_asset("https://MıDORI.example/path", "domain"), "xn--mdori-n4a.example")

    def test_wildcard_is_stored_canonically(self):
        self.assertEqual(normalize_official_asset("*.Login.Example.COM.", "wildcard"), "*.login.example.com")

    def test_plain_value_can_be_declared_as_wildcard(self):
        self.assertEqual(normalize_official_asset("service.example", "wildcard"), "*.service.example")

    def test_rejects_unknown_asset_type(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            normalize_official_asset("example.com", "network")


if __name__ == "__main__":
    unittest.main()
