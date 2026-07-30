import unittest

from app.campaign_intelligence.fingerprints import certificate_issuance_profile, domain_lure_template, normalize_url_template, page_structure_fingerprint, rdap_registration_profile, url_hostname


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

    def test_registration_profile_groups_a_batch_without_pii(self):
        payload = {"registrar": "Example Registrar", "events": [{"eventAction": "registration", "eventDate": "2026-07-30T10:23:00Z"}], "status": ["active"]}
        same_batch = {**payload, "events": [{"eventAction": "registration", "eventDate": "2026-07-30T10:59:00Z"}]}
        self.assertEqual(rdap_registration_profile(payload), rdap_registration_profile(same_batch))

    def test_certificate_profile_requires_issuance_context(self):
        payload = {"issuer": "CN=Example CA", "not_before": "2026-07-30T10:01:00Z", "not_after": "2026-10-28T10:01:00Z", "sans": ["one.example"]}
        self.assertIsNotNone(certificate_issuance_profile(payload))
        self.assertIsNone(certificate_issuance_profile({"issuer": "CN=Example CA"}))

    def test_multi_brand_lure_template_abstracts_brand(self):
        self.assertEqual(domain_lure_template("login-emag-secure.example", ["emag", "bt"]), "login{brand}secure")
        self.assertEqual(domain_lure_template("login-bt-secure.example", ["emag", "bt"]), "login{brand}secure")

    def test_form_structure_is_order_independent(self):
        first = page_structure_fingerprint({"forms": [{"method": "post", "input_types": ["password", "email"], "action": "https://collect.example/send"}]})
        second = page_structure_fingerprint({"forms": [{"method": "POST", "input_types": ["email", "password"], "action": "https://collect.example/other"}]})
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
