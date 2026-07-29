import unittest

from app.detection import Signal
from app.incident_policy import should_create_incident, source_signals


class IncidentPolicyTests(unittest.TestCase):
    def test_weak_shared_hosting_match_is_observation_only(self):
        signals = [
            Signal("brand_token", 1, 22, "brand token"),
            Signal("deceptive_subdomain", 1, 30, "subdomain"),
            Signal("shared_hosting_impersonation", 1, 18, "shared host"),
        ]
        self.assertFalse(should_create_incident("emag", signals, 70))

    def test_lure_on_shared_hosting_is_queued(self):
        signals = [
            Signal("brand_token", 1, 22, "brand token"),
            Signal("suspicious_tokens", 1, 20, "portal"),
            Signal("shared_hosting_impersonation", 1, 18, "shared host"),
        ]
        self.assertTrue(should_create_incident("sameday", signals, 60))

    def test_ambiguous_brand_requires_high_intent_signal(self):
        weak = [Signal("brand_token", 1, 22, "brand token"), Signal("deceptive_subdomain", 1, 30, "subdomain")]
        exact = weak + [Signal("exact_brand_nonofficial", 1, 38, "exact registration")]
        self.assertFalse(should_create_incident("electrica", weak, 52))
        self.assertTrue(should_create_incident("electrica", exact, 90))

    def test_public_malicious_verdict_is_explicit_signal(self):
        signals = source_signals({"verdicts": {"overall": {"malicious": True}}})
        self.assertEqual([signal.name for signal in signals], ["threat_feed_verdict"])
        self.assertEqual(source_signals({"verdicts": {"overall": {"malicious": False}}}), [])

    def test_fresh_registration_qualifies_ambiguous_brand(self):
        signals = [
            Signal("brand_token", 1, 22, "brand token"),
            Signal("enrichment.just_registered", 1, 22, "registered today"),
        ]
        self.assertTrue(should_create_incident("electrica", signals, 45))


if __name__ == "__main__":
    unittest.main()
