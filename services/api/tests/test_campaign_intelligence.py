import unittest

from app.campaign_intelligence.rules import PATTERN_CATALOG, relation_rule


class CampaignIntelligenceRuleTests(unittest.TestCase):
    def test_exact_certificate_is_a_strong_link(self):
        result = relation_rule("presents_certificate", "certificate", "abcdef")
        self.assertEqual(result.weight, 35)
        self.assertTrue(result.strong)

    def test_shared_provider_ip_cannot_link_campaign(self):
        result = relation_rule("resolves_to", "ip", "1.1.1.1", {"provider": "Cloudflare"})
        self.assertEqual(result.weight, 0)
        self.assertFalse(result.strong)

    def test_cname_is_context_not_campaign_proof(self):
        result = relation_rule("aliases_to", "domain", "tenant.pages.dev")
        self.assertEqual(result.weight, 5)
        self.assertFalse(result.strong)

    def test_patterns_require_correlated_signals(self):
        self.assertGreaterEqual(len(PATTERN_CATALOG), 3)
        self.assertTrue(all(item["minimum_independent_signals"] >= 2 for item in PATTERN_CATALOG))


if __name__ == "__main__":
    unittest.main()
