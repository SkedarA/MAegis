import unittest

from datetime import datetime, timedelta, timezone

from app.campaign_intelligence.rules import PATTERN_CATALOG, rarity_factor, relation_rule, score_direct_link


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

    def test_popular_indicators_are_downweighted(self):
        self.assertEqual(rarity_factor(2, 1000), 1)
        self.assertLess(rarity_factor(500, 1000), .2)

    def test_single_family_cannot_form_campaign(self):
        now = datetime.now(timezone.utc)
        signals = [{"relation_type": "presents_certificate", "degree": 2, "total_domains": 100}]
        result = score_direct_link(signals, now, now + timedelta(days=30))
        self.assertFalse(result.admitted)
        self.assertEqual(result.independent_families, 1)

    def test_independent_rare_and_temporal_signals_are_admitted(self):
        now = datetime.now(timezone.utc)
        signals = [
            {"relation_type": "presents_certificate", "degree": 2, "total_domains": 100},
            {"relation_type": "uses_nameserver", "degree": 2, "total_domains": 100},
        ]
        result = score_direct_link(signals, now, now + timedelta(hours=12))
        self.assertTrue(result.admitted)
        self.assertGreaterEqual(result.independent_families, 3)
        self.assertGreaterEqual(result.score, 55)

    def test_old_relationships_decay(self):
        now = datetime.now(timezone.utc)
        fresh = score_direct_link([{"relation_type": "presents_certificate", "degree": 2, "total_domains": 100, "age_days": 1}], now, now)
        old = score_direct_link([{"relation_type": "presents_certificate", "degree": 2, "total_domains": 100, "age_days": 365}], now, now)
        self.assertGreater(fresh.family_scores["certificate"], old.family_scores["certificate"])


if __name__ == "__main__":
    unittest.main()
