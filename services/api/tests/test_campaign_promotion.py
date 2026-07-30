import unittest

from app.campaign_intelligence.rules import promotion_eligible


class CampaignPromotionTests(unittest.TestCase):
    def test_automatic_promotion_requires_all_high_confidence_gates(self):
        self.assertTrue(promotion_eligible(.75, .85, .65))
        self.assertFalse(promotion_eligible(.74, .95, .95))
        self.assertFalse(promotion_eligible(.95, .84, .95))
        self.assertFalse(promotion_eligible(.95, .95, .64))


if __name__ == "__main__":
    unittest.main()
