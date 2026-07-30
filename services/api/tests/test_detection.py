import unittest

from app.detection import analyze_domain, damerau_levenshtein, generate_candidate_variants, generate_candidates, normalize_domain
from app.scoring import score_signals


class DetectionTests(unittest.TestCase):
    def test_normalizes_url_and_idna(self):
        ascii_domain, unicode_domain = normalize_domain("https://mıdori-login.com/path")
        self.assertTrue(ascii_domain.startswith("xn--"))
        self.assertEqual(unicode_domain, "mıdori-login.com")

    def test_damerau_transposition(self):
        self.assertEqual(damerau_levenshtein("acme", "amce"), 1)

    def test_official_domain_is_suppressed(self):
        signals = analyze_domain("acme.com", "acme.com", "Acme", ["acme.com"])
        result = score_signals(signals)
        self.assertEqual(result.score, 0)

    def test_official_subdomain_is_suppressed(self):
        signals = analyze_domain("login.acme.com", "login.acme.com", "Acme", ["acme.com"])
        self.assertEqual(score_signals(signals).score, 0)

    def test_brand_token_and_login_raise_score(self):
        signals = analyze_domain("acme-login.com", "acme-login.com", "Acme", ["acme.com"])
        names = {signal.name for signal in signals}
        self.assertIn("brand_token", names)
        self.assertIn("suspicious_tokens", names)
        self.assertGreaterEqual(score_signals(signals).score, 30)

    def test_unicode_confusable(self):
        signals = analyze_domain("xn--80ak6aa92e.com", "аррӏе.com", "apple", ["apple.com"])
        self.assertTrue({"mixed_script", "unicode_confusable"} & {signal.name for signal in signals})

    def test_exact_brand_on_unapproved_tld_is_detected(self):
        signals = analyze_domain("acme.shop", "acme.shop", "Acme", ["acme.com"])
        self.assertIn("exact_brand_nonofficial", {signal.name for signal in signals})
        self.assertGreaterEqual(score_signals(signals).score, 35)

    def test_shared_hosting_brand_login_is_high_risk(self):
        signals = analyze_domain("bitdefender-login.pages.dev", "bitdefender-login.pages.dev", "Bitdefender", ["bitdefender.com"])
        names = {signal.name for signal in signals}
        self.assertTrue({"brand_token", "suspicious_tokens", "deceptive_subdomain", "shared_hosting_impersonation"}.issubset(names))
        self.assertGreaterEqual(score_signals(signals).score, 70)

    def test_brand_bearing_tracking_subdomain_is_detected(self):
        domain = "fancourier-ro.tracking-portal.click"
        signals = analyze_domain(domain, domain, "FAN Courier", ["fancourier.ro"])
        names = {signal.name for signal in signals}
        self.assertTrue({"brand_token", "suspicious_tokens", "deceptive_subdomain"}.issubset(names))
        self.assertGreaterEqual(score_signals(signals).score, 70)

    def test_candidate_generation_is_bounded_and_unique(self):
        candidates = generate_candidates("Acme", limit=40)
        self.assertLessEqual(len(candidates), 40)
        self.assertEqual(len(candidates), len(set(candidates)))
        self.assertIn("acme-login.com", candidates)

    def test_candidate_generation_covers_fresh_registration_patterns(self):
        variants = generate_candidate_variants("Acme", tlds=("com", "ro"), limit=500)
        by_domain = {item.domain: item.mutation for item in variants}
        self.assertEqual(by_domain["acme.ro"], "tld_swap")
        self.assertEqual(by_domain["amce.com"], "adjacent_transposition")
        self.assertEqual(by_domain["accme.com"], "character_duplication")
        self.assertEqual(by_domain["acme-payment.ro"], "brand_plus_keyword")

    def test_brand_keywords_feed_candidate_generation(self):
        variants = generate_candidate_variants("Acme", tlds=("ro",), keywords=("delivery",), limit=100)
        domains = {item.domain for item in variants}
        self.assertIn("acme-delivery.ro", domains)
        self.assertIn("delivery-acme.ro", domains)

    def test_default_budget_remains_mutation_diverse(self):
        variants = generate_candidate_variants("Bitdefender", limit=250)
        mutation_types = {item.mutation for item in variants}
        self.assertTrue({"character_omission", "character_duplication", "adjacent_transposition", "keyboard_substitution"}.issubset(mutation_types))

    def test_dnstwist_style_families_and_tld_diversity_are_bounded(self):
        variants = generate_candidate_variants("Acme", tlds=("com", "ro", "net"), limit=120)
        mutation_types = {item.mutation for item in variants}
        suffixes = {item.domain.rsplit(".", 1)[-1] for item in variants}
        self.assertTrue({"ascii_homoglyph", "vowel_substitution", "prefix_addition", "suffix_addition", "pluralization"}.issubset(mutation_types))
        self.assertEqual(suffixes, {"com", "ro", "net"})
        self.assertEqual(len(variants), len({item.domain for item in variants}))

    def test_unicode_homograph_candidates_are_emitted_as_valid_idna(self):
        variants = generate_candidate_variants("Acme", tlds=("com",), limit=500)
        homographs = [item for item in variants if item.mutation == "unicode_homoglyph"]
        self.assertTrue(homographs)
        self.assertTrue(all(item.domain.startswith("xn--") for item in homographs))
        self.assertTrue(all(item.unicode_label for item in homographs))
        self.assertTrue(all(item.evidence().get("unicode_label") for item in homographs))

    def test_default_suffixes_cover_modern_abuse_surfaces(self):
        variants = generate_candidate_variants("Acme", limit=100)
        exact_suffixes = {item.domain.rsplit(".", 1)[-1] for item in variants if item.mutation == "tld_swap"}
        self.assertTrue({"ro", "com", "xyz", "click", "store", "live"}.issubset(exact_suffixes))


if __name__ == "__main__":
    unittest.main()
