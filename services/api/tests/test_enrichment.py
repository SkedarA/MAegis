import unittest
from datetime import datetime, timedelta, timezone

from app.enrichment import enrichment_signals, public_addresses, registration_date
from app.detection import Signal
from app.scoring import score_signals


class EnrichmentTests(unittest.TestCase):
    def test_public_address_policy_blocks_internal_destinations(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"):
            with self.assertRaises(ValueError):
                public_addresses([address])

    def test_public_address_policy_deduplicates(self):
        self.assertEqual(public_addresses(["1.1.1.1", "1.1.1.1"]), ["1.1.1.1"])

    def test_registration_date_reads_rdap_event(self):
        timestamp = registration_date({"events": [{"eventAction": "registration", "eventDate": "2026-07-01T10:00:00Z"}]})
        self.assertEqual(timestamp, datetime(2026, 7, 1, 10, tzinfo=timezone.utc))

    def test_enrichment_signals_are_explainable_and_bounded(self):
        now = datetime(2026, 7, 28, tzinfo=timezone.utc)
        dns = {"records": {"MX": ["10 mail.example.test"]}}
        rdap = {"events": [{"eventAction": "registration", "eventDate": (now - timedelta(days=4)).isoformat()}]}
        tls = {"not_before": (now - timedelta(days=2)).isoformat()}
        signals = enrichment_signals(dns, rdap, tls, now=now)
        self.assertEqual([signal.name for signal in signals], ["enrichment.mx_configured", "enrichment.just_registered", "enrichment.recent_certificate"])
        self.assertEqual(sum(signal.weight for signal in signals), 36)

    def test_registration_age_bands_are_distinct(self):
        now = datetime(2026, 7, 28, tzinfo=timezone.utc)
        for days, expected in ((2, "enrichment.just_registered"), (20, "enrichment.new_registration"), (60, "enrichment.recent_registration")):
            rdap = {"events": [{"eventAction": "registration", "eventDate": (now - timedelta(days=days)).isoformat()}]}
            self.assertEqual(enrichment_signals(None, rdap, None, now=now)[0].name, expected)

    def test_registry_wildcard_suppresses_lexical_false_positive(self):
        dns = {"registry_wildcard": {"matched_candidate": True, "query": "maegis-random.ph", "addresses": ["45.79.222.138"]}}
        signals = [Signal("exact_brand_nonofficial", 1, 38, "Exact brand outside allowlist"), *enrichment_signals(dns, None, None)]
        self.assertEqual(score_signals(signals).score, 0)


if __name__ == "__main__":
    unittest.main()
