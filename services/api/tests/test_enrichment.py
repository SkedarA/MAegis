import unittest
from datetime import datetime, timedelta, timezone

from app.enrichment import enrichment_signals, public_addresses, registration_date


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
        self.assertEqual([signal.name for signal in signals], ["enrichment.mx_configured", "enrichment.new_registration", "enrichment.recent_certificate"])
        self.assertEqual(sum(signal.weight for signal in signals), 29)


if __name__ == "__main__":
    unittest.main()
