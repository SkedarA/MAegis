import unittest

from app.correlation import correlation_reason, evidence_correlation_keys


class CorrelationTests(unittest.TestCase):
    def test_extracts_network_registry_and_certificate_keys(self):
        rows = [
            {"evidence_type": "dns", "payload": {"records": {"A": ["203.0.113.10"], "NS": ["NS1.EXAMPLE.NET."]}}},
            {"evidence_type": "rdap", "payload": {"nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}]}},
            {"evidence_type": "tls_certificate", "payload": {"fingerprint": "ABC123"}},
            {"evidence_type": "source_observation", "payload": {"page_asn": "AS64500", "favicon_hash": "42"}},
        ]
        keys = evidence_correlation_keys(rows)
        self.assertTrue({"a:203.0.113.10", "ns:ns1.example.net", "tls:abc123", "asn:as64500", "favicon:42"}.issubset(keys))
        self.assertEqual(correlation_reason("tls:abc123"), "Shared TLS certificate: abc123")


if __name__ == "__main__":
    unittest.main()
