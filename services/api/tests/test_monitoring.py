import unittest
from datetime import datetime, timezone

from app.monitoring import classify_snapshot, compact_snapshot, meaningful_changes, next_check_time, snapshot_hash


class DomainMonitoringTests(unittest.TestCase):
    def test_inactive_domain_is_classified_without_content_capture(self):
        snapshot = compact_snapshot({"records": {kind: [] for kind in ("A", "AAAA", "CNAME", "MX", "NS")}}, None, None)
        self.assertEqual(classify_snapshot(snapshot), "inactive")

    def test_known_parking_nameserver_is_conservatively_classified(self):
        snapshot = compact_snapshot({"records": {"A": ["203.0.113.4"], "NS": ["ns1.sedoparking.com"]}}, None, None)
        self.assertEqual(classify_snapshot(snapshot), "likely_parked")

    def test_activation_is_a_meaningful_change(self):
        inactive = compact_snapshot({"records": {}}, None, None)
        active = compact_snapshot({"records": {"A": ["1.1.1.1"], "NS": ["ns.example"]}}, None, {"sha256": "abc", "issuer": "test"})
        changes = meaningful_changes(inactive, active)
        self.assertIn("classification:inactive->active_infrastructure", changes)
        self.assertIn("dns:a", changes)
        self.assertIn("tls:certificate", changes)
        self.assertNotEqual(snapshot_hash(inactive), snapshot_hash(active))

    def test_scheduling_is_deterministic_and_never_below_minimum(self):
        now = datetime(2026, 7, 30, tzinfo=timezone.utc)
        first = next_check_time("monitor-1", 3600, now)
        self.assertEqual(first, next_check_time("monitor-1", 3600, now))
        self.assertGreaterEqual((first - now).total_seconds(), 900)


if __name__ == "__main__":
    unittest.main()
