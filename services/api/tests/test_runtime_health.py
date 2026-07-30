import unittest
from datetime import datetime, timedelta, timezone

from app.runtime_health import worker_is_fresh


class RuntimeHealthTests(unittest.TestCase):
    def test_recent_heartbeat_is_fresh(self):
        now = datetime(2026, 7, 28, 12, tzinfo=timezone.utc)
        self.assertTrue(worker_is_fresh(now - timedelta(seconds=30), 60, now=now))

    def test_stale_future_and_missing_heartbeats_fail_closed(self):
        now = datetime(2026, 7, 28, 12, tzinfo=timezone.utc)
        self.assertFalse(worker_is_fresh(now - timedelta(seconds=61), 60, now=now))
        self.assertFalse(worker_is_fresh(now + timedelta(seconds=1), 60, now=now))
        self.assertFalse(worker_is_fresh(None, 60, now=now))


if __name__ == "__main__":
    unittest.main()
