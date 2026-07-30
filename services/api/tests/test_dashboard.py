import unittest
from datetime import datetime, timedelta, timezone

from app.dashboard import build_dashboard_summary


class DashboardTests(unittest.TestCase):
    def test_separates_incidents_by_client_and_window(self):
        now = datetime(2026, 7, 30, tzinfo=timezone.utc)
        rows = [
            {"brand_id": "a", "severity": "critical", "status": "new", "risk_score": 91, "assigned_to": None, "created_at": now - timedelta(days=1)},
            {"brand_id": "a", "severity": "high", "status": "investigating", "risk_score": 72, "assigned_to": "analyst@example.com", "created_at": now - timedelta(days=2)},
            {"brand_id": "b", "severity": "low", "status": "closed", "risk_score": 18, "assigned_to": None, "created_at": now - timedelta(days=40)},
        ]
        result = build_dashboard_summary(rows, [{"id": "a", "name": "Client A"}, {"id": "b", "name": "Client B"}], days=30, now=now)
        self.assertEqual(result["totals"]["incidents"], 2)
        self.assertEqual(result["totals"]["unassigned"], 1)
        self.assertEqual(result["by_brand"][0]["name"], "Client A")
        self.assertEqual(result["by_brand"][0]["open"], 2)
        self.assertEqual(next(item for item in result["by_brand"] if item["brand_id"] == "b")["total"], 0)

    def test_all_time_window_includes_historical_cases(self):
        now = datetime(2026, 7, 30, tzinfo=timezone.utc)
        rows = [{"brand_id": "a", "severity": "medium", "status": "closed", "risk_score": 50, "assigned_to": None, "created_at": now - timedelta(days=1000)}]
        result = build_dashboard_summary(rows, [{"id": "a", "name": "Client A"}], days=0, now=now)
        self.assertEqual(result["totals"]["incidents"], 1)
        self.assertEqual(result["by_severity"]["medium"], 1)


if __name__ == "__main__":
    unittest.main()
