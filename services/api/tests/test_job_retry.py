import unittest

from app.job_retry import retry_delay_seconds


class JobRetryTests(unittest.TestCase):
    def test_exponential_backoff_is_bounded(self):
        self.assertEqual(retry_delay_seconds(1), 30)
        self.assertEqual(retry_delay_seconds(2), 60)
        self.assertEqual(retry_delay_seconds(5), 480)
        self.assertEqual(retry_delay_seconds(20), 900)


if __name__ == "__main__":
    unittest.main()
