import unittest
from types import SimpleNamespace
from app.candidate_schedule import fetch_candidate_batch
from app.detection import GeneratedCandidate


class FlakyConnector:
    name = "dns_candidates"
    version = "test"

    def __init__(self):
        self.calls = []

    async def fetch(self, domain, checkpoint):
        self.calls.append(domain)
        if len(self.calls) == 1:
            raise TimeoutError("temporary resolver timeout")
        observation = SimpleNamespace(
            domain=domain,
            source=self.name,
            raw_hash=f"hash-{domain}",
            payload={"queried_domain": domain},
        )
        return [observation], checkpoint


class WorkerPollingTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_timeout_does_not_block_later_candidates(self):
        variants = [
            GeneratedCandidate("acm-a.com", "character_omission", "acm-a"),
            GeneratedCandidate("acm-b.com", "character_omission", "acm-b"),
        ]
        connector = FlakyConnector()
        collected, failures = await fetch_candidate_batch(connector, variants)

        self.assertEqual(connector.calls, ["acm-a.com", "acm-b.com"])
        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0][0].domain, "acm-b.com")
        self.assertEqual(len(failures), 1)
        self.assertIn("acm-a.com", failures[0])


if __name__ == "__main__":
    unittest.main()
