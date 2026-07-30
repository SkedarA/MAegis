import unittest
import sys
import types
from unittest.mock import patch

try:
    import httpx  # noqa: F401
except ModuleNotFoundError:  # local lightweight test environments may omit declared runtime dependencies
    httpx_stub = types.ModuleType("httpx")
    httpx_stub.AsyncClient = object
    sys.modules["httpx"] = httpx_stub

try:
    import pydantic_settings  # noqa: F401
except ModuleNotFoundError:
    config_stub = types.ModuleType("app.config")
    config_stub.get_settings = lambda: None
    sys.modules["app.config"] = config_stub

from app.connectors import RDAPRegistrationConnector, URLScanConnector


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "results": [
                {
                    "task": {
                        "uuid": "scan-1",
                        "url": "https://fancourier-ro.tracking-portal.click/",
                        "time": "2026-07-23T08:08:03Z",
                    },
                    "page": {
                        "url": "https://tracking.fancourier-ro.lol/verify",
                        "domain": "tracking.fancourier-ro.lol",
                        "title": "Verify",
                        "ip": "47.79.98.250",
                    },
                    "verdicts": {"overall": {"malicious": False, "score": 0}},
                }
            ]
        }


class FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url, params):
        self.url = url
        self.params = params
        return FakeResponse()


class URLScanConnectorTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.connectors.httpx.AsyncClient", FakeClient)
    async def test_normalizes_submitted_and_effective_domains_with_checkpointing(self):
        connector = URLScanConnector()
        observations, checkpoint = await connector.fetch("fancourier", {})
        self.assertEqual(
            [item.domain for item in observations],
            ["fancourier-ro.tracking-portal.click", "tracking.fancourier-ro.lol"],
        )
        self.assertTrue(all(item.payload["scan_url"].startswith("https://urlscan.io/result/") for item in observations))
        replay, _ = await connector.fetch("fancourier", checkpoint)
        self.assertEqual(replay, [])


async def fake_registered_rdap(domain):
    return {
        "handle": domain.upper(),
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2026-07-28T08:00:00Z"}],
        "nameservers": [],
        "entities": [],
        "raw": {},
    }


async def fake_missing_rdap(domain):
    return {"status": "not_found"}


async def fake_old_rdap(domain):
    return {
        "handle": domain.upper(),
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "nameservers": [],
        "entities": [],
        "raw": {},
    }


async def fake_undated_rdap(domain):
    return {"handle": domain.upper(), "status": ["active"], "events": [], "nameservers": [], "entities": [], "raw": {}}


class RDAPRegistrationConnectorTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.connectors.fetch_rdap", fake_registered_rdap)
    async def test_emits_registered_domain_even_without_dns(self):
        observations, checkpoint = await RDAPRegistrationConnector().fetch("acmme.ro", {})
        self.assertEqual([item.domain for item in observations], ["acmme.ro"])
        self.assertEqual(observations[0].payload["rdap"]["events"][0]["eventAction"], "registration")
        self.assertLessEqual(observations[0].payload["fresh_registration"]["age_days"], 90)
        self.assertEqual(checkpoint["last_domain"], "acmme.ro")

    @patch("app.connectors.fetch_rdap", fake_missing_rdap)
    async def test_skips_unregistered_candidate(self):
        observations, _ = await RDAPRegistrationConnector().fetch("acmme.ro", {})
        self.assertEqual(observations, [])

    @patch("app.connectors.fetch_rdap", fake_old_rdap)
    async def test_skips_registered_domain_outside_freshness_window(self):
        observations, checkpoint = await RDAPRegistrationConnector(max_age_days=90).fetch("acmme.ro", {})
        self.assertEqual(observations, [])
        self.assertEqual(checkpoint["result"], "outside_freshness_window")

    @patch("app.connectors.fetch_rdap", fake_undated_rdap)
    async def test_skips_domain_without_registration_date(self):
        observations, checkpoint = await RDAPRegistrationConnector().fetch("acmme.ro", {})
        self.assertEqual(observations, [])
        self.assertEqual(checkpoint["result"], "registration_date_missing")


if __name__ == "__main__":
    unittest.main()
