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

from app.connectors import URLScanConnector


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


if __name__ == "__main__":
    unittest.main()
