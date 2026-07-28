import socket
import unittest
from unittest.mock import patch

from capture import validate_target


class CaptureSafetyTests(unittest.TestCase):
    def test_rejects_file_scheme(self):
        with self.assertRaises(ValueError):
            validate_target("file:///etc/passwd")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            validate_target("https://user:pass@example.com")

    @patch("capture.socket.getaddrinfo")
    def test_rejects_private_target(self, lookup):
        lookup.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with self.assertRaises(ValueError):
            validate_target("https://example.test")

    @patch("capture.socket.getaddrinfo")
    def test_accepts_public_https_target(self, lookup):
        lookup.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        self.assertEqual(validate_target("https://example.com"), "https://example.com")

