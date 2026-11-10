import base64
import json
import unittest

from scripts.opnsense_readonly import (
    OPNsenseAdapterError,
    fetch_posture,
    validate_base_url,
)


class FakeResponse:
    def __init__(self, value):
        self.payload = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.payload[:limit]


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if request.get_method() != "GET":
            raise AssertionError("OPNsense adapter must be GET-only")
        return FakeResponse(self.responses.pop(0))


class OPNsenseReadOnlyAdapterTests(unittest.TestCase):
    def test_only_two_fixed_get_endpoints_are_called(self):
        fake = FakeOpener([
            {
                "cpu": 12.5,
                "memory": 44,
                "uptime": 900,
                "private_users": ["must-not-export"],
                "config": {"password": "must-not-export"},
            },
            {
                "status": "ok",
                "product_name": "OPNsense",
                "product_version": "26.1",
                "product_latest": "26.1.1",
                "upgrade_needs_reboot": "0",
                "api_key": "must-not-export",
            },
        ])
        result = fetch_posture(
            "https://firewall.example", "key", "secret",
            opener_factory=lambda ca: fake,
        )
        self.assertEqual(
            [request.full_url for request, _ in fake.requests],
            [
                "https://firewall.example/api/core/system/status",
                "https://firewall.example/api/core/firmware/status",
            ],
        )
        self.assertTrue(all(request.get_method() == "GET" for request, _ in fake.requests))
        self.assertEqual(result["system"]["cpu"], 12.5)
        self.assertEqual(result["firmware"]["product_version"], "26.1")
        self.assertNotIn("private_users", result["system"])
        self.assertNotIn("config", result["system"])
        self.assertNotIn("api_key", result["firmware"])
        self.assertEqual(result["actions_performed"], [])
        self.assertTrue(result["read_only"])

    def test_basic_auth_is_header_only(self):
        fake = FakeOpener([{}, {"status": "ok"}])
        fetch_posture(
            "https://firewall.example", "reader-key", "reader-secret",
            opener_factory=lambda ca: fake,
        )
        expected = "Basic " + base64.b64encode(b"reader-key:reader-secret").decode("ascii")
        self.assertEqual(fake.requests[0][0].get_header("Authorization"), expected)
        self.assertNotIn("reader-secret", fake.requests[0][0].full_url)

    def test_https_is_required_except_explicit_localhost_test(self):
        with self.assertRaises(OPNsenseAdapterError):
            validate_base_url("http://firewall.example")
        with self.assertRaises(OPNsenseAdapterError):
            validate_base_url("http://10.0.0.1", allow_http_local=True)
        self.assertEqual(
            validate_base_url("http://localhost:8080", allow_http_local=True),
            "http://localhost:8080",
        )

    def test_credentials_and_url_are_validated_before_network_access(self):
        fake = FakeOpener([])
        for args in (
            ("https://user:pass@firewall.example", "key", "secret"),
            ("https://firewall.example?token=secret", "key", "secret"),
            ("https://firewall.example/../api", "key", "secret"),
            ("https://firewall.example:not-a-port", "key", "secret"),
            ("https://firewall.example", "", "secret"),
            ("https://firewall.example", "key", ""),
        ):
            with self.subTest(args=args), self.assertRaises(OPNsenseAdapterError):
                fetch_posture(*args, opener_factory=lambda ca: fake)
        self.assertEqual(fake.requests, [])

    def test_invalid_firmware_status_is_rejected(self):
        fake = FakeOpener([{}, {"status": {"nested": "unexpected"}}])
        with self.assertRaises(OPNsenseAdapterError):
            fetch_posture(
                "https://firewall.example", "key", "secret",
                opener_factory=lambda ca: fake,
            )

    def test_only_allowlisted_scalar_values_are_returned(self):
        fake = FakeOpener([
            {"cpu": {"processes": ["private"]}, "memory": "unknown", "disk": 70},
            {"status": "ok", "updates": 2, "mirror": "sensitive"},
        ])
        result = fetch_posture(
            "https://firewall.example", "key", "secret",
            opener_factory=lambda ca: fake,
        )
        self.assertNotIn("cpu", result["system"])
        self.assertEqual(result["system"]["memory"], "unknown")
        self.assertEqual(result["firmware"]["updates"], 2)
        self.assertNotIn("mirror", result["firmware"])


if __name__ == "__main__":
    unittest.main()
