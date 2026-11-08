import base64
import json
import unittest
from urllib.request import Request

from scripts.malcolm_readonly import (
    MalcolmAdapterError,
    fetch_status,
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
            raise AssertionError("adapter must use GET only")
        return FakeResponse(self.responses.pop(0))


class MalcolmReadOnlyAdapterTests(unittest.TestCase):
    def healthy_responses(self):
        return [
            {"ping": "pong"},
            {
                "opensearch": True,
                "pcap_monitor": True,
                "logstash_lumberjack": True,
                "logstash_pipelines": True,
                "dashboards": True,
            },
            {
                "version": "26.09.0",
                "opensearch": {
                    "version": {"number": "2.14.0"},
                    "health": {"status": "green"},
                    "cluster_name": "must-not-be-exported",
                },
                "machine": "must-not-be-exported",
            },
        ]

    def test_only_fixed_read_only_get_endpoints_are_called(self):
        fake = FakeOpener(self.healthy_responses())
        result = fetch_status(
            "https://malcolm.example/",
            opener_factory=lambda ca: fake,
        )
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(result["malcolm_version"], "26.09.0")
        self.assertEqual(result["opensearch_health"], "green")
        self.assertNotIn("machine", result)
        self.assertEqual(
            [request.full_url for request, _ in fake.requests],
            [
                "https://malcolm.example/mapi/ping",
                "https://malcolm.example/mapi/ready",
                "https://malcolm.example/mapi/version",
            ],
        )
        self.assertTrue(all(request.get_method() == "GET" for request, _ in fake.requests))

    def test_missing_required_service_means_degraded_not_healthy(self):
        responses = self.healthy_responses()
        responses[1].pop("pcap_monitor")
        fake = FakeOpener(responses)
        result = fetch_status("https://malcolm.example", opener_factory=lambda ca: fake)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["missing_required_services"], ["pcap_monitor"])

    def test_http_requires_explicit_localhost_override(self):
        with self.assertRaises(MalcolmAdapterError):
            validate_base_url("http://malcolm.example")
        with self.assertRaises(MalcolmAdapterError):
            validate_base_url("http://10.0.0.2", allow_http_local=True)
        self.assertEqual(
            validate_base_url("http://localhost:9443", allow_http_local=True),
            "http://localhost:9443",
        )

    def test_url_userinfo_query_and_fragment_are_rejected(self):
        for value in (
            "https://user:pass@malcolm.example",
            "https://malcolm.example?token=secret",
            "https://malcolm.example#fragment",
            "https://malcolm.example/../admin",
        ):
            with self.subTest(value=value), self.assertRaises(MalcolmAdapterError):
                validate_base_url(value)

    def test_credentials_are_sent_only_as_basic_auth_header(self):
        fake = FakeOpener(self.healthy_responses())
        fetch_status(
            "https://malcolm.example",
            username="reader",
            password="secret",
            opener_factory=lambda ca: fake,
        )
        expected = "Basic " + base64.b64encode(b"reader:secret").decode("ascii")
        self.assertEqual(fake.requests[0][0].get_header("Authorization"), expected)
        self.assertNotIn("secret", fake.requests[0][0].full_url)

    def test_invalid_readiness_shape_is_rejected(self):
        fake = FakeOpener([{"ping": "pong"}, {"opensearch": "yes"}])
        with self.assertRaises(MalcolmAdapterError):
            fetch_status("https://malcolm.example", opener_factory=lambda ca: fake)

    def test_ping_mismatch_stops_before_other_endpoints(self):
        fake = FakeOpener([{"ping": "not-pong"}])
        with self.assertRaises(MalcolmAdapterError):
            fetch_status("https://malcolm.example", opener_factory=lambda ca: fake)
        self.assertEqual(len(fake.requests), 1)


if __name__ == "__main__":
    unittest.main()
