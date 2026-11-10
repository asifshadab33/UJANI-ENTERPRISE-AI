import json
import unittest

from scripts.misp_readonly import (
    MISPAdapterError,
    normalize_attribute,
    search_indicators,
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
    def __init__(self, pages):
        self.pages = list(pages)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if request.get_method() != "POST":
            raise AssertionError("MISP restSearch is a read-only search POST")
        return FakeResponse(self.pages.pop(0))


def attribute(value="198.51.100.7", **overrides):
    result = {
        "id": "42",
        "event_id": "7",
        "type": "ip-src",
        "category": "Network activity",
        "value": value,
        "to_ids": True,
        "timestamp": "1790000000",
        "comment": "test indicator",
        "distribution": "1",
        "Event": {"uuid": "event-uuid", "info": "test event"},
        "private_field": "must-not-leak",
        "data": "must-not-leak",
    }
    result.update(overrides)
    return result


class MISPReadOnlyAdapterTests(unittest.TestCase):
    def test_exact_indicator_lookup_uses_fixed_read_only_endpoint(self):
        fake = FakeOpener([{"response": {"Attribute": [attribute()]}}])
        result = search_indicators(
            "https://misp.example/", "api-key", "198.51.100.7",
            opener_factory=lambda ca: fake,
        )
        request, timeout = fake.requests[0]
        self.assertEqual(request.full_url, "https://misp.example/attributes/restSearch")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "api-key")
        self.assertEqual(timeout, 8)
        body = json.loads(request.data)
        self.assertEqual(body, {
            "returnFormat": "json",
            "value": "198.51.100.7",
            "limit": 50,
            "page": 1,
        })
        self.assertTrue(result["read_only"])
        self.assertEqual(result["actions_performed"], [])
        self.assertEqual(result["result_count"], 1)
        self.assertNotIn("private_field", result["results"][0])
        self.assertNotIn("data", result["results"][0])

    def test_pagination_is_bounded_and_stops_on_short_page(self):
        fake = FakeOpener([
            {"response": {"Attribute": [attribute("198.51.100.1")]}},
            {"response": {"Attribute": [attribute("198.51.100.2")]}},
            {"response": {"Attribute": []}},
        ])
        result = search_indicators(
            "https://misp.example", "api-key", "198.51.100.1",
            page_size=1, max_pages=5, opener_factory=lambda ca: fake,
        )
        self.assertEqual(result["result_count"], 2)
        self.assertEqual(len(fake.requests), 3)
        self.assertEqual(json.loads(fake.requests[2][0].data)["page"], 3)

    def test_unsupported_attribute_types_are_not_exported(self):
        self.assertIsNone(normalize_attribute(attribute(type="attachment")))
        self.assertIsNone(normalize_attribute(attribute(value={"nested": "data"})))

    def test_url_and_credentials_are_validated_before_network_access(self):
        fake = FakeOpener([])
        for url in (
            "http://misp.example",
            "https://user:secret@misp.example",
            "https://misp.example?key=secret",
            "https://misp.example/../admin",
            "https://misp.example:not-a-port",
        ):
            with self.subTest(url=url), self.assertRaises(MISPAdapterError):
                search_indicators(url, "api-key", "indicator", opener_factory=lambda ca: fake)
        with self.assertRaises(MISPAdapterError):
            search_indicators("https://misp.example", "", "indicator", opener_factory=lambda ca: fake)
        self.assertEqual(fake.requests, [])

    def test_local_http_requires_explicit_opt_in(self):
        fake = FakeOpener([{"response": {"Attribute": []}}])
        with self.assertRaises(MISPAdapterError):
            search_indicators("http://localhost:8080", "key", "x", opener_factory=lambda ca: fake)
        search_indicators(
            "http://localhost:8080", "key", "x", allow_http_local=True,
            opener_factory=lambda ca: fake,
        )
        self.assertEqual(fake.requests[0][0].full_url, "http://localhost:8080/attributes/restSearch")

    def test_query_and_pagination_bounds(self):
        fake = FakeOpener([])
        invalid = (
            ("", 50, 1),
            ("x" * 513, 50, 1),
            ("x", 0, 1),
            ("x", 101, 1),
            ("x", 10, 0),
            ("x", 10, 6),
        )
        for indicator, page_size, max_pages in invalid:
            with self.subTest(indicator_length=len(indicator), page_size=page_size, max_pages=max_pages):
                with self.assertRaises(MISPAdapterError):
                    search_indicators(
                        "https://misp.example", "key", indicator,
                        page_size=page_size, max_pages=max_pages,
                        opener_factory=lambda ca: fake,
                    )
        self.assertEqual(fake.requests, [])

    def test_malformed_attribute_is_rejected_without_dumping_source(self):
        fake = FakeOpener([{"response": {"Attribute": ["not-an-object"]}}])
        with self.assertRaises(MISPAdapterError):
            search_indicators(
                "https://misp.example", "key", "indicator",
                opener_factory=lambda ca: fake,
            )

    def test_tenant_unrelated_private_fields_never_escape_normalizer(self):
        normalized = normalize_attribute(attribute())
        self.assertEqual(normalized["provider_id"], "misp")
        self.assertEqual(normalized["data_classification"], "internal")
        self.assertNotIn("private_field", normalized)
        self.assertNotIn("data", normalized)
        self.assertNotIn("Tag", normalized)


if __name__ == "__main__":
    unittest.main()
