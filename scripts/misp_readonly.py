#!/usr/bin/env python3
"""Read-only MISP indicator lookup using the documented attributes/restSearch API.

The adapter sends a bounded search request only. It never creates, edits,
publishes, deletes, or synchronises MISP data. The API key is supplied via
UJANI_MISP_API_KEY and is never included in URLs or output.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_QUERY_BYTES = 512
MAX_PAGE_SIZE = 100
MAX_PAGES = 5
TIMEOUT_SECONDS = 8
MAX_RESULTS = MAX_PAGE_SIZE * MAX_PAGES
ALLOWED_TYPES = {
    "md5", "sha1", "sha256", "sha512", "ip-src", "ip-dst",
    "domain", "hostname", "url", "email-src", "email-dst",
}


class MISPAdapterError(Exception):
    """A bounded, safe-to-display connector error."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise MISPAdapterError("redirects are disabled for the MISP adapter")


def validate_base_url(value: str, allow_http_local: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        raise MISPAdapterError("base URL contains an invalid port or authority") from None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise MISPAdapterError("base URL must not contain credentials, query or fragment")
    if not parsed.hostname:
        raise MISPAdapterError("base URL must include a hostname")
    if parsed.scheme != "https":
        local = {"localhost", "127.0.0.1", "::1"}
        if not (allow_http_local and parsed.scheme == "http" and parsed.hostname in local):
            raise MISPAdapterError("HTTPS is required; HTTP is allowed only for explicit localhost testing")
    if ".." in parsed.path.split("/"):
        raise MISPAdapterError("base URL path traversal is not permitted")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def reject_constant(value: str):
    raise MISPAdapterError("non-finite JSON numeric constant is not permitted")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MISPAdapterError("duplicate JSON object key is not permitted")
        result[key] = value
    return result


def build_opener(ca_bundle: str | None = None):
    context = ssl.create_default_context(cafile=ca_bundle)
    # Do not inherit HTTP(S)_PROXY from the environment: API keys must not be
    # sent through an ambient proxy that the administrator did not configure.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        RejectRedirects(),
    )


def _decode_response(raw: bytes):
    if len(raw) > MAX_RESPONSE_BYTES:
        raise MISPAdapterError("MISP response exceeds the 1 MiB limit")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError, MISPAdapterError, RecursionError):
        raise MISPAdapterError("MISP returned invalid JSON") from None


def _request_page(opener, url: str, api_key: str, indicator: str,
                  page: int, page_size: int):
    body = json.dumps({
        "returnFormat": "json",
        "value": indicator,
        "limit": page_size,
        "page": page,
    }, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": api_key,
            "User-Agent": "UJANI-Enterprise-MISP-ReadOnly/1",
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except MISPAdapterError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise MISPAdapterError("MISP indicator lookup failed; check endpoint, credentials and TLS") from None
    return _decode_response(raw)


def _extract_attributes(payload):
    if isinstance(payload, dict):
        response = payload.get("response", payload)
        if isinstance(response, dict):
            attributes = response.get("Attribute", response.get("attributes", []))
        elif isinstance(response, list):
            attributes = response
        else:
            attributes = []
    elif isinstance(payload, list):
        attributes = payload
    else:
        raise MISPAdapterError("MISP response has an unsupported structure")
    if not isinstance(attributes, list):
        raise MISPAdapterError("MISP attribute result is not a list")
    return attributes


def _bounded_text(value, limit: int):
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    text = str(value)
    if len(text.encode("utf-8")) > limit:
        return None
    return text


def normalize_attribute(attribute):
    if not isinstance(attribute, dict):
        raise MISPAdapterError("MISP returned a malformed attribute")
    attr_type = _bounded_text(attribute.get("type"), 64)
    value = _bounded_text(attribute.get("value"), MAX_QUERY_BYTES)
    if attr_type not in ALLOWED_TYPES or value is None:
        # Unsupported types and malformed values are not exported to UJANI.
        return None
    event = attribute.get("Event")
    event_info = _bounded_text(event.get("info"), 256) if isinstance(event, dict) else None
    result = {
        "provider_id": "misp",
        "attribute_id": _bounded_text(attribute.get("id"), 64),
        "event_id": _bounded_text(attribute.get("event_id"), 64),
        "event_uuid": _bounded_text(event.get("uuid"), 64) if isinstance(event, dict) else None,
        "event_info": event_info,
        "type": attr_type,
        "value": value,
        "category": _bounded_text(attribute.get("category"), 96),
        "to_ids": attribute.get("to_ids") if isinstance(attribute.get("to_ids"), bool) else None,
        "timestamp": _bounded_text(attribute.get("timestamp"), 32),
        "first_seen": _bounded_text(attribute.get("first_seen"), 32),
        "last_seen": _bounded_text(attribute.get("last_seen"), 32),
        "comment": _bounded_text(attribute.get("comment"), 256),
        "distribution": _bounded_text(attribute.get("distribution"), 8),
        "data_classification": "internal",
    }
    return {key: val for key, val in result.items() if val is not None}


def search_indicators(base_url: str, api_key: str, indicator: str, *,
                      page_size: int = 50, max_pages: int = 3,
                      ca_bundle: str | None = None, allow_http_local: bool = False,
                      opener_factory=build_opener):
    base = validate_base_url(base_url, allow_http_local)
    if not isinstance(api_key, str) or not api_key or len(api_key) > 4096 or any(c in api_key for c in "\r\n"):
        raise MISPAdapterError("MISP API key must be a non-empty bounded string")
    if not isinstance(indicator, str) or not indicator.strip() or len(indicator.encode("utf-8")) > MAX_QUERY_BYTES:
        raise MISPAdapterError("indicator must be a non-empty string up to 512 UTF-8 bytes")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise MISPAdapterError("page_size must be between 1 and 100")
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PAGES:
        raise MISPAdapterError("max_pages must be between 1 and 5")

    opener = opener_factory(ca_bundle)
    endpoint = f"{base}/attributes/restSearch"
    results = []
    for page in range(1, max_pages + 1):
        payload = _request_page(opener, endpoint, api_key, indicator.strip(), page, page_size)
        attributes = _extract_attributes(payload)
        if len(attributes) > page_size:
            raise MISPAdapterError("MISP returned more attributes than the requested page limit")
        for attribute in attributes:
            normalized = normalize_attribute(attribute)
            if normalized is not None:
                results.append(normalized)
                if len(results) >= MAX_RESULTS:
                    break
        if len(attributes) < page_size or len(results) >= MAX_RESULTS:
            break
    return {
        "schema_version": "1.0",
        "provider_id": "misp",
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "query": indicator.strip(),
        "result_count": len(results),
        "results": results,
        "read_only": True,
        "actions_performed": [],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="MISP base URL (HTTPS)")
    parser.add_argument("--indicator", required=True, help="exact indicator value to look up")
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--max-pages", type=int, default=3)
    parser.add_argument("--ca-bundle", help="optional trusted CA bundle")
    parser.add_argument("--allow-http-local", action="store_true",
                        help="allow HTTP only for localhost/loopback test instances")
    args = parser.parse_args(argv)
    api_key = os.environ.get("UJANI_MISP_API_KEY")
    try:
        if api_key is None:
            raise MISPAdapterError("UJANI_MISP_API_KEY is required")
        result = search_indicators(
            args.base_url, api_key, args.indicator,
            page_size=args.page_size, max_pages=args.max_pages,
            ca_bundle=args.ca_bundle, allow_http_local=args.allow_http_local,
        )
    except MISPAdapterError as exc:
        print(f"UJANI MISP adapter rejected request: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
