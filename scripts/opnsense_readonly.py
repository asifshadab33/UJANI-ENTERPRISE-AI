#!/usr/bin/env python3
"""Read-only OPNsense posture probe using fixed, documented GET endpoints.

Only GET /api/core/system/status and GET /api/core/firmware/status are used.
The adapter never accesses firmware/info, firewall mutation routes, service
start/stop, rule changes, reboots, upgrades, or configuration writes.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 8
ALLOWED_SYSTEM_FIELDS = {
    "cpu", "memory", "disk", "uptime", "load_average",
    "product_name", "product_version", "os_version",
}
ALLOWED_FIRMWARE_FIELDS = {
    "status", "product_name", "product_version", "product_latest",
    "updates", "upgrade_needs_reboot",
}


class OPNsenseAdapterError(Exception):
    """A bounded, safe-to-display adapter error."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise OPNsenseAdapterError("redirects are disabled for the OPNsense adapter")


def validate_base_url(value: str, allow_http_local: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        raise OPNsenseAdapterError("base URL contains an invalid port or authority") from None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OPNsenseAdapterError("base URL must not contain credentials, query or fragment")
    if not parsed.hostname:
        raise OPNsenseAdapterError("base URL must include a hostname")
    if parsed.scheme != "https":
        local = {"localhost", "127.0.0.1", "::1"}
        if not (allow_http_local and parsed.scheme == "http" and parsed.hostname in local):
            raise OPNsenseAdapterError("HTTPS is required; HTTP is allowed only for explicit localhost testing")
    if ".." in parsed.path.split("/"):
        raise OPNsenseAdapterError("base URL path traversal is not permitted")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def reject_constant(value):
    raise OPNsenseAdapterError("non-finite JSON numeric constant is not permitted")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OPNsenseAdapterError("duplicate JSON object key is not permitted")
        result[key] = value
    return result


def build_opener(ca_bundle=None):
    context = ssl.create_default_context(cafile=ca_bundle)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        RejectRedirects(),
    )


def _fetch_json(opener, url, headers):
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except OPNsenseAdapterError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise OPNsenseAdapterError("OPNsense read-only request failed; check endpoint, credentials and TLS") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OPNsenseAdapterError("OPNsense response exceeds the 1 MiB limit")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError, OPNsenseAdapterError, RecursionError):
        raise OPNsenseAdapterError("OPNsense returned invalid JSON") from None
    if not isinstance(value, dict):
        raise OPNsenseAdapterError("OPNsense response must be a JSON object")
    return value


def _allowlisted_fields(payload, allowed):
    result = {}
    for key in allowed:
        value = payload.get(key)
        if isinstance(value, bool):
            result[key] = value
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            rendered = str(value)
            if len(rendered.encode("utf-8")) <= 128:
                result[key] = value
    return result


def fetch_posture(base_url: str, api_key: str, api_secret: str, *,
                  ca_bundle: str | None = None, allow_http_local: bool = False,
                  opener_factory=build_opener):
    base = validate_base_url(base_url, allow_http_local)
    if (not isinstance(api_key, str) or not api_key or len(api_key) > 512
            or not isinstance(api_secret, str) or not api_secret or len(api_secret) > 1024
            or any(char in api_key + api_secret for char in "\r\n")):
        raise OPNsenseAdapterError("OPNsense API key and secret must be bounded non-empty strings")
    token = base64.b64encode(f"{api_key}:{api_secret}".encode("utf-8")).decode("ascii")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {token}",
        "User-Agent": "UJANI-Enterprise-OPNsense-ReadOnly/1",
    }
    opener = opener_factory(ca_bundle)
    # Keep the endpoint allowlist literal and GET-only. In particular, do not
    # call /api/core/firmware/info or any POST/action endpoint.
    system = _fetch_json(opener, f"{base}/api/core/system/status", headers)
    firmware = _fetch_json(opener, f"{base}/api/core/firmware/status", headers)
    if "status" in firmware and firmware["status"] not in ("ok", "error"):
        raise OPNsenseAdapterError("OPNsense firmware status field is invalid")
    return {
        "schema_version": "1.0",
        "provider_id": "opnsense",
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "system": _allowlisted_fields(system, ALLOWED_SYSTEM_FIELDS),
        "firmware": _allowlisted_fields(firmware, ALLOWED_FIRMWARE_FIELDS),
        "read_only": True,
        "methods_used": ["GET", "GET"],
        "actions_performed": [],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="OPNsense base URL (HTTPS)")
    parser.add_argument("--ca-bundle", help="optional trusted CA bundle")
    parser.add_argument("--allow-http-local", action="store_true",
                        help="allow HTTP only for localhost/loopback test instances")
    args = parser.parse_args(argv)
    api_key = os.environ.get("UJANI_OPNSENSE_API_KEY")
    api_secret = os.environ.get("UJANI_OPNSENSE_API_SECRET")
    try:
        if api_key is None or api_secret is None:
            raise OPNsenseAdapterError("UJANI_OPNSENSE_API_KEY and UJANI_OPNSENSE_API_SECRET are required")
        result = fetch_posture(
            args.base_url, api_key, api_secret,
            ca_bundle=args.ca_bundle, allow_http_local=args.allow_http_local,
        )
    except OPNsenseAdapterError as exc:
        print(f"UJANI OPNsense adapter rejected request: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
