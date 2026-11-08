#!/usr/bin/env python3
"""Read-only Malcolm health adapter.

Uses only Malcolm's documented GET /mapi/ping, /mapi/ready and /mapi/version
endpoints. It never queries packet/session data or invokes provider actions.
TLS verification is enabled by default; credentials are read only from the
MALCOLM_API_USERNAME and MALCOLM_API_PASSWORD environment variables.
"""
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
TIMEOUT_SECONDS = 5
REQUIRED_READY_SERVICES = (
    "opensearch",
    "pcap_monitor",
    "logstash_lumberjack",
    "logstash_pipelines",
)


class MalcolmAdapterError(Exception):
    pass


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise MalcolmAdapterError("redirects are disabled for the Malcolm adapter")


def validate_base_url(value, allow_http_local=False):
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise MalcolmAdapterError("base URL must not contain credentials, query or fragment")
    if not parsed.hostname:
        raise MalcolmAdapterError("base URL must include a hostname")
    if parsed.scheme != "https":
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if not (allow_http_local and parsed.scheme == "http" and parsed.hostname in local_hosts):
            raise MalcolmAdapterError("HTTPS is required; HTTP is allowed only for explicit localhost testing")
    if parsed.path and ".." in parsed.path.split("/"):
        raise MalcolmAdapterError("base URL path traversal is not permitted")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def reject_constant(value):
    raise MalcolmAdapterError("non-finite JSON numeric constant is not permitted")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MalcolmAdapterError("duplicate JSON object key is not permitted")
        result[key] = value
    return result


def build_opener(ca_bundle=None):
    context = ssl.create_default_context(cafile=ca_bundle)
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        RejectRedirects(),
    )


def fetch_json(opener, url, headers):
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except MalcolmAdapterError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError):
        raise MalcolmAdapterError("Malcolm endpoint request failed") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise MalcolmAdapterError("Malcolm response exceeds the 1 MiB limit")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, MalcolmAdapterError, RecursionError):
        raise MalcolmAdapterError("Malcolm endpoint returned invalid JSON") from None
    return value


def fetch_status(base_url, username=None, password=None, ca_bundle=None,
                 allow_http_local=False, opener_factory=build_opener):
    base = validate_base_url(base_url, allow_http_local)
    if (username is None) != (password is None):
        raise MalcolmAdapterError("both Malcolm username and password must be supplied together")
    if username is not None and (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username
        or not password
        or len(username) > 256
        or len(password) > 1024
    ):
        raise MalcolmAdapterError("Malcolm credentials must be non-empty strings within supported bounds")
    headers = {"Accept": "application/json", "User-Agent": "UJANI-Enterprise-Malcolm-ReadOnly/1"}
    if username is not None:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"

    opener = opener_factory(ca_bundle)
    ping = fetch_json(opener, f"{base}/mapi/ping", headers)
    if not isinstance(ping, dict) or ping.get("ping") != "pong":
        raise MalcolmAdapterError("Malcolm ping response did not match the documented contract")

    ready = fetch_json(opener, f"{base}/mapi/ready", headers)
    if not isinstance(ready, dict) or any(not isinstance(v, bool) for v in ready.values()):
        raise MalcolmAdapterError("Malcolm readiness response must be an object of boolean service states")
    missing = [name for name in REQUIRED_READY_SERVICES if name not in ready]
    service_states = {name: ready.get(name, False) for name in REQUIRED_READY_SERVICES}
    is_ready = not missing and all(service_states.values())

    version_data = fetch_json(opener, f"{base}/mapi/version", headers)
    if not isinstance(version_data, dict):
        raise MalcolmAdapterError("Malcolm version response must be a JSON object")
    version = version_data.get("version")
    if version is not None and (not isinstance(version, str) or len(version) > 64):
        raise MalcolmAdapterError("Malcolm version field is invalid")
    opensearch = version_data.get("opensearch")
    os_version = None
    os_health = None
    if isinstance(opensearch, dict):
        version_info = opensearch.get("version")
        health_info = opensearch.get("health")
        if isinstance(version_info, dict):
            candidate = version_info.get("number")
            if isinstance(candidate, str) and len(candidate) <= 64:
                os_version = candidate
        if isinstance(health_info, dict):
            candidate = health_info.get("status")
            if candidate in ("green", "yellow", "red"):
                os_health = candidate

    return {
        "schema_version": "1.0",
        "provider_id": "malcolm",
        "status": "healthy" if is_ready else "degraded",
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "malcolm_version": version,
        "opensearch_version": os_version,
        "opensearch_health": os_health,
        "required_services": service_states,
        "missing_required_services": missing,
        "read_only": True,
        "data_queried": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Malcolm base URL (HTTPS)")
    parser.add_argument("--ca-bundle", help="optional trusted CA bundle for the Malcolm certificate")
    parser.add_argument("--allow-http-local", action="store_true",
                        help="allow HTTP only for localhost/loopback test instances")
    args = parser.parse_args(argv)
    username = os.environ.get("MALCOLM_API_USERNAME")
    password = os.environ.get("MALCOLM_API_PASSWORD")
    try:
        result = fetch_status(args.base_url, username, password, args.ca_bundle,
                              args.allow_http_local)
    except MalcolmAdapterError as exc:
        print(f"UJANI Malcolm adapter rejected request: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
