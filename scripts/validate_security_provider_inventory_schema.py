"""Validate the versioned, read-only Enterprise security-provider inventory schema."""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "security-provider-inventory-v1.schema.json"


def sample() -> dict:
    return {
        "schema_version": 1,
        "generated_at_unix_ms": 2_000_000,
        "providers": [
            {
                "device_id": "device-01",
                "provider_id": "vendor.endpoint",
                "display_name": "Existing Endpoint Protection",
                "category": "malware_protection",
                "status": "healthy",
                "evidence_source": "customer-configured read-only connector",
                "evidence_freshness": "fresh",
                "observed_at_unix_ms": 1_999_000,
                "product_identity_known": True,
                "capabilities": ["malware_protection", "quarantine"],
                "update_posture": "out_of_date",
                "update_checked_at_unix_ms": 1_998_000,
                "update_channel": "security_intelligence",
                "update_recommendation": "Update through the existing vendor or OS workflow.",
            },
            {
                "device_id": "device-02",
                "provider_id": "vendor.firewall",
                "display_name": None,
                "category": "firewall",
                "status": "unknown",
                "evidence_source": "customer-configured read-only connector",
                "evidence_freshness": "stale",
                "observed_at_unix_ms": 1_999_000,
                "product_identity_known": False,
                "capabilities": [],
                "update_posture": "unverified",
                "update_checked_at_unix_ms": None,
                "update_channel": None,
                "update_recommendation": "Firewall update freshness cannot be verified.",
            },
        ],
    }


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    valid = sample()
    validator.validate(valid)

    invalid_cases = []
    bad_category = sample()
    bad_category["providers"][0]["category"] = "antivirus_everywhere"
    invalid_cases.append(bad_category)

    bad_update = sample()
    bad_update["providers"][0]["update_posture"] = "probably_current"
    invalid_cases.append(bad_update)

    duplicate_capability = sample()
    duplicate_capability["providers"][0]["capabilities"] = ["quarantine", "quarantine"]
    invalid_cases.append(duplicate_capability)

    unexpected_field = sample()
    unexpected_field["providers"][0]["credentials"] = "must never be present"
    invalid_cases.append(unexpected_field)

    invalid_freshness = sample()
    invalid_freshness["providers"][0]["evidence_freshness"] = "fresh-ish"
    invalid_cases.append(invalid_freshness)

    missing_verified_update_time = sample()
    missing_verified_update_time["providers"][0]["update_checked_at_unix_ms"] = None
    invalid_cases.append(missing_verified_update_time)

    for candidate in invalid_cases:
        if validator.is_valid(candidate):
            raise SystemExit("security-provider inventory schema accepted an invalid fixture")

    print("Security-provider inventory v1 schema and negative fixtures passed.")


if __name__ == "__main__":
    main()
