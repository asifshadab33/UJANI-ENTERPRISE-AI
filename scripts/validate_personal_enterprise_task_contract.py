#!/usr/bin/env python3
"""Validate the shared Public/Enterprise task-contract v1 schema boundary."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/personal-enterprise-task-contract-v1.schema.json"
SAFE_INTEGER_MAXIMUM = 9_007_199_254_740_991
ZERO_SHA256 = "0" * 64
TEST_SIGNATURE = "A" * 86
TEST_NONCE = "A" * 43


def _sample_messages() -> dict[str, dict[str, Any]]:
    """Build minimal schema-valid examples for all three contract message types."""
    envelope = {
        "message_type": "task_envelope",
        "schema_version": 1,
        "task_id": "task-1",
        "sender": {"principal_id": "user-1", "device_id": "personal-1"},
        "audience": {"organisation_id": "org-1", "service_id": "ujani-enterprise"},
        "issued_at_unix_ms": 1_000,
        "expires_at_unix_ms": 301_000,
        "nonce": TEST_NONCE,
        "operation_id": "document.summarise",
        "operation_version": 1,
        "payload": {"sha256": ZERO_SHA256, "byte_length": 0, "media_type": "application/json"},
        "data_classification": "internal",
        "privacy_classification": "personal",
        "required_scopes": ["document.read"],
        "required_capabilities": ["chat"],
        "min_context_length_tokens": 4_096,
        "resource_limits": {
            "cpu_millis": 1_000,
            "memory_mb": 1_024,
            "max_runtime_ms": 60_000,
            "max_output_bytes": 65_536,
        },
        "network_access": "none",
        "consent": {
            "user": {
                "decision": "granted",
                "consent_id": "consent-1",
                "subject_id": "user-1",
                "granted_at_unix_ms": 900,
                "expires_at_unix_ms": 301_000,
                "binding_sha256": ZERO_SHA256,
            },
            "required_approvals": ["organisation_admin", "worker_device_owner"],
        },
        "device_trust": {
            "target_device_id": "worker-1",
            "required_trust_state": "enrolled_active",
            "require_owner_opt_in": True,
        },
        "signature": {"algorithm": "ed25519", "key_id": "sender-key-1", "value": TEST_SIGNATURE},
        "network_destinations": [],
    }
    status = {
        "message_type": "task_status",
        "schema_version": 1,
        "task_id": "task-1",
        "sequence": 1,
        "state": "awaiting_approval",
        "updated_at_unix_ms": 1_100,
        "policy_version": "policy-1",
        "consent_state": {
            "user": "granted",
            "organisation_admin": "pending",
            "worker_device_owner": "pending",
        },
        "signature": {"algorithm": "ed25519", "key_id": "service-key-1", "value": TEST_SIGNATURE},
    }
    receipt = {
        "message_type": "execution_receipt",
        "schema_version": 1,
        "task_id": "task-1",
        "sequence": 1,
        "input_sha256": ZERO_SHA256,
        "output_sha256": None,
        "output_byte_length": 0,
        "worker": {"organisation_id": "org-1", "device_id": "worker-1"},
        "execution_location": "enrolled_device",
        "started_at_unix_ms": 1_200,
        "completed_at_unix_ms": 1_300,
        "outcome": "completed",
        "consent_refs": {
            "user_consent_id": "consent-1",
            "organisation_approval_id": "approval-1",
            "worker_owner_consent_id": "owner-consent-1",
        },
        "policy_version": "policy-1",
        "signature": {"algorithm": "ed25519", "key_id": "worker-key-1", "value": TEST_SIGNATURE},
    }
    return {"task_envelope": envelope, "task_status": status, "execution_receipt": receipt}


def _validate_instance_fixtures(schema: dict[str, Any]) -> None:
    """Validate accepted and rejected message fixtures when jsonschema is installed."""
    try:
        import jsonschema
    except ImportError:
        print(
            "WARNING: jsonschema is not installed; Draft 2020-12 meta-schema "
            "and instance-fixture validation were skipped."
        )
        return

    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    samples = _sample_messages()
    valid_fixtures = list(samples.items())

    approved_terminal = copy.deepcopy(samples["task_status"])
    approved_terminal["state"] = "failed"
    approved_terminal["reason_code"] = "internal_error"
    valid_fixtures.append(("failed status with reason code", approved_terminal))

    allowlisted_envelope = copy.deepcopy(samples["task_envelope"])
    allowlisted_envelope["network_access"] = "allowlisted"
    allowlisted_envelope["network_destinations"] = ["models.example.com"]
    valid_fixtures.append(("allowlisted DNS destination", allowlisted_envelope))

    receipt_with_output = copy.deepcopy(samples["execution_receipt"])
    receipt_with_output["output_sha256"] = ZERO_SHA256
    receipt_with_output["output_byte_length"] = 5
    valid_fixtures.append(("receipt with output digest", receipt_with_output))

    for name, instance in valid_fixtures:
        errors = list(validator.iter_errors(instance))
        assert not errors, f"valid {name} fixture rejected: {errors[0].message}"

    invalid: list[tuple[str, dict[str, Any]]] = []
    unknown_field = copy.deepcopy(samples["task_envelope"])
    unknown_field["unrecognised"] = True
    invalid.append(("unknown envelope field", unknown_field))

    missing_destination = copy.deepcopy(samples["task_envelope"])
    missing_destination["network_access"] = "allowlisted"
    invalid.append(("empty allowlist", missing_destination))

    over_limit_memory = copy.deepcopy(samples["task_envelope"])
    over_limit_memory["resource_limits"]["memory_mb"] = 4_194_305
    invalid.append(("over-limit memory", over_limit_memory))

    missing_owner_approval = copy.deepcopy(samples["task_envelope"])
    missing_owner_approval["consent"]["required_approvals"] = ["organisation_admin"]
    invalid.append(("missing worker-owner approval", missing_owner_approval))

    pending_admin = copy.deepcopy(samples["task_status"])
    pending_admin["state"] = "running"
    invalid.append(("running before administrator approval", pending_admin))

    revoked_user = copy.deepcopy(samples["task_status"])
    revoked_user["state"] = "running"
    revoked_user["consent_state"]["user"] = "revoked"
    invalid.append(("running after user consent revocation", revoked_user))

    pending_owner = copy.deepcopy(samples["task_status"])
    pending_owner["state"] = "running"
    invalid.append(("running before worker-owner approval", pending_owner))

    missing_terminal_reason = copy.deepcopy(samples["task_status"])
    missing_terminal_reason["state"] = "failed"
    invalid.append(("terminal failure without reason code", missing_terminal_reason))

    unsafe_timestamp = copy.deepcopy(samples["task_envelope"])
    unsafe_timestamp["issued_at_unix_ms"] = SAFE_INTEGER_MAXIMUM + 1
    invalid.append(("unsafe I-JSON integer", unsafe_timestamp))

    receipt_without_digest = copy.deepcopy(samples["execution_receipt"])
    receipt_without_digest["output_byte_length"] = 1
    invalid.append(("output bytes without digest", receipt_without_digest))

    digest_without_output = copy.deepcopy(samples["execution_receipt"])
    digest_without_output["output_sha256"] = ZERO_SHA256
    invalid.append(("digest without output bytes", digest_without_output))

    for hostname in ("Example.com", ".", "..", "a..b", "-bad.example", "bad-.example",
                     "example.com.", "127.0.0.1", "example.com:443"):
        invalid_host = copy.deepcopy(samples["task_envelope"])
        invalid_host["network_access"] = "allowlisted"
        invalid_host["network_destinations"] = [hostname]
        invalid.append((f"invalid network destination {hostname!r}", invalid_host))

    for name, instance in invalid:
        errors = list(validator.iter_errors(instance))
        assert errors, f"invalid fixture unexpectedly accepted: {name}"

    print(
        "JSON Schema Draft 2020-12 meta-schema and "
        f"{len(valid_fixtures)} valid / {len(invalid)} invalid contract fixtures passed."
    )


def main() -> None:
    """Check shared message structure, bounded values, and optional instance fixtures."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:ujani:personal-enterprise-task-contract:v1"
    assert len(schema["oneOf"]) == 3

    definitions = schema["$defs"]
    envelope = definitions["task_envelope"]
    status = definitions["task_status"]
    receipt = definitions["execution_receipt"]
    for definition in (envelope, status, receipt):
        assert definition["type"] == "object"
        assert definition["additionalProperties"] is False

    envelope_required = set(envelope["required"])
    assert {
        "task_id", "sender", "audience", "issued_at_unix_ms", "expires_at_unix_ms",
        "nonce", "operation_id", "operation_version", "payload", "data_classification",
        "privacy_classification", "required_scopes", "required_capabilities",
        "resource_limits", "network_access", "network_destinations", "consent",
        "device_trust", "signature",
    } <= envelope_required
    assert definitions["signature"]["properties"]["algorithm"]["const"] == "ed25519"
    assert definitions["signature"]["properties"]["value"]["minLength"] == 86
    assert envelope["properties"]["nonce"]["minLength"] == 43
    assert envelope["properties"]["payload"]["properties"]["byte_length"]["maximum"] == 16_777_216
    assert envelope["properties"]["resource_limits"]["properties"]["max_runtime_ms"]["maximum"] == 604_800_000

    memory_limit = envelope["properties"]["resource_limits"]["properties"]["memory_mb"]
    assert "mebibytes (MiB)" in memory_limit["description"]
    approvals = envelope["properties"]["consent"]["properties"]["required_approvals"]
    assert approvals["minItems"] == 2 and approvals["maxItems"] == 2 and approvals["uniqueItems"] is True
    assert approvals["items"]["enum"] == ["organisation_admin", "worker_device_owner"]

    destinations = envelope["properties"]["network_destinations"]
    assert destinations["maxItems"] == 8
    assert destinations["items"]["pattern"].startswith("^[a-z0-9]")
    assert destinations["items"]["not"]["pattern"] == "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"
    allowlisted_rule, restricted_rule = envelope["allOf"]
    assert allowlisted_rule["if"]["properties"]["network_access"]["const"] == "allowlisted"
    assert allowlisted_rule["then"]["properties"]["network_destinations"]["minItems"] == 1
    assert restricted_rule["if"]["properties"]["network_access"]["enum"] == ["none", "enterprise_internal"]
    assert restricted_rule["then"]["properties"]["network_destinations"]["maxItems"] == 0

    states = status["properties"]["state"]["enum"]
    assert {"awaiting_approval", "queued", "reserved", "running", "completed", "failed", "cancelled", "timed_out", "rejected", "expired"} <= set(states)
    assert status["properties"]["sequence"]["minimum"] == 1
    assert status["properties"]["consent_state"]["required"] == ["user", "organisation_admin", "worker_device_owner"]
    assert len(status["allOf"]) == 2
    assert status["allOf"][1]["then"]["required"] == ["reason_code"]
    consent_state = status["properties"]["consent_state"]["properties"]
    assert "revoked" in consent_state["user"]["enum"]
    assert "revoked" in consent_state["organisation_admin"]["enum"]
    assert "revoked" in consent_state["worker_device_owner"]["enum"]
    assert status["allOf"][0]["then"]["properties"]["consent_state"]["properties"]["organisation_admin"]["const"] == "approved"
    assert "consent_revoked" in status["properties"]["reason_code"]["enum"]

    assert "output_byte_length" in receipt["required"]
    assert receipt["properties"]["output_byte_length"]["maximum"] == 67_108_864
    assert "mebibytes (MiB)" in receipt["properties"]["resource_usage"]["properties"]["peak_memory_mb"]["description"]
    assert receipt["properties"]["input_sha256"]["$ref"] == "#/$defs/sha256"
    assert receipt["properties"]["worker"]["additionalProperties"] is False
    assert receipt["properties"]["consent_refs"]["required"] == [
        "user_consent_id", "organisation_approval_id", "worker_owner_consent_id"
    ]
    assert receipt["properties"]["signature"]["$ref"] == "#/$defs/signature"

    def check_closed_objects(node: object) -> None:
        """Ensure every declared object rejects unrecognised properties."""
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            for value in node.values():
                check_closed_objects(value)
        elif isinstance(node, list):
            for value in node:
                check_closed_objects(value)

    def check_integer_safe_bounds(node: object) -> None:
        """Ensure all integer-valued wire fields fit the I-JSON safe integer range."""
        if isinstance(node, dict):
            node_type = node.get("type")
            if node_type == "integer" or (
                isinstance(node_type, list) and "integer" in node_type
            ):
                assert node.get("maximum") is not None
                assert node["maximum"] <= SAFE_INTEGER_MAXIMUM
            for value in node.values():
                check_integer_safe_bounds(value)
        elif isinstance(node, list):
            for value in node:
                check_integer_safe_bounds(value)

    check_closed_objects(definitions)
    check_integer_safe_bounds(definitions)
    _validate_instance_fixtures(schema)
    print("Personal-to-Enterprise task-contract v1 structural checks passed.")


if __name__ == "__main__":
    main()
