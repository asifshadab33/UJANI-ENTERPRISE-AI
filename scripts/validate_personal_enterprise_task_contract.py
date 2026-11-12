"""Validate the shared Personal-to-Enterprise task contract and vectors."""
#!/usr/bin/env python3
"""Validate the shared Public/Enterprise task-contract v1 schema boundary."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/personal-enterprise-task-contract-v1.schema.json"
SAFE_INTEGER_MAXIMUM = 9_007_199_254_740_991
MAX_FUTURE_ISSUE_SKEW_MS = 60_000
ZERO_SHA256 = "0" * 64
TEST_SIGNATURE = "A" * 86
TEST_NONCE = "A" * 43


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON objects instead of silently accepting the last key."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    """Reject NaN and Infinity, which are not valid JSON values."""
    raise ValueError(f"non-JSON numeric constant: {value}")


def _strict_json_loads(value: str) -> Any:
    """Decode JSON while rejecting duplicate keys and non-standard constants."""
    return json.loads(
        value,
        object_pairs_hook=_reject_duplicate_object_pairs,
        parse_constant=_reject_non_json_constant,
    )


def _validate_strict_json_decoder() -> None:
    """Keep the contract tooling fail-closed for ambiguous JSON encodings."""
    sample = {"outer": {"name": "ujani", "version": 1}}
    assert _strict_json_loads(json.dumps(sample)) == sample

    # Exercise duplicate-key rejection independently for every shared message type.
    for message_type, message in _sample_messages().items():
        encoded = json.dumps(message, separators=(",", ":"))
        marker = '"message_type":' + json.dumps(message_type)
        assert marker in encoded, f"sample missing message type marker: {message_type}"
        duplicate = encoded.replace(
            marker,
            marker + ',"message_type":' + json.dumps(message_type),
            1,
        )
        try:
            _strict_json_loads(duplicate)
        except ValueError as error:
            assert "duplicate JSON object key: message_type" in str(error)
        else:
            raise AssertionError(
                f"duplicate message_type key unexpectedly accepted for {message_type}"
            )

    for ambiguous in (
        '{"outer":{"sequence":1,"sequence":2}}',
        '{"value":NaN}',
        '{"value":Infinity}',
    ):
        try:
            _strict_json_loads(ambiguous)
        except ValueError:
            continue
        raise AssertionError(f"ambiguous/non-JSON input unexpectedly accepted: {ambiguous}")


def _canonical_consent_binding_bytes(envelope: dict[str, Any]) -> bytes:
    """Return the restricted v1 JCS preimage with signature and self-digest removed."""
    binding = copy.deepcopy(envelope)
    binding.pop("signature")
    binding["consent"]["user"].pop("binding_sha256")
    # The v1 profile restricts property names/values to ASCII and numbers to safe
    # integers, so this sorted compact UTF-8 form is byte-equivalent to RFC 8785 JCS.
    return json.dumps(
        binding, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _consent_binding_sha256(envelope: dict[str, Any]) -> str:
    """Compute the domain-separated v1 consent binding digest."""
    return hashlib.sha256(
        b"UJANI-CONSENT-BINDING-V1\0" + _canonical_consent_binding_bytes(envelope)
    ).hexdigest()


def _validate_consent_binding_vector() -> None:
    """Verify the fixed cross-language canonicalization vector and field binding."""
    vector_path = ROOT / "schemas/test-vectors/consent-binding-v1.json"
    vector = _strict_json_loads(vector_path.read_text(encoding="utf-8"))
    assert vector["canonicalization"] == "RFC 8785 JSON Canonicalization Scheme"
    assert vector["domain_prefix"] == "UJANI-CONSENT-BINDING-V1"
    assert vector["domain_prefix_nul_terminated"] is True
    envelope = vector["envelope"]
    expected = vector["expected_binding_sha256"]
    canonical = _canonical_consent_binding_bytes(envelope)
    assert canonical.decode("utf-8") == vector["canonical_preimage_utf8"]
    assert envelope["consent"]["user"]["binding_sha256"] == expected
    assert _consent_binding_sha256(envelope) == expected

    changed = copy.deepcopy(envelope)
    changed["resource_limits"]["memory_mb"] += 1
    assert _consent_binding_sha256(changed) != expected

    signature_only = copy.deepcopy(envelope)
    signature_only["signature"]["value"] = "B" * 86
    assert _consent_binding_sha256(signature_only) == expected


def _refresh_consent_binding(envelope: dict[str, Any]) -> None:
    """Refresh the digest after a test fixture changes a bound envelope field."""
    envelope["consent"]["user"]["binding_sha256"] = _consent_binding_sha256(envelope)


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
    _refresh_consent_binding(envelope)

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


def _semantic_errors(instance: dict[str, Any], now_unix_ms: int = 1_000) -> list[str]:
    """Check cross-field time and expiry rules that JSON Schema cannot compare."""
    message_type = instance.get("message_type")
    errors: list[str] = []
    if message_type == "task_envelope":
        issued = instance["issued_at_unix_ms"]
        expires = instance["expires_at_unix_ms"]
        consent = instance["consent"]["user"]
        granted = consent["granted_at_unix_ms"]
        consent_expires = consent["expires_at_unix_ms"]
        if issued > now_unix_ms + MAX_FUTURE_ISSUE_SKEW_MS:
            errors.append("task issue time exceeds the 60,000 ms future clock-skew allowance")
        if expires <= issued:
            errors.append("task expiry must follow issue time")
        if expires - issued > 300_000:
            errors.append("task lifetime must not exceed 300,000 ms")
        if granted > issued:
            errors.append("user consent must be granted no later than task issue")
        if consent_expires <= granted or consent_expires < expires:
            errors.append("user consent must cover the task expiry")
        if consent["binding_sha256"] != _consent_binding_sha256(instance):
            errors.append("user consent binding digest does not match the task envelope")
    elif message_type == "execution_receipt":
        if instance["completed_at_unix_ms"] < instance["started_at_unix_ms"]:
            errors.append("receipt completion must not precede start")
    return errors


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
    vector = _strict_json_loads(
        (ROOT / "schemas/test-vectors/consent-binding-v1.json").read_text(encoding="utf-8")
    )
    valid_fixtures.append(("shared consent-binding vector envelope", vector["envelope"]))

    # Every active state must be valid only when all three authorities have approved.
    approved_status = copy.deepcopy(samples["task_status"])
    approved_status["state"] = "running"
    approved_status["consent_state"]["organisation_admin"] = "approved"
    approved_status["consent_state"]["worker_device_owner"] = "approved"
    for state in ("queued", "reserved", "running", "completed"):
        approved_state = copy.deepcopy(approved_status)
        approved_state["state"] = state
        valid_fixtures.append((f"{state} status with dual approval", approved_state))

    approved_terminal = copy.deepcopy(samples["task_status"])
    approved_terminal["state"] = "failed"
    approved_terminal["reason_code"] = "internal_error"
    valid_fixtures.append(("failed status with reason code", approved_terminal))

    allowlisted_envelope = copy.deepcopy(samples["task_envelope"])
    allowlisted_envelope["network_access"] = "allowlisted"
    allowlisted_envelope["network_destinations"] = ["models.example.com"]
    _refresh_consent_binding(allowlisted_envelope)
    valid_fixtures.append(("allowlisted DNS destination", allowlisted_envelope))

    single_label_envelope = copy.deepcopy(samples["task_envelope"])
    single_label_envelope["network_access"] = "allowlisted"
    single_label_envelope["network_destinations"] = ["models"]
    _refresh_consent_binding(single_label_envelope)
    valid_fixtures.append(("single-label DNS destination", single_label_envelope))

    digit_leading_hostname = copy.deepcopy(samples["task_envelope"])
    digit_leading_hostname["network_access"] = "allowlisted"
    digit_leading_hostname["network_destinations"] = ["3com"]
    _refresh_consent_binding(digit_leading_hostname)
    valid_fixtures.append(("digit-leading DNS hostname", digit_leading_hostname))

    receipt_with_output = copy.deepcopy(samples["execution_receipt"])
    receipt_with_output["output_sha256"] = ZERO_SHA256
    receipt_with_output["output_byte_length"] = 5
    valid_fixtures.append(("receipt with output digest", receipt_with_output))

    for name, instance in valid_fixtures:
        errors = list(validator.iter_errors(instance))
        assert not errors, f"valid {name} fixture rejected: {errors[0].message}"
        semantic_errors = _semantic_errors(instance)
        assert not semantic_errors, f"valid {name} fixture violates time semantics: {semantic_errors}"

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

    pending_admin = copy.deepcopy(approved_status)
    pending_admin["consent_state"]["organisation_admin"] = "pending"
    invalid.append(("running before administrator approval", pending_admin))

    denied_admin = copy.deepcopy(approved_status)
    denied_admin["consent_state"]["organisation_admin"] = "denied"
    invalid.append(("running after administrator denial", denied_admin))

    revoked_admin = copy.deepcopy(approved_status)
    revoked_admin["consent_state"]["organisation_admin"] = "revoked"
    invalid.append(("running after administrator revocation", revoked_admin))

    revoked_user = copy.deepcopy(approved_status)
    revoked_user["consent_state"]["user"] = "revoked"
    invalid.append(("running after user consent revocation", revoked_user))

    pending_owner = copy.deepcopy(approved_status)
    pending_owner["consent_state"]["worker_device_owner"] = "pending"
    invalid.append(("running before worker-owner approval", pending_owner))

    denied_owner = copy.deepcopy(approved_status)
    denied_owner["consent_state"]["worker_device_owner"] = "denied"
    invalid.append(("running after worker-owner denial", denied_owner))

    revoked_owner = copy.deepcopy(approved_status)
    revoked_owner["consent_state"]["worker_device_owner"] = "revoked"
    invalid.append(("running after worker-owner revocation", revoked_owner))

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

    for hostname in (
        "Example.com", ".", "..", "a..b", "-bad.example", "bad-.example",
        "example.com.", "127.0.0.1", "127.1", "2130706433",
        "0x7f000001", "0177.0.0.1", "0x7f.1", "example.com:443",
    ):
        invalid_host = copy.deepcopy(samples["task_envelope"])
        invalid_host["network_access"] = "allowlisted"
        invalid_host["network_destinations"] = [hostname]
        invalid.append((f"invalid network destination {hostname!r}", invalid_host))

    for name, instance in invalid:
        errors = list(validator.iter_errors(instance))
        assert errors, f"invalid fixture unexpectedly accepted: {name}"

    semantic_invalid = []
    future_issue_outside_skew = copy.deepcopy(samples["task_envelope"])
    future_issue_outside_skew["issued_at_unix_ms"] = 61_001
    future_issue_outside_skew["expires_at_unix_ms"] = 361_001
    future_issue_outside_skew["consent"]["user"]["granted_at_unix_ms"] = 61_000
    future_issue_outside_skew["consent"]["user"]["expires_at_unix_ms"] = 361_001
    _refresh_consent_binding(future_issue_outside_skew)
    semantic_invalid.append(("future issue exceeds 60-second clock skew", future_issue_outside_skew))

    future_issue_within_skew = copy.deepcopy(samples["task_envelope"])
    future_issue_within_skew["issued_at_unix_ms"] = 61_000
    future_issue_within_skew["expires_at_unix_ms"] = 361_000
    future_issue_within_skew["consent"]["user"]["granted_at_unix_ms"] = 60_999
    future_issue_within_skew["consent"]["user"]["expires_at_unix_ms"] = 361_000
    _refresh_consent_binding(future_issue_within_skew)
    assert not _semantic_errors(future_issue_within_skew, now_unix_ms=1_000), (
        "future issue exactly at the 60-second skew boundary should be accepted"
    )

    expiry_order = copy.deepcopy(samples["task_envelope"])
    expiry_order["expires_at_unix_ms"] = expiry_order["issued_at_unix_ms"]
    _refresh_consent_binding(expiry_order)
    semantic_invalid.append(("expiry not after issue", expiry_order))

    excessive_lifetime = copy.deepcopy(samples["task_envelope"])
    excessive_lifetime["expires_at_unix_ms"] += 1
    _refresh_consent_binding(excessive_lifetime)
    semantic_invalid.append(("task lifetime above 300 seconds", excessive_lifetime))

    consent_expires_early = copy.deepcopy(samples["task_envelope"])
    consent_expires_early["consent"]["user"]["expires_at_unix_ms"] -= 1
    _refresh_consent_binding(consent_expires_early)
    semantic_invalid.append(("consent expires before task", consent_expires_early))

    future_consent = copy.deepcopy(samples["task_envelope"])
    future_consent["consent"]["user"]["granted_at_unix_ms"] = (
        future_consent["issued_at_unix_ms"] + 1
    )
    _refresh_consent_binding(future_consent)
    semantic_invalid.append(("consent granted after task issue", future_consent))

    stale_consent_binding = copy.deepcopy(samples["task_envelope"])
    stale_consent_binding["payload"]["sha256"] = "1" * 64
    semantic_invalid.append(("payload changed without refreshing consent binding", stale_consent_binding))

    reversed_receipt_times = copy.deepcopy(samples["execution_receipt"])
    reversed_receipt_times["completed_at_unix_ms"] = (
        reversed_receipt_times["started_at_unix_ms"] - 1
    )
    semantic_invalid.append(("receipt completes before start", reversed_receipt_times))

    for name, instance in semantic_invalid:
        assert not list(validator.iter_errors(instance)), (
            f"cross-field fixture {name} should be structurally valid"
        )
        errors = _semantic_errors(instance)
        assert errors, f"cross-field invalid fixture unexpectedly accepted: {name}"

    print(
        "JSON Schema Draft 2020-12 meta-schema, "
        f"{len(valid_fixtures)} valid / {len(invalid)} invalid structural fixtures, "
        f"and {len(semantic_invalid)} invalid cross-field time fixtures passed."
    )


def main() -> None:
    """Check shared message structure, bounded values, and optional instance fixtures."""
    _validate_strict_json_decoder()
    _validate_consent_binding_vector()
    schema = _strict_json_loads(SCHEMA_PATH.read_text(encoding="utf-8"))
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
    assert destinations["items"]["not"]["pattern"] == (
        r"^(?:(?:[0-9]+|0[xX][0-9A-Fa-f]+)(?:\.(?:[0-9]+|0[xX][0-9A-Fa-f]+)){0,3})$"
    )
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
