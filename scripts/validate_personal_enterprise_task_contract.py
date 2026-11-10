#!/usr/bin/env python3
"""Check the shared Public/Enterprise task-contract v1 schema boundary."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/personal-enterprise-task-contract-v1.schema.json"


def main() -> None:
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
        "nonce", "operation_id", "payload", "data_classification",
        "privacy_classification", "required_scopes", "required_capabilities",
        "resource_limits", "network_access", "network_destinations", "consent",
        "device_trust", "signature",
    } <= envelope_required
    assert definitions["signature"]["properties"]["algorithm"]["const"] == "ed25519"
    assert definitions["signature"]["properties"]["value"]["minLength"] == 86
    assert envelope["properties"]["nonce"]["minLength"] == 43
    assert envelope["properties"]["payload"]["properties"]["byte_length"]["maximum"] == 16_777_216
    assert envelope["properties"]["resource_limits"]["properties"]["max_runtime_ms"]["maximum"] == 604_800_000
    approvals = envelope["properties"]["consent"]["properties"]["required_approvals"]
    assert approvals["minItems"] == 2 and approvals["maxItems"] == 2 and approvals["uniqueItems"] is True
    assert len(envelope["allOf"]) == 2
    assert envelope["properties"]["network_destinations"]["maxItems"] == 8
    allowlisted_rule, restricted_rule = envelope["allOf"]
    assert allowlisted_rule["if"]["properties"]["network_access"]["const"] == "allowlisted"
    assert allowlisted_rule["then"]["properties"]["network_destinations"]["minItems"] == 1
    assert restricted_rule["if"]["properties"]["network_access"]["enum"] == ["none", "enterprise_internal"]
    assert restricted_rule["then"]["properties"]["network_destinations"]["maxItems"] == 0

    states = status["properties"]["state"]["enum"]
    assert {"awaiting_approval", "queued", "reserved", "running", "completed", "failed", "cancelled", "timed_out", "rejected", "expired"} <= set(states)
    assert status["properties"]["sequence"]["minimum"] == 1
    consent_state = status["properties"]["consent_state"]["properties"]
    assert "revoked" in consent_state["user"]["enum"]
    assert "revoked" in consent_state["organization_admin"]["enum"]
    assert "revoked" in consent_state["worker_device_owner"]["enum"]
    assert "consent_revoked" in status["properties"]["reason_code"]["enum"]
    assert receipt["properties"]["input_sha256"]["$ref"] == "#/$defs/sha256"
    assert receipt["properties"]["worker"]["additionalProperties"] is False
    assert receipt["properties"]["consent_refs"]["required"] == [
        "user_consent_id", "organization_approval_id", "worker_owner_consent_id"
    ]
    assert receipt["properties"]["signature"]["$ref"] == "#/$defs/signature"

    def check_closed_objects(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            for value in node.values():
                check_closed_objects(value)
        elif isinstance(node, list):
            for value in node:
                check_closed_objects(value)

    check_closed_objects(definitions)
    try:
        import jsonschema
    except ImportError:
        pass
    else:
        jsonschema.Draft202012Validator.check_schema(schema)
    print("Personal-to-Enterprise task-contract v1 schema checks passed.")


if __name__ == "__main__":
    main()
