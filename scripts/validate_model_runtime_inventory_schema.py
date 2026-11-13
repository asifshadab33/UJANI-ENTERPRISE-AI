#!/usr/bin/env python3
"""Validate the shared UJANI model/runtime inventory and task contracts."""
from __future__ import annotations

import copy
import json
import jsonschema
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/model-runtime-inventory-v1.schema.json"


def validate_self_evolution_schema() -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas/self-evolution-proposal-v1.schema.json"
    fixture_path = Path(__file__).resolve().parents[1] / "schemas/test-vectors/self-evolution-proposal-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:ujani:self-evolution-proposal:v1"
    assert schema["properties"]["schema_version"]["const"] == 1
    validator = jsonschema.Draft202012Validator(schema)
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validator.validate(fixture)

    # The schema is a structural contract, not an authorization grant.
    # It must reject traversal, malformed refs/digests, missing paired line bounds,
    # and unknown fields before the Rust protected-path policy is consulted.
    invalid_path = copy.deepcopy(fixture)
    invalid_path["changes"][0]["path"] = "../outside.rs"
    assert list(validator.iter_errors(invalid_path))

    invalid_ref = copy.deepcopy(fixture)
    invalid_ref["target"]["base_ref"] = "feature/../main"
    assert list(validator.iter_errors(invalid_ref))

    invalid_digest = copy.deepcopy(fixture)
    invalid_digest["changes"][0]["patch_sha256"] = "not-a-digest"
    assert list(validator.iter_errors(invalid_digest))

    incomplete_line_range = copy.deepcopy(fixture)
    incomplete_line_range["findings"][0].pop("line_end")
    assert list(validator.iter_errors(incomplete_line_range))

    unknown_field = copy.deepcopy(fixture)
    unknown_field["changes"][0]["unreviewed_permission"] = "shell"
    assert list(validator.iter_errors(unknown_field))
    print("Self-evolution proposal v1 schema and fixture checks passed.")


def main() -> None:
    """Validate the model-runtime inventory schema and its bounded fixtures."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:ujani:model-runtime-inventory:v1"
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1
    assert set(schema["required"]) == {
        "schema_version", "generated_at_unix_ms", "platform", "hardware", "runtimes", "models"
    }
    device_ref = schema["properties"]["device_ref"]
    assert device_ref["type"] == ["string", "null"]
    assert device_ref["pattern"] == "^[A-Za-z0-9._:-]+$"
    assert schema["properties"]["runtimes"]["maxItems"] <= 16
    assert schema["properties"]["models"]["maxItems"] <= 512
    assert schema["properties"]["hardware"]["properties"]["accelerators"]["maxItems"] <= 32
    evidence = schema["$defs"]["evidence"]
    assert evidence["additionalProperties"] is False
    assert evidence["properties"]["confidence"]["enum"] == [
        "verified", "reported", "estimated", "unknown"
    ]
    fixture_path = SCHEMA_PATH.parent / "test-vectors/model-runtime-inventory-v1.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(fixture)
    assert fixture["schema_version"] == 1
    assert fixture["models"][0]["estimated_min_memory_mb"] == 3_374

    # An empty report is valid but means "not reported", not "no capability".
    empty_inventory = copy.deepcopy(fixture)
    empty_inventory["models"] = []
    validator.validate(empty_inventory)

    # Unknown top-level and nested fields must not be silently accepted.
    unknown_top_level = copy.deepcopy(fixture)
    unknown_top_level["unexpected_field"] = True
    assert list(validator.iter_errors(unknown_top_level))

    unknown_model_field = copy.deepcopy(fixture)
    unknown_model_field["models"][0]["unrecognised_capability_claim"] = True
    assert list(validator.iter_errors(unknown_model_field))
    print("Model/runtime inventory v1 schema and shared fixture checks passed.")

    validate_self_evolution_schema()

    from validate_personal_enterprise_task_contract import main as validate_task_contract
    validate_task_contract()


if __name__ == "__main__":
    main()
