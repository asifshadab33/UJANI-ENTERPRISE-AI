#!/usr/bin/env python3
"""Validate the bounded operator model/runtime inventory projection."""
from __future__ import annotations
import copy, json
from pathlib import Path
import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON object keys at any nesting depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_strict(path: Path) -> object:
    return json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)


SCHEMA = load_json_strict(ROOT / "schemas/operator-model-runtime-inventory-v2-projection.schema.json")
FIXTURE = load_json_strict(ROOT / "schemas/test-vectors/operator-model-runtime-inventory-v2-projection.json")


def semantic_errors(projection: dict) -> list[str]:
    """Check cross-field consistency not expressible by the JSON Schema."""
    errors: list[str] = []
    records = projection.get("records", [])
    if projection.get("returned_devices") != len(records):
        errors.append("returned_devices must equal records length")
    model_count = sum(len(record.get("models", [])) for record in records)
    if projection.get("returned_models") != model_count:
        errors.append("returned_models must equal included models")
    if projection.get("returned_devices", 0) > projection.get("total_devices", 0):
        errors.append("returned_devices cannot exceed total_devices")
    if projection.get("returned_models", 0) > projection.get("total_models", 0):
        errors.append("returned_models cannot exceed total_models")
    if projection.get("status") == "complete":
        if projection.get("returned_devices") != projection.get("total_devices"):
            errors.append("complete status requires all devices")
        if projection.get("returned_models") != projection.get("total_models"):
            errors.append("complete status requires all models")

    device_refs: set[str] = set()
    for record in records:
        device_ref = record.get("device_ref")
        if device_ref in device_refs:
            errors.append("device_ref values must be unique")
        device_refs.add(device_ref)
        runtime_refs = [item.get("runtime_ref") for item in record.get("runtimes", [])]
        if len(runtime_refs) != len(set(runtime_refs)):
            errors.append("runtime_ref values must be unique per device")
        model_refs = [item.get("model_ref") for item in record.get("models", [])]
        if len(model_refs) != len(set(model_refs)):
            errors.append("model_ref values must be unique per device")
        known_runtime_refs = set(runtime_refs)
        for model in record.get("models", []):
            runtime_ref = model.get("runtime_ref")
            if runtime_ref is not None and runtime_ref not in known_runtime_refs:
                errors.append("model runtime_ref must refer to same-device runtime")
    return errors


def main() -> None:
    # Python's default decoder silently keeps the last duplicate key. Reject
    # repeated fields recursively so validation has one unambiguous meaning.
    duplicate_key_cases = [
        '{"projection_version":1,"projection_version":1}',
        '{"record":{"device_ref":"first","device_ref":"second"}}',
        '{"records":[{"models":[{"capabilities":{"chat":true,"chat":false}}]}]}',
    ]
    for raw in duplicate_key_cases:
        try:
            json.loads(raw, object_pairs_hook=reject_duplicate_keys)
        except ValueError as error:
            assert "duplicate JSON key" in str(error)
        else:
            raise AssertionError("duplicate JSON keys unexpectedly accepted")

    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    validator = jsonschema.Draft202012Validator(SCHEMA)
    validator.validate(FIXTURE)
    assert not semantic_errors(FIXTURE), "fixture must be semantically valid"

    schema_invalid_cases = []
    invalid = copy.deepcopy(FIXTURE); invalid["records"][0]["models"][0]["local_path"] = "/home/user/model"; schema_invalid_cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE); invalid["records"][0]["models"][0]["evidence"]["freshness"] = "fresh"; schema_invalid_cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE); invalid["returned_devices"] = 65; schema_invalid_cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE); invalid["status"] = "unavailable"; schema_invalid_cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE); invalid["records"][0]["hardware"]["memory_total_mb"] = 0; schema_invalid_cases.append(invalid)
    for case in schema_invalid_cases:
        assert list(validator.iter_errors(case)), "schema-invalid projection unexpectedly passed"

    semantic_invalid_cases = []
    invalid = copy.deepcopy(FIXTURE); invalid["returned_devices"] = 0; semantic_invalid_cases.append((invalid, "returned_devices"))
    invalid = copy.deepcopy(FIXTURE); invalid["returned_models"] = 0; semantic_invalid_cases.append((invalid, "returned_models"))
    invalid = copy.deepcopy(FIXTURE); invalid["total_devices"] = 0; semantic_invalid_cases.append((invalid, "cannot exceed total_devices"))
    invalid = copy.deepcopy(FIXTURE); invalid["total_models"] = 0; semantic_invalid_cases.append((invalid, "cannot exceed total_models"))
    invalid = copy.deepcopy(FIXTURE); invalid["total_devices"] = 2; semantic_invalid_cases.append((invalid, "complete status requires all devices"))
    invalid = copy.deepcopy(FIXTURE); invalid["total_models"] = 2; semantic_invalid_cases.append((invalid, "complete status requires all models"))
    invalid = copy.deepcopy(FIXTURE); invalid["records"].append(copy.deepcopy(invalid["records"][0])); invalid["returned_devices"] = 2; invalid["total_devices"] = 2; semantic_invalid_cases.append((invalid, "device_ref values must be unique"))
    invalid = copy.deepcopy(FIXTURE); invalid["records"][0]["runtimes"].append(copy.deepcopy(invalid["records"][0]["runtimes"][0])); semantic_invalid_cases.append((invalid, "runtime_ref values must be unique"))
    invalid = copy.deepcopy(FIXTURE); invalid["records"][0]["models"].append(copy.deepcopy(invalid["records"][0]["models"][0])); invalid["returned_models"] = 2; invalid["total_models"] = 2; semantic_invalid_cases.append((invalid, "model_ref values must be unique"))
    invalid = copy.deepcopy(FIXTURE); invalid["records"][0]["models"][0]["runtime_ref"] = "missing-runtime"; semantic_invalid_cases.append((invalid, "model runtime_ref must refer"))

    for case, expected in semantic_invalid_cases:
        errors = semantic_errors(case)
        assert any(expected in error for error in errors), f"expected semantic rejection: {expected}"

    partial = copy.deepcopy(FIXTURE)
    partial["status"] = "partial_response_budget"
    partial["total_devices"] = 3
    partial["total_models"] = 9
    assert not semantic_errors(partial), "valid partial projection must be accepted"
    print("Operator inventory v2 projection schema, semantic consistency, and privacy/bounds tests passed.")


if __name__ == "__main__":
    main()
