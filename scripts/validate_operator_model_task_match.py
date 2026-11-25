#!/usr/bin/env python3
"""Validate the bounded, read-only operator model-task-match v1 contract."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_schema(name: str) -> dict:
    value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"),
                       object_pairs_hook=reject_duplicate_keys)
    jsonschema.Draft202012Validator.check_schema(value)
    return value


def main() -> None:
    request_schema = load_schema("operator-model-task-match-request-v1.schema.json")
    response_schema = load_schema("operator-model-task-match-response-v1.schema.json")
    request = jsonschema.Draft202012Validator(request_schema)
    response = jsonschema.Draft202012Validator(response_schema)

    valid_request = {
        "device_id": "lab-device-01",
        "model_ref": "llama3.2:latest",
        "requirements": {
            "required_capabilities": ["chat"],
            "minimum_context_length_tokens": 4096,
            "minimum_memory_mb": 2048,
        },
    }
    request.validate(valid_request)
    invalid_requests = []
    case = copy.deepcopy(valid_request); case["tenant_id"] = "tenant-from-browser"; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["role"] = "administrator"; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["requirements"]["required_capabilities"] = ["chat", "chat"]; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["requirements"]["required_capabilities"] = ["unknown"]; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["requirements"]["minimum_context_length_tokens"] = 0; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["requirements"]["minimum_memory_mb"] = 0; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["requirements"]["minimum_memory_mb"] = 9007199254740992; invalid_requests.append(case)
    case = copy.deepcopy(valid_request); case["device_id"] = "../other-tenant"; invalid_requests.append(case)
    for case in invalid_requests:
        assert list(request.iter_errors(case)), "invalid request unexpectedly passed"

    valid_responses = [
        {"schema_version": 1, "device_id": "lab-device-01",
         "result": {"model_ref": "llama3.2:latest", "status": "compatible",
                    "reasons": [], "evidence_confidence": "verified"}},
        {"schema_version": 1, "device_id": "lab-device-01",
         "result": {"model_ref": "llama3.2:latest", "status": "incompatible",
                    "reasons": ["context_length_too_short"], "evidence_confidence": "reported"}},
        {"schema_version": 1, "device_id": "lab-device-01",
         "result": {"model_ref": "llama3.2:latest", "status": "unknown",
                    "reasons": ["capability_evidence_unknown"], "evidence_confidence": "unknown"}},
    ]
    for value in valid_responses:
        response.validate(value)

    invalid_responses = []
    case = copy.deepcopy(valid_responses[0]); case["tenant_id"] = "tenant-a"; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["result"]["status"] = "compatible"; case["result"]["evidence_confidence"] = "estimated"; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["result"]["evidence_confidence"] = "unknown"; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["result"]["evidence_confidence"] = "reported"; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["result"]["reasons"] = ["context_length_too_short"]; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["result"]["status"] = "incompatible"; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["result"]["reasons"] = ["not_a_reason"]; invalid_responses.append(case)
    case = copy.deepcopy(valid_responses[0]); case["schema_version"] = 2; invalid_responses.append(case)
    for case in invalid_responses:
        assert list(response.iter_errors(case)), "invalid response unexpectedly passed"

    duplicate_key_cases = [
        '{"device_id":"a","device_id":"b","model_ref":"m","requirements":{"required_capabilities":[]}}',
        '{"schema_version":1,"device_id":"a","result":{"model_ref":"m","status":"unknown","reasons":[],"evidence_confidence":"unknown","status":"compatible"}}',
    ]
    for raw in duplicate_key_cases:
        try:
            json.loads(raw, object_pairs_hook=reject_duplicate_keys)
        except ValueError as error:
            assert "duplicate JSON key" in str(error)
        else:
            raise AssertionError("duplicate JSON keys unexpectedly accepted")

    print("Operator model-task-match v1 request/response schemas and adversarial cases passed.")


if __name__ == "__main__":
    main()
