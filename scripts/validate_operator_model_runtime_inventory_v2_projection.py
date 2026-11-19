#!/usr/bin/env python3
"""Validate the proposed bounded operator model/runtime inventory projection."""
from __future__ import annotations
import copy, json
from pathlib import Path
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/operator-model-runtime-inventory-v2-projection.schema.json").read_text())
FIXTURE = json.loads((ROOT / "schemas/test-vectors/operator-model-runtime-inventory-v2-projection.json").read_text())

def main() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    validator = jsonschema.Draft202012Validator(SCHEMA)
    validator.validate(FIXTURE)
    cases = []
    invalid = copy.deepcopy(FIXTURE)
    invalid["records"][0]["models"][0]["local_path"] = "/home/user/model"
    cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE)
    invalid["records"][0]["models"][0]["evidence"]["freshness"] = "fresh"
    cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE)
    invalid["returned_devices"] = 65
    cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE)
    invalid["status"] = "unavailable"
    cases.append(invalid)
    invalid = copy.deepcopy(FIXTURE)
    invalid["records"][0]["hardware"]["memory_total_mb"] = 0
    cases.append(invalid)
    for case in cases:
        assert list(validator.iter_errors(case)), "invalid projection unexpectedly passed"
    print("Operator inventory v2 projection schema and privacy/bounds fixtures passed.")

if __name__ == "__main__":
    main()
