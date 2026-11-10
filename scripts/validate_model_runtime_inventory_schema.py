#!/usr/bin/env python3
"""Validate the shared UJANI model/runtime inventory v1 contract."""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/model-runtime-inventory-v1.schema.json"


def main() -> None:
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
    print("Model/runtime inventory v1 schema checks passed.")


if __name__ == "__main__":
    main()
