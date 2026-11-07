#!/usr/bin/env python3
"""Dependency-free regression checks for the UJANI security-event JSON Schema.

This deliberately implements only the JSON Schema keywords used by v1. The
published schema remains normative; this test catches accidental contract
weakening without adding a runtime dependency to the Rust policy crate.
"""
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/security-event-v1.schema.json"

def validate(value, schema, path="$"):
    errors = []
    kind = schema.get("type")
    checks = {
        "object": lambda v: isinstance(v, dict),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    }
    if kind in checks and not checks[kind](value):
        return [f"{path}: expected {kind}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: value differs from const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is not in enum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            errors.append(f"{path}: string length out of bounds")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: pattern mismatch")
        if schema.get("format") == "uuid":
            if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value) is None:
                errors.append(f"{path}: invalid UUID")
            else:
                try:
                    uuid.UUID(value)
                except ValueError:
                    errors.append(f"{path}: invalid UUID")
        if schema.get("format") == "date-time":
            rfc3339 = r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})$"
            if re.fullmatch(rfc3339, value) is None:
                errors.append(f"{path}: invalid RFC 3339 date-time")
            else:
                try:
                    datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"{path}: invalid RFC 3339 date-time")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            errors.append(f"{path}: numeric value out of bounds")
    if isinstance(value, dict):
        missing = set(schema.get("required", [])) - set(value)
        errors.extend(f"{path}: missing required property {key}" for key in sorted(missing))
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(f"{path}: unexpected property {key}" for key in sorted(set(value) - set(props)))
        for key, child in value.items():
            if key in props:
                errors.extend(validate(child, props[key], f"{path}.{key}"))
    return errors

def sample_event():
    return {
        "schema_version": "1.0",
        "event_id": "b4e8aef0-6f3e-4b58-8db5-63c2c8ac62b7",
        "tenant_id": "tenant-a",
        "device_id": "device-01",
        "sequence": 1,
        "observed_at": "2026-11-07T12:00:00Z",
        "event_type": "network.anomaly",
        "severity": "medium",
        "source": {"sensor_id": "endpoint", "sensor_version": "1.0.0", "platform": "linux"},
        "evidence": {"signal": "dns.burst", "confidence": 0.82, "count": 17, "window_seconds": 60}
    }

def collect_property_names(schema):
    """Collect declared property names recursively across nested object schemas."""
    names = set()
    for key, child in schema.get("properties", {}).items():
        names.add(key)
        names.update(collect_property_names(child))
    for keyword in ("items", "additionalProperties", "not", "if", "then", "else"):
        child = schema.get(keyword)
        if isinstance(child, dict):
            names.update(collect_property_names(child))
    for keyword in ("allOf", "anyOf", "oneOf"):
        children = schema.get(keyword, [])
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    names.update(collect_property_names(child))
    return names


def main():
    """Run valid, invalid, format, privacy, and nested-schema contract fixtures."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    event = sample_event()
    failures = validate(event, schema)
    if failures:
        raise SystemExit("valid fixture rejected: " + "; ".join(failures))
    cases = []
    unknown = sample_event(); unknown["command"] = "execute"
    cases.append(("unknown command field", unknown))
    bad_tenant = sample_event(); bad_tenant["tenant_id"] = "../other-tenant"
    cases.append(("tenant identifier traversal", bad_tenant))
    bad_confidence = sample_event(); bad_confidence["evidence"]["confidence"] = 1.5
    cases.append(("out-of-range confidence", bad_confidence))
    bad_sequence = sample_event(); bad_sequence["sequence"] = 0
    cases.append(("zero sequence", bad_sequence))
    missing_source = sample_event(); del missing_source["source"]["sensor_id"]
    cases.append(("missing sensor identity", missing_source))
    bad_uuid = sample_event(); bad_uuid["event_id"] = "not-a-uuid"
    cases.append(("invalid event UUID", bad_uuid))
    bad_timestamp = sample_event(); bad_timestamp["observed_at"] = "not-a-date"
    cases.append(("invalid event timestamp", bad_timestamp))
    naive_timestamp = sample_event(); naive_timestamp["observed_at"] = "2026-11-07T12:00:00"
    cases.append(("timestamp without timezone", naive_timestamp))
    command_sensor = sample_event(); command_sensor["source"]["sensor_id"] = "cat /etc/passwd"
    cases.append(("command-like sensor identifier", command_sensor))
    command_version = sample_event(); command_version["source"]["sensor_version"] = "1.0.0; cat /etc/passwd"
    cases.append(("command-like sensor version", command_version))
    unknown_source = sample_event(); unknown_source["source"]["unexpected_field"] = "value"
    cases.append(("unknown source field", unknown_source))
    unknown_evidence = sample_event(); unknown_evidence["evidence"]["unexpected_field"] = "value"
    cases.append(("unknown evidence field", unknown_evidence))
    for label, candidate in cases:
        if not validate(candidate, schema):
            raise SystemExit(f"invalid fixture unexpectedly accepted: {label}")
    forbidden = {
        "file_contents", "document_contents", "credentials", "token", "raw_command",
        "command", "command_line", "file_path", "memory_dump", "conversation",
        "executable_payload", "response_action", "remote_command", "remediation"
    }
    all_property_names = collect_property_names(schema)
    if all_property_names & forbidden:
        raise SystemExit("privacy/remote-execution fields entered the event contract")
    if schema.get("additionalProperties") is not False:
        raise SystemExit("root event schema must reject unknown fields")
    print(f"security-event-v1 schema contract checks passed ({len(cases) + 1} fixtures)")

if __name__ == "__main__":
    main()
