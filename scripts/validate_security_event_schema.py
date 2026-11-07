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

ANNOTATION_KEYWORDS = {"$schema", "$id", "title", "description", "$comment"}
VALIDATION_KEYWORDS = {
    "type", "const", "enum", "minLength", "maxLength", "pattern", "format",
    "minimum", "maximum", "required", "properties", "additionalProperties",
}
SUPPORTED_SCHEMA_KEYWORDS = ANNOTATION_KEYWORDS | VALIDATION_KEYWORDS


def validate(value, schema, path="$"):
    """Validate one event value against the JSON Schema subset implemented below."""
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
            rfc3339 = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
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


def ensure_supported_keywords(schema, path="$"):
    """Reject schema constructs that the dependency-free validator cannot enforce."""
    if not isinstance(schema, dict):
        raise SystemExit(f"{path}: expected a schema object")
    unsupported = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise SystemExit(f"{path}: unsupported JSON Schema keyword(s): {names}")
    kind = schema.get("type")
    if kind is not None and kind not in {"object", "string", "integer", "number"}:
        raise SystemExit(f"{path}: unsupported JSON Schema type: {kind}")
    fmt = schema.get("format")
    if fmt is not None and fmt not in {"uuid", "date-time"}:
        raise SystemExit(f"{path}: unsupported JSON Schema format: {fmt}")
    if "additionalProperties" in schema and schema["additionalProperties"] is not False:
        raise SystemExit(f"{path}: only additionalProperties:false is supported")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise SystemExit(f"{path}: properties must be an object")
    for name, child in properties.items():
        ensure_supported_keywords(child, f"{path}.properties.{name}")


def sample_event():
    """Return the minimal valid event used as the basis for regression fixtures."""
    return {
        "schema_version": "1.0",
        "event_id": "b4e8aef0-6f3e-4b58-8db5-63c2c8ac62b7",
        "tenant_id": "tenant-a",
        "device_id": "device-01",
        "sequence": 1,
        "observed_at": "2026-11-07T12:00:00Z",
        "event_type": "network.anomaly",
        "severity": "medium",
        "source": {"sensor_id": "ujani-network", "sensor_version": "1.0.0", "platform": "linux"},
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
    ensure_supported_keywords(schema)

    # Prove that schema constructs outside the implemented subset fail loudly.
    unsupported_schema = json.loads(json.dumps(schema))
    unsupported_schema["properties"]["evidence"]["properties"]["signal"]["oneOf"] = [
        {"const": "dns.burst"}
    ]
    try:
        ensure_supported_keywords(unsupported_schema)
    except SystemExit:
        pass
    else:
        raise SystemExit("unsupported schema keyword unexpectedly accepted")

    event = sample_event()
    failures = validate(event, schema)
    if failures:
        raise SystemExit("valid fixture rejected: " + "; ".join(failures))

    optional_event = sample_event()
    optional_event["evidence"].update({
        "indicator_hash": "a" * 64,
        "indicator_domain": "example.com",
        "path_fingerprint": "b" * 64,
        "process_class": "browser",
    })
    optional_event["correlation_hint"] = "c" * 64
    failures = validate(optional_event, schema)
    if failures:
        raise SystemExit("valid optional-field fixture rejected: " + "; ".join(failures))

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
    short_hash = sample_event(); short_hash["evidence"]["indicator_hash"] = "abc"
    cases.append(("short indicator hash", short_hash))
    domain_with_path = sample_event(); domain_with_path["evidence"]["indicator_domain"] = "example.com/path"
    cases.append(("indicator domain containing a path", domain_with_path))
    domain_with_whitespace = sample_event(); domain_with_whitespace["evidence"]["indicator_domain"] = "example.com "
    cases.append(("indicator domain containing whitespace", domain_with_whitespace))
    path_like_fingerprint = sample_event(); path_like_fingerprint["evidence"]["path_fingerprint"] = "../etc/passwd"
    cases.append(("path-like fingerprint", path_like_fingerprint))
    unknown_process_class = sample_event(); unknown_process_class["evidence"]["process_class"] = "administrator"
    cases.append(("unknown process class", unknown_process_class))
    short_correlation_hint = sample_event(); short_correlation_hint["correlation_hint"] = "abc"
    cases.append(("short correlation hint", short_correlation_hint))
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
    print(f"security-event-v1 schema contract checks passed ({len(cases) + 2} event fixtures)")

if __name__ == "__main__":
    main()
