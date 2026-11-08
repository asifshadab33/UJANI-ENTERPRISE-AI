#!/usr/bin/env python3
"""Dependency-free regression checks for the UJANI security-event JSON Schema.

This deliberately implements only the JSON Schema keywords used by v1. The
published schema remains normative; this test catches accidental contract
weakening without adding a runtime dependency to the Rust policy crate.
"""
import json
import math
import random
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


def ensure_supported_keywords(schema, path="$"):
    """Reject schema constructs that this dependency-free validator cannot enforce."""
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

def validate(value, schema, path="$"):
    """Validate a value against the JSON Schema subset used by event v1."""
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
        if "pattern" in schema:
            pattern = schema["pattern"]
            matcher = re.fullmatch if pattern.startswith("^") and pattern.endswith("$") else re.search
            if matcher(pattern, value) is None:
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
            rfc3339 = re.fullmatch(
                r"(?P<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])"
                r"(?P<fraction>\.[0-9]+)?(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
                value,
            )
            if rfc3339 is None:
                errors.append(f"{path}: invalid RFC 3339 date-time")
            else:
                # datetime stores microseconds. Normalize arbitrary RFC 3339
                # fractional precision before parsing so Python versions agree.
                fraction = rfc3339.group("fraction") or ""
                normalized_fraction = fraction[:7].ljust(7, "0") if fraction else ""
                normalized = (
                    rfc3339.group("base")
                    + normalized_fraction
                    + rfc3339.group("zone")
                )
                try:
                    datetime.fromisoformat(normalized.replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"{path}: invalid RFC 3339 date-time")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # JSON Schema numbers are finite. Python's json module accepts NaN and
        # Infinity by default, so reject them explicitly rather than allowing
        # NaN to bypass both the minimum and maximum comparisons.
        if isinstance(value, float) and not math.isfinite(value):
            errors.append(f"{path}: numeric value must be finite")
        elif value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
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
    """Return a valid minimal event matching the v1 allowlists."""
    # Keep the positive fixture aligned with the schema's explicit sensor allowlist.
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


def reject_non_finite_json_constant(value):
    """Reject Python json extensions that are not valid JSON numbers."""
    raise ValueError(f"non-finite JSON numeric constant is not permitted: {value}")


def reject_duplicate_json_keys(pairs):
    """Reject ambiguous JSON objects instead of silently keeping the last key."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key is not permitted: {key}")
        result[key] = value
    return result


def set_nested_value(document, dotted_path, value):
    """Set a nested event property for deterministic schema mutation tests."""
    parts = dotted_path.split(".")
    target = document
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value


def run_deterministic_property_checks(schema):
    """Exercise numeric boundaries, generated values, enums, and JSON type edges."""
    rng = random.Random(20261108)
    numeric_fields = (
        ("sequence", 1, 9007199254740991, True),
        ("evidence.confidence", 0.0, 1.0, False),
        ("evidence.count", 0, 1000000, True),
        ("evidence.window_seconds", 1, 86400, True),
    )
    checks = 0
    for dotted_path, lower, upper, integer in numeric_fields:
        for boundary in (lower, upper):
            candidate = sample_event()
            set_nested_value(candidate, dotted_path, boundary)
            if validate(candidate, schema):
                raise SystemExit(f"schema rejected valid boundary for {dotted_path}: {boundary}")
            checks += 1
        for invalid in (lower - 1, upper + 1):
            candidate = sample_event()
            set_nested_value(candidate, dotted_path, invalid)
            if not validate(candidate, schema):
                raise SystemExit(f"schema accepted out-of-range value for {dotted_path}: {invalid}")
            checks += 1
        for _ in range(64):
            if integer:
                value = rng.randint(lower, upper)
            else:
                value = rng.uniform(lower, upper)
            candidate = sample_event()
            set_nested_value(candidate, dotted_path, value)
            if validate(candidate, schema):
                raise SystemExit(f"schema rejected generated in-range value for {dotted_path}")
            checks += 1

    for dotted_path in ("sequence", "evidence.confidence", "evidence.count", "evidence.window_seconds"):
        candidate = sample_event()
        set_nested_value(candidate, dotted_path, True)
        if not validate(candidate, schema):
            raise SystemExit(f"schema accepted boolean as numeric field: {dotted_path}")
        checks += 1

    def visit(node, prefix=""):
        for name, child in node.get("properties", {}).items():
            path = f"{prefix}.{name}" if prefix else name
            if "enum" in child:
                yield path, child["enum"]
            yield from visit(child, path)

    for dotted_path, allowed_values in visit(schema):
        for allowed in allowed_values:
            candidate = sample_event()
            set_nested_value(candidate, dotted_path, allowed)
            if validate(candidate, schema):
                raise SystemExit(f"schema rejected declared enum value for {dotted_path}: {allowed}")
            checks += 1
        candidate = sample_event()
        set_nested_value(candidate, dotted_path, "__not_a_declared_value__")
        if not validate(candidate, schema):
            raise SystemExit(f"schema accepted undeclared enum value for {dotted_path}")
        checks += 1
    return checks


def main():
    """Run valid, invalid, format, privacy, and nested-schema contract fixtures."""
    try:
        schema = json.loads(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            parse_constant=reject_non_finite_json_constant,
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"invalid JSON Schema document: {exc}") from exc
    ensure_supported_keywords(schema)
    # JSON Schema pattern uses search semantics; exercise each anchored pattern
    # directly so a final newline cannot slip past the schema's end assertion.
    pattern_fixtures = {
        "tenant_id": (schema["properties"]["tenant_id"]["pattern"], "tenant-a"),
        "device_id": (schema["properties"]["device_id"]["pattern"], "device-01"),
        "sensor_version": (
            schema["properties"]["source"]["properties"]["sensor_version"]["pattern"],
            "1.2.3",
        ),
        "indicator_hash": (
            schema["properties"]["evidence"]["properties"]["indicator_hash"]["pattern"],
            "a" * 64,
        ),
        "indicator_domain": (
            schema["properties"]["evidence"]["properties"]["indicator_domain"]["pattern"],
            "example.com",
        ),
        "path_fingerprint": (
            schema["properties"]["evidence"]["properties"]["path_fingerprint"]["pattern"],
            "a" * 16,
        ),
        "correlation_hint": (schema["properties"]["correlation_hint"]["pattern"], "a" * 32),
    }
    for label, (pattern, valid_value) in pattern_fixtures.items():
        if re.search(pattern, valid_value) is None:
            raise SystemExit(f"schema pattern rejected valid {label} fixture")
        if re.search(pattern, valid_value + chr(10)) is not None:
            raise SystemExit(f"schema pattern accepted trailing newline for {label}")
    property_checks = run_deterministic_property_checks(schema)
    event = sample_event()
    failures = validate(event, schema)
    if failures:
        raise SystemExit("valid fixture rejected: " + "; ".join(failures))
    for timestamp in (
        "2026-11-07T12:00:00.1Z",
        "2026-11-07T12:00:00.123456789Z",
    ):
        fractional_event = sample_event()
        fractional_event["observed_at"] = timestamp
        failures = validate(fractional_event, schema)
        if failures:
            raise SystemExit(
                f"valid fractional RFC 3339 timestamp rejected ({timestamp}): "
                + "; ".join(failures)
            )
    cases = []
    unknown = sample_event(); unknown["command"] = "execute"
    cases.append(("unknown command field", unknown))
    bad_tenant = sample_event(); bad_tenant["tenant_id"] = "../other-tenant"
    cases.append(("tenant identifier traversal", bad_tenant))
    newline_tenant = sample_event(); newline_tenant["tenant_id"] = "tenant-a" + chr(10)
    cases.append(("tenant identifier trailing newline", newline_tenant))
    newline_sensor = sample_event(); newline_sensor["source"]["sensor_id"] = "ujani-network" + chr(10)
    cases.append(("sensor identifier trailing newline", newline_sensor))
    bad_confidence = sample_event(); bad_confidence["evidence"]["confidence"] = 1.5
    cases.append(("out-of-range confidence", bad_confidence))
    nan_confidence = sample_event(); nan_confidence["evidence"]["confidence"] = float("nan")
    cases.append(("non-finite NaN confidence", nan_confidence))
    infinite_confidence = sample_event(); infinite_confidence["evidence"]["confidence"] = float("inf")
    cases.append(("infinite confidence", infinite_confidence))
    huge_integer_confidence = sample_event(); huge_integer_confidence["evidence"]["confidence"] = 10 ** 400
    cases.append(("oversized integer confidence", huge_integer_confidence))
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
    invalid_offset_minutes = sample_event(); invalid_offset_minutes["observed_at"] = "2026-11-07T12:00:00+00:60"
    cases.append(("RFC 3339 offset minute out of range", invalid_offset_minutes))
    invalid_offset_hours = sample_event(); invalid_offset_hours["observed_at"] = "2026-11-07T12:00:00+24:00"
    cases.append(("RFC 3339 offset hour out of range", invalid_offset_hours))
    unicode_fraction = sample_event(); unicode_fraction["observed_at"] = "2026-11-07T12:00:00." + chr(0x0661) + "Z"
    cases.append(("non-ASCII fractional timestamp digit", unicode_fraction))
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
    for token in ("NaN", "Infinity", "-Infinity"):
        try:
            json.loads(token, parse_constant=reject_non_finite_json_constant)
        except ValueError:
            continue
        raise SystemExit(f"non-standard JSON numeric constant unexpectedly accepted: {token}")
    try:
        json.loads('{"schema_version":"1.0","schema_version":"2.0"}', object_pairs_hook=reject_duplicate_json_keys)
    except ValueError:
        pass
    else:
        raise SystemExit("duplicate JSON object key unexpectedly accepted")
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
    print(f"security-event-v1 schema contract checks passed ({len(cases) + 1} fixtures, {property_checks} deterministic property checks)")

if __name__ == "__main__":
    main()
