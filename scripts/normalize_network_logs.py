#!/usr/bin/env python3
"""Normalize local Suricata EVE JSON and Zeek JSON logs into bounded UJANI evidence.

Read-only local file import only. This script never opens network connections,
changes provider configuration, executes commands, or sends data to a service.
It intentionally exports a small allowlist rather than raw packet/application data.
"""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 100_000
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_FIELDS = 24
MAX_VALUE_BYTES = 512
TENANT_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SURICATA_EVENT_TYPES = {
    "alert", "anomaly", "flow", "dns", "http", "tls", "ssh", "fileinfo",
    "stats", "netflow", "smtp", "dcerpc", "smb", "ftp", "tftp", "ike",
}
ZEEK_FIELDS = {
    "conn": ("uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
             "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state"),
    "notice": ("uid", "note", "sub", "src", "dst", "p", "conn"),
    "weird": ("uid", "name", "id.orig_h", "id.resp_h", "proto", "conn"),
}


class ImportErrorSafe(Exception):
    """An input or contract error safe to show without dumping source data."""


def reject_constant(value):
    raise ImportErrorSafe("non-finite JSON number is not permitted")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ImportErrorSafe("duplicate JSON object key is not permitted")
        result[key] = value
    return result


def parse_json_line(raw, line_number):
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError, ImportErrorSafe, RecursionError) as exc:
        raise ImportErrorSafe(f"line {line_number}: invalid JSON input ({type(exc).__name__})") from None


def timestamp_to_ms(value, provider):
    if provider == "suricata":
        if not isinstance(value, str) or len(value) > 64:
            raise ImportErrorSafe("Suricata timestamp must be a bounded RFC3339 string")
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            result = parsed.timestamp() * 1000
        except (ValueError, OverflowError, OSError):
            raise ImportErrorSafe("invalid Suricata timestamp") from None
    else:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ImportErrorSafe("Zeek ts must be a numeric Unix timestamp")
        try:
            seconds = float(value)
        except (OverflowError, ValueError):
            raise ImportErrorSafe("invalid Zeek timestamp") from None
        if not math.isfinite(seconds) or seconds < 0:
            raise ImportErrorSafe("invalid Zeek timestamp")
        result = seconds * 1000
    if not math.isfinite(result) or result < 0 or result > 9_007_199_254_740_991:
        raise ImportErrorSafe("timestamp is outside supported bounds")
    return int(result)


def scalar_text(value):
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        text = str(value)
    else:
        return None
    if len(text.encode("utf-8")) > MAX_VALUE_BYTES:
        return None
    return text


def pick_fields(source, keys):
    result = {}
    for key in keys:
        if key in source:
            value = scalar_text(source[key])
            if value is not None:
                result[key] = value
    return dict(sorted(result.items())[:MAX_FIELDS])


def make_record(provider, tenant_id, provider_version, event_type, severity,
                observed_at_ms, source_ref, summary, fields):
    if not IDENTIFIER_RE.fullmatch(tenant_id):
        raise ImportErrorSafe("invalid tenant identifier")
    if not source_ref or len(source_ref.encode("utf-8")) > 256:
        source_ref = "unavailable"
    canonical = json.dumps(
        [provider, tenant_id, event_type, observed_at_ms, source_ref, fields],
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    event_id = hashlib.sha256(canonical).hexdigest()
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "tenant_id": tenant_id,
        "provider_id": provider,
        "provider_version": provider_version,
        "event_type": event_type,
        "severity": severity,
        "observed_at_unix_ms": observed_at_ms,
        "source_ref": source_ref,
        "summary": summary,
        "data_classification": "internal",
        "fields": fields,
    }


def normalize_suricata(obj, tenant_id, provider_version):
    if not isinstance(obj, dict):
        raise ImportErrorSafe("Suricata EVE record must be a JSON object")
    event_type = obj.get("event_type")
    if not isinstance(event_type, str) or event_type not in SURICATA_EVENT_TYPES:
        raise ImportErrorSafe("unsupported or missing Suricata event_type")
    observed = timestamp_to_ms(obj.get("timestamp"), "suricata")
    alert = obj.get("alert") if isinstance(obj.get("alert"), dict) else {}
    fields = pick_fields(obj, (
        "flow_id", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
        "app_proto", "pkt_src", "community_id",
    ))
    if event_type == "alert":
        fields.update(pick_fields(alert, ("signature_id", "signature", "category", "severity", "action")))
    fields = dict(sorted(fields.items())[:MAX_FIELDS])
    flow_id = scalar_text(obj.get("flow_id"))
    source_ref = f"flow:{flow_id}" if flow_id else f"line-event:{event_type}"
    severity_value = alert.get("severity")
    if isinstance(severity_value, bool) or not isinstance(severity_value, int):
        severity_value = None
    severity = {1: "high", 2: "medium", 3: "low"}.get(severity_value, "info")
    summary = "Suricata alert observed" if event_type == "alert" else f"Suricata {event_type} event observed"
    return make_record("suricata", tenant_id, provider_version,
                       f"suricata.{event_type}", severity, observed,
                       source_ref, summary, fields)


def normalize_zeek(obj, tenant_id, provider_version, log_kind):
    if not isinstance(obj, dict):
        raise ImportErrorSafe("Zeek record must be a JSON object")
    if log_kind not in ZEEK_FIELDS:
        raise ImportErrorSafe("unsupported Zeek log kind; choose conn, notice or weird")
    observed = timestamp_to_ms(obj.get("ts"), "zeek")
    fields = pick_fields(obj, ZEEK_FIELDS[log_kind])
    uid = scalar_text(obj.get("uid"))
    source_ref = f"uid:{uid}" if uid else f"zeek:{log_kind}:{observed}"
    severity = {"conn": "info", "notice": "medium", "weird": "low"}[log_kind]
    summary = {
        "conn": "Zeek connection observation",
        "notice": "Zeek notice observed",
        "weird": "Zeek protocol anomaly observed",
    }[log_kind]
    return make_record("zeek", tenant_id, provider_version,
                       f"zeek.{log_kind}", severity, observed,
                       source_ref, summary, fields)


def read_records(input_path, provider, tenant_id, provider_version, log_kind=None):
    path = Path(input_path)
    try:
        info = path.lstat()
    except OSError:
        raise ImportErrorSafe("input file cannot be accessed") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ImportErrorSafe("input must be a regular file, not a symlink")
    if info.st_size > MAX_INPUT_BYTES:
        raise ImportErrorSafe("input file exceeds the 256 MiB import limit")

    output = []
    output_bytes = 0
    input_bytes = 0
    try:
        with path.open("rb") as stream:
            for line_number, raw in enumerate(stream, start=1):
                input_bytes += len(raw)
                if input_bytes > MAX_INPUT_BYTES:
                    raise ImportErrorSafe("input grew beyond the 256 MiB import limit")
                if len(raw) > MAX_LINE_BYTES:
                    raise ImportErrorSafe(f"line {line_number}: exceeds the 1 MiB line limit")
                if not raw.strip() or (provider == "zeek" and raw.lstrip().startswith(b"#")):
                    continue
                if len(output) >= MAX_RECORDS:
                    raise ImportErrorSafe("input exceeds the 100,000 record limit")
                obj = parse_json_line(raw, line_number)
                if provider == "suricata":
                    record = normalize_suricata(obj, tenant_id, provider_version)
                else:
                    record = normalize_zeek(obj, tenant_id, provider_version, log_kind)
                encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
                output_bytes += len(encoded.encode("utf-8")) + 1
                if output_bytes > MAX_OUTPUT_BYTES:
                    raise ImportErrorSafe("normalized output exceeds the 256 MiB limit")
                output.append(encoded)
    except OSError:
        raise ImportErrorSafe("input file read failed") from None
    return output


def write_output(lines, output_path):
    payload = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    if output_path == "-":
        sys.stdout.buffer.write(payload)
        return
    destination = Path(output_path)
    parent = destination.parent
    if not parent.exists() or not parent.is_dir():
        raise ImportErrorSafe("output directory does not exist")
    if destination.is_symlink():
        raise ImportErrorSafe("output must not be a symlink")
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=parent, prefix=".ujani-import-", delete=False) as temp:
            temp_name = temp.name
            temp.write(payload)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_name, destination)
    except OSError:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        raise ImportErrorSafe("could not atomically write normalized output") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("suricata", "zeek"), required=True)
    parser.add_argument("--input", required=True, help="local JSON-lines log file")
    parser.add_argument("--output", default="-", help="output file or - for stdout")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--provider-version", default="unknown")
    parser.add_argument("--zeek-log-kind", choices=tuple(ZEEK_FIELDS))
    args = parser.parse_args(argv)
    if not TENANT_RE.fullmatch(args.tenant_id):
        parser.error("invalid tenant identifier")
    if not args.provider_version or len(args.provider_version) > 64:
        parser.error("provider version must be 1-64 characters")
    if args.provider == "zeek" and not args.zeek_log_kind:
        parser.error("--zeek-log-kind is required for Zeek imports")
    if args.provider == "suricata" and args.zeek_log_kind:
        parser.error("--zeek-log-kind is only valid with --provider zeek")
    if args.output != "-":
        source = Path(args.input)
        destination = Path(args.output)
        try:
            same_path = source.resolve() == destination.resolve()
            if source.exists() and destination.exists():
                same_path = same_path or os.path.samefile(source, destination)
        except OSError:
            parser.error("input/output path relationship cannot be verified")
        if same_path:
            parser.error("output must not overwrite the input log")
    try:
        lines = read_records(args.input, args.provider, args.tenant_id,
                             args.provider_version, args.zeek_log_kind)
        write_output(lines, args.output)
    except ImportErrorSafe as exc:
        print(f"UJANI import rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
