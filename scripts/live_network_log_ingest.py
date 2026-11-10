#!/usr/bin/env python3
"""Follow local Suricata EVE or Zeek JSONL logs into the tenant-scoped evidence store.

At-least-once delivery: event IDs make a crash between DB commit and checkpoint
safe to replay. Start at end by default; --from-start imports existing complete lines.
A single process must own a given checkpoint file.
"""
import argparse
import json
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

from scripts.normalize_network_logs import (
    ImportErrorSafe, parse_json_line, normalize_suricata, normalize_zeek,
)
from scripts.security_event_store import SecurityEventStore, StoreError

MAX_LINE_BYTES = 1024 * 1024
MAX_BATCH_RECORDS = 250


def _safe_open(path):
    path = Path(path)
    if os.name == "nt":
        try:
            before = os.lstat(path)
        except OSError:
            raise ImportErrorSafe("log path could not be inspected") from None
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(before.st_mode) or (getattr(before, "st_file_attributes", 0) & reparse):
            raise ImportErrorSafe("log path must not be a symlink or reparse point")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    else:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        non_blocking = getattr(os, "O_NONBLOCK", None)
        if no_follow is None or non_blocking is None:
            raise ImportErrorSafe("platform lacks safe no-follow log open support")
        flags = os.O_RDONLY | no_follow | non_blocking | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise ImportErrorSafe("log input must be a regular file")
        if os.name == "nt" and (
            not before.st_ino or not info.st_ino
            or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)
        ):
            os.close(fd)
            raise ImportErrorSafe("log path changed during safe open")
        return fd, info
    except ImportErrorSafe:
        raise
    except OSError:
        raise ImportErrorSafe("log file could not be safely opened") from None


def _load_checkpoint(path, tenant_id, provider_id):
    path = Path(path)
    if not path.exists():
        return None
    if path.is_symlink():
        raise ImportErrorSafe("checkpoint must not be a symlink")
    try:
        raw = path.read_bytes()
        if len(raw) > 4096:
            raise ImportErrorSafe("checkpoint exceeds size limit")
        value = json.loads(raw.decode("utf-8"))
    except ImportErrorSafe:
        raise
    except (OSError, UnicodeDecodeError, ValueError):
        raise ImportErrorSafe("checkpoint is unreadable or malformed") from None
    expected = {"schema_version", "tenant_id", "provider_id", "device", "inode", "offset"}
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != 1:
        raise ImportErrorSafe("checkpoint contract mismatch")
    if value["tenant_id"] != tenant_id or value["provider_id"] != provider_id:
        raise ImportErrorSafe("checkpoint tenant/provider scope mismatch")
    if any(isinstance(value[k], bool) or not isinstance(value[k], int) or value[k] < 0
           for k in ("device", "inode", "offset")):
        raise ImportErrorSafe("checkpoint cursor is invalid")
    return value


def _save_checkpoint(path, value):
    destination = Path(path)
    if not destination.parent.exists() or not destination.parent.is_dir():
        raise ImportErrorSafe("checkpoint parent directory must exist")
    if destination.is_symlink():
        raise ImportErrorSafe("checkpoint must not be a symlink")
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent,
                                         prefix=".ujani-cursor-", delete=False) as temp:
            temp_name = temp.name
            os.chmod(temp_name, 0o600)
            json.dump(value, temp, sort_keys=True, separators=(",", ":"))
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_name, destination)
    except OSError:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        raise ImportErrorSafe("checkpoint could not be atomically saved") from None


def ingest_once(*, log_path, database, checkpoint, provider, tenant_id,
                provider_version="unknown", from_start=False, now_ms=None):
    if provider not in ("zeek", "suricata"):
        raise ImportErrorSafe("provider must be zeek or suricata")
    if not tenant_id or len(tenant_id) > 128:
        raise ImportErrorSafe("invalid tenant identifier")
    cursor = _load_checkpoint(checkpoint, tenant_id, provider)
    fd, info = _safe_open(log_path)
    try:
        identity = (int(info.st_dev), int(info.st_ino))
        if cursor is None:
            offset = 0 if from_start else int(info.st_size)
        elif (cursor["device"], cursor["inode"]) != identity or cursor["offset"] > info.st_size:
            # Rotation or truncation: begin at the new file's start.
            offset = 0
        else:
            offset = cursor["offset"]
        stream = os.fdopen(fd, "rb")
        fd = -1
        records = []
        with stream:
            stream.seek(offset)
            next_offset = offset
            while len(records) < MAX_BATCH_RECORDS:
                raw = stream.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE_BYTES:
                    raise ImportErrorSafe("log line exceeds the 1 MiB limit")
                if not raw.endswith(b"\n"):
                    # Do not advance past a partially-written final record.
                    break
                next_offset += len(raw)
                if not raw.strip() or (provider == "zeek" and raw.lstrip().startswith(b"#")):
                    continue
                obj = parse_json_line(raw, len(records) + 1)
                if provider == "suricata":
                    record = normalize_suricata(obj, tenant_id, provider_version)
                else:
                    record = normalize_zeek(obj, tenant_id, provider_version, "conn")
                records.append(record)
        inserted = 0
        # Commit the DB batch before advancing the cursor; replay is idempotent.
        store = SecurityEventStore(database)
        try:
            if records:
                inserted = store.ingest(records, tenant_id=tenant_id, provider_id=provider, now_ms=now_ms)
        finally:
            store.close()
        checkpoint_value = {
            "schema_version": 1, "tenant_id": tenant_id, "provider_id": provider,
            "device": identity[0], "inode": identity[1], "offset": next_offset,
        }
        _save_checkpoint(checkpoint, checkpoint_value)
        return inserted, len(records), next_offset
    finally:
        if fd >= 0:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("zeek", "suricata"), required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--provider-version", default="unknown")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if not 0.25 <= args.poll_seconds <= 60:
        parser.error("--poll-seconds must be between 0.25 and 60")
    try:
        while True:
            inserted, read_count, offset = ingest_once(
                log_path=args.input, database=args.database, checkpoint=args.checkpoint,
                provider=args.provider, tenant_id=args.tenant_id,
                provider_version=args.provider_version, from_start=args.from_start,
            )
            args.from_start = False
            print(f"UJANI {args.provider}: read={read_count} inserted={inserted} offset={offset}")
            if args.once:
                return 0
            time.sleep(args.poll_seconds)
    except (ImportErrorSafe, StoreError) as exc:
        print(f"UJANI live import stopped safely: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
