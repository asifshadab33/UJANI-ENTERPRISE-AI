#!/usr/bin/env python3
"""Tenant-scoped, bounded SQLite storage and search for normalized security evidence.

This is a local storage primitive, not a network listener or authentication service.
The caller must authenticate the principal and derive tenant_id from trusted context.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

PROVIDERS = {"suricata", "zeek", "malcolm", "opnsense", "misp"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_EVENT_BYTES = 16 * 1024
MAX_BATCH = 500
MAX_PAGE = 100
MAX_SUMMARY = 512
MAX_FIELDS = 32
MAX_FIELD_VALUE = 1024
MAX_FUTURE_SKEW_MS = 30_000


class StoreError(ValueError):
    """A rejected event, query or storage operation."""


class SecurityEventStore:
    """Small local evidence store. All reads and writes require an explicit tenant."""

    def __init__(self, database: str | os.PathLike[str], *, max_records_per_tenant: int = 100_000,
                 retention_ms: int = 30 * 24 * 60 * 60 * 1000) -> None:
        if not 1 <= max_records_per_tenant <= 10_000_000:
            raise StoreError("max_records_per_tenant is outside supported bounds")
        if not 60_000 <= retention_ms <= 365 * 24 * 60 * 60 * 1000:
            raise StoreError("retention_ms is outside supported bounds")
        self.database = str(database)
        self.max_records_per_tenant = max_records_per_tenant
        self.retention_ms = retention_ms
        self._lock = threading.RLock()
        if self.database != ":memory:":
            path = Path(self.database)
            if path.exists() and path.is_symlink():
                raise StoreError("database path must not be a symlink")
            if not path.parent.exists() or not path.parent.is_dir():
                raise StoreError("database parent directory must already exist")
        self._db = sqlite3.connect(self.database, timeout=5.0, isolation_level=None,
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA trusted_schema=OFF")
        self._db.execute("PRAGMA busy_timeout=5000")
        if self.database != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
            try:
                os.chmod(self.database, 0o600)
            except OSError:
                self._db.close()
                raise StoreError("could not restrict database file permissions") from None
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS security_events (
                tenant_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                ingested_at_ms INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, provider_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_events_tenant_time
                ON security_events (tenant_id, observed_at_ms DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS idx_events_tenant_provider_time
                ON security_events (tenant_id, provider_id, observed_at_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_events_tenant_type_time
                ON security_events (tenant_id, event_type, observed_at_ms DESC);
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @staticmethod
    def _validate_event(event: Any, tenant_id: str, provider_id: str, now_ms: int) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise StoreError("event must be an object")
        required = {"schema_version", "event_id", "tenant_id", "provider_id",
                    "provider_version", "event_type", "severity", "observed_at_unix_ms",
                    "source_ref", "summary", "data_classification", "fields"}
        if set(event) != required:
            raise StoreError("event fields do not match the normalized evidence contract")
        if event["schema_version"] != "1.0" or event["data_classification"] != "internal":
            raise StoreError("unsupported schema or data classification")
        if event["tenant_id"] != tenant_id or event["provider_id"] != provider_id:
            raise StoreError("tenant or provider boundary violation")
        if (not isinstance(tenant_id, str) or not IDENTIFIER.fullmatch(tenant_id)
                or not isinstance(provider_id, str) or provider_id not in PROVIDERS):
            raise StoreError("invalid tenant or unsupported provider")
        if not isinstance(event["event_id"], str) or not re.fullmatch(r"[a-f0-9]{64}", event["event_id"]):
            raise StoreError("event_id must be a SHA-256 hex digest")
        if not isinstance(event["provider_version"], str) or not 1 <= len(event["provider_version"]) <= 64:
            raise StoreError("invalid provider version")
        if not isinstance(event["event_type"], str) or not 1 <= len(event["event_type"]) <= 96:
            raise StoreError("invalid event type")
        if not isinstance(event["severity"], str) or event["severity"] not in SEVERITIES:
            raise StoreError("invalid severity")
        observed = event["observed_at_unix_ms"]
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
            raise StoreError("invalid event timestamp")
        if observed > now_ms + MAX_FUTURE_SKEW_MS:
            raise StoreError("event timestamp is too far in the future")
        if not isinstance(event["source_ref"], str) or not 1 <= len(event["source_ref"].encode("utf-8")) <= 256:
            raise StoreError("invalid source reference")
        if not isinstance(event["summary"], str) or len(event["summary"].encode("utf-8")) > MAX_SUMMARY:
            raise StoreError("invalid event summary")
        fields = event["fields"]
        if not isinstance(fields, dict) or len(fields) > MAX_FIELDS:
            raise StoreError("invalid event fields")
        for key, value in fields.items():
            if not isinstance(key, str) or not 1 <= len(key.encode("utf-8")) <= 96:
                raise StoreError("invalid event field name")
            if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FIELD_VALUE:
                raise StoreError("invalid event field value")
        try:
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError):
            raise StoreError("event is not JSON serializable") from None
        if len(encoded.encode("utf-8")) > MAX_EVENT_BYTES:
            raise StoreError("event exceeds the 16 KiB storage limit")
        return {"event": event, "encoded": encoded, "observed": observed}

    def ingest(self, events: Iterable[dict[str, Any]], *, tenant_id: str, provider_id: str,
               now_ms: int | None = None) -> int:
        """Atomically insert one bounded provider batch; duplicate IDs are idempotent."""
        current = int(time.time() * 1000) if now_ms is None else now_ms
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise StoreError("invalid ingestion clock")
        if not IDENTIFIER.fullmatch(tenant_id) or provider_id not in PROVIDERS:
            raise StoreError("invalid tenant or unsupported provider")
        batch = list(events)
        if not 1 <= len(batch) <= MAX_BATCH:
            raise StoreError("batch must contain between 1 and 500 events")
        validated = [self._validate_event(item, tenant_id, provider_id, current) for item in batch]
        cutoff = current - self.retention_ms
        if any(item["observed"] < cutoff for item in validated):
            raise StoreError("event is older than the configured retention window")
        inserted = 0
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute("DELETE FROM security_events WHERE tenant_id=? AND observed_at_ms < ?",
                                 (tenant_id, cutoff))
                for item in validated:
                    event = item["event"]
                    cursor = self._db.execute("""
                        INSERT OR IGNORE INTO security_events
                        (tenant_id, provider_id, event_id, observed_at_ms, ingested_at_ms,
                         event_type, severity, summary, payload_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (tenant_id, provider_id, event["event_id"], item["observed"], current,
                          event["event_type"], event["severity"], event["summary"], item["encoded"]))
                    inserted += cursor.rowcount
                excess = self._db.execute(
                    "SELECT MAX(COUNT(*) - ?, 0) FROM security_events WHERE tenant_id=?",
                    (self.max_records_per_tenant, tenant_id),
                ).fetchone()[0]
                if excess:
                    self._db.execute("""
                        DELETE FROM security_events WHERE rowid IN (
                            SELECT rowid FROM security_events WHERE tenant_id=?
                            ORDER BY observed_at_ms ASC, event_id ASC LIMIT ?
                        )
                    """, (tenant_id, excess))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return inserted

    def search(self, *, tenant_id: str, provider_id: str | None = None,
               event_type: str | None = None, severity: str | None = None,
               text_query: str | None = None, since_ms: int | None = None,
               until_ms: int | None = None, after: tuple[int, str] | None = None,
               limit: int = 50) -> list[dict[str, Any]]:
        """Search a single tenant using indexed filters and keyset pagination."""
        if not isinstance(tenant_id, str) or not IDENTIFIER.fullmatch(tenant_id):
            raise StoreError("a valid tenant scope is required")
        if not 1 <= limit <= MAX_PAGE:
            raise StoreError("limit must be between 1 and 100")
        clauses = ["tenant_id=?"]
        params: list[Any] = [tenant_id]
        if provider_id is not None:
            if provider_id not in PROVIDERS:
                raise StoreError("unsupported provider")
            clauses.append("provider_id=?")
            params.append(provider_id)
        if event_type is not None:
            if not isinstance(event_type, str) or not 1 <= len(event_type) <= 96:
                raise StoreError("invalid event type filter")
            clauses.append("event_type=?")
            params.append(event_type)
        if severity is not None:
            if severity not in SEVERITIES:
                raise StoreError("invalid severity filter")
            clauses.append("severity=?")
            params.append(severity)
        if text_query is not None:
            if not isinstance(text_query, str) or not 1 <= len(text_query) <= 128:
                raise StoreError("invalid text query")
            escaped = text_query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("summary LIKE ? ESCAPE '\\'")
            params.append("%" + escaped + "%")
        for field, value, op in (("observed_at_ms", since_ms, ">="), ("observed_at_ms", until_ms, "<=")):
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise StoreError("invalid time filter")
                clauses.append(f"{field} {op} ?")
                params.append(value)
        if after is not None:
            if (not isinstance(after, tuple) or len(after) != 2
                    or isinstance(after[0], bool) or not isinstance(after[0], int)
                    or not isinstance(after[1], str) or not re.fullmatch(r"[a-f0-9]{64}", after[1])):
                raise StoreError("invalid pagination cursor")
            clauses.append("(observed_at_ms < ? OR (observed_at_ms = ? AND event_id < ?))")
            params.extend((after[0], after[0], after[1]))
        params.append(limit)
        sql = ("SELECT payload_json FROM security_events WHERE " + " AND ".join(clauses)
               + " ORDER BY observed_at_ms DESC, event_id DESC LIMIT ?")
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def count(self, *, tenant_id: str) -> int:
        if not IDENTIFIER.fullmatch(tenant_id):
            raise StoreError("a valid tenant scope is required")
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS total FROM security_events WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        return int(row["total"])
