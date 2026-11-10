"""Authenticated trusted-device envelope verification for security evidence ingestion.

This module is an authentication boundary, not an HTTP server. A future receiver
must call authenticate_envelope before parsing or storing event data and must
obtain the registry from protected operator-managed configuration.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Mapping, Any

DEVICE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
TENANT_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
MAX_BODY_BYTES = 256 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
NONCE_RETENTION_SECONDS = 600


class AuthenticationError(ValueError):
    """A request failed trusted-device authentication."""


def _open_replay_db(path: str | os.PathLike[str]) -> sqlite3.Connection:
    target = Path(path)
    db: sqlite3.Connection | None = None
    try:
        if target.is_symlink():
            raise AuthenticationError("replay database path is unsafe")
        if not target.parent.exists() or not target.parent.is_dir():
            raise AuthenticationError("replay database parent must exist")
        db = sqlite3.connect(str(target), timeout=5.0, isolation_level=None)
        # Restrict the main database before enabling WAL, which may create
        # companion files. The containing directory must still be protected
        # from untrusted writers by the host deployment.
        os.chmod(target, 0o600)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY(device_id, nonce)
            )
        """)
        return db
    except AuthenticationError:
        if db is not None:
            db.close()
        raise
    except (OSError, sqlite3.Error):
        if db is not None:
            try:
                db.close()
            except sqlite3.Error:
                pass
        raise AuthenticationError("replay protection storage unavailable") from None


def sign_envelope(secret: bytes, timestamp: int, nonce: str, body: bytes) -> str:
    """Create the HMAC-SHA256 signature used by a trusted device agent."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise AuthenticationError("device signing key is invalid")
    message = str(timestamp).encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def authenticate_envelope(*, device_id: str, timestamp: int, nonce: str,
                           body: bytes, signature: str,
                           registry: Mapping[str, Mapping[str, Any]],
                           replay_database: str | os.PathLike[str],
                           now_seconds: int | None = None) -> str:
    """Verify device identity, HMAC, freshness and one-time nonce; return trusted tenant."""
    now = int(time.time()) if now_seconds is None else now_seconds
    if (isinstance(now, bool) or not isinstance(now, int) or now < 0
            or isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0
            or abs(now - timestamp) > MAX_CLOCK_SKEW_SECONDS):
        raise AuthenticationError("request authentication failed")
    if (not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id)
            or not isinstance(nonce, str) or not NONCE.fullmatch(nonce)
            or not isinstance(body, bytes) or not 1 <= len(body) <= MAX_BODY_BYTES
            or not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{64}", signature)):
        raise AuthenticationError("request authentication failed")
    entry = registry.get(device_id)
    if not isinstance(entry, Mapping) or entry.get("revoked") is not False:
        raise AuthenticationError("request authentication failed")
    tenant_id = entry.get("tenant_id")
    secret = entry.get("secret")
    if (not isinstance(tenant_id, str) or not TENANT_ID.fullmatch(tenant_id)
            or not isinstance(secret, bytes) or len(secret) < 32):
        raise AuthenticationError("request authentication failed")
    expected = sign_envelope(secret, timestamp, nonce, body)
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("request authentication failed")

    db = _open_replay_db(replay_database)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM consumed_nonces WHERE expires_at < ?", (now,))
        try:
            db.execute(
                "INSERT INTO consumed_nonces(device_id, nonce, expires_at) VALUES (?, ?, ?)",
                (device_id, nonce, now + NONCE_RETENTION_SECONDS),
            )
        except sqlite3.IntegrityError:
            db.execute("ROLLBACK")
            raise AuthenticationError("request authentication failed") from None
        db.execute("COMMIT")
    except AuthenticationError:
        raise
    except sqlite3.Error:
        try:
            db.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise AuthenticationError("replay protection storage unavailable") from None
    finally:
        db.close()
    return tenant_id
