"""Authenticate trusted-device batches before parsing and tenant-scoped storage.

This is a library boundary, not an HTTP listener. The provider identity is supplied
by trusted host configuration; tenant identity is derived only from the device registry.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

from scripts.security_event_store import MAX_BATCH, SecurityEventStore, StoreError
from scripts.trusted_device_ingest_auth import (
    AuthenticationError,
    authenticate_envelope,
)


class IngestionEnvelopeError(ValueError):
    """The authenticated request body does not match the bounded batch contract."""


def authenticate_and_ingest(
    *,
    device_id: str,
    timestamp: int,
    nonce: str,
    body: bytes,
    signature: str,
    registry: Mapping[str, Mapping[str, Any]],
    replay_database: str,
    store: SecurityEventStore,
    provider_id: str,
    now_seconds: int | None = None,
    now_ms: int | None = None,
) -> int:
    """Authenticate raw bytes first, then overwrite tenant/provider from trusted context."""
    tenant_id = authenticate_envelope(
        device_id=device_id,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        signature=signature,
        registry=registry,
        replay_database=replay_database,
        now_seconds=now_seconds,
    )

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise IngestionEnvelopeError("authenticated event batch is malformed") from None
    if not isinstance(payload, dict) or set(payload) != {"events"}:
        raise IngestionEnvelopeError("authenticated event batch contract mismatch")
    events = payload["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH:
        raise IngestionEnvelopeError("authenticated event batch is outside supported bounds")
    if any(not isinstance(event, dict) for event in events):
        raise IngestionEnvelopeError("authenticated event records must be objects")

    # Never trust tenant/provider labels carried inside the signed event payload.
    # Device-to-tenant mapping comes from the authenticated registry; provider
    # identity comes from the trusted host connector configuration.
    scoped_events = []
    for event in events:
        scoped = dict(event)
        scoped["tenant_id"] = tenant_id
        scoped["provider_id"] = provider_id
        scoped_events.append(scoped)

    try:
        return store.ingest(
            scoped_events,
            tenant_id=tenant_id,
            provider_id=provider_id,
            now_ms=now_ms,
        )
    except StoreError:
        raise
