"""Tenant-scoped inventory and posture assessment for existing security products.

This is a pure policy/data-normalisation layer. It does not install agents, connect
to vendor APIs, store credentials, scan files, quarantine, isolate devices, or
perform remote actions. A trusted connector must authenticate upstream and bind
tenant/device identity before passing observations here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_LABEL = 160
MAX_SOURCE = 96
MAX_OBSERVATIONS = 64
MAX_CLOCK_SKEW_MS = 30_000


class InventoryError(ValueError):
    """Invalid or cross-tenant security provider evidence."""


class SecurityCategory(str, Enum):
    MALWARE_PROTECTION = "malware_protection"
    FIREWALL = "firewall"
    ENDPOINT_DETECTION_RESPONSE = "endpoint_detection_response"
    QUARANTINE = "quarantine"
    DEVICE_ISOLATION = "device_isolation"
    SECURITY_UPDATES = "security_updates"


class ProviderStatus(str, Enum):
    HEALTHY = "healthy"
    ATTENTION = "attention"
    ALERT = "alert"
    NOT_MONITORED = "not_monitored"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class Posture(str, Enum):
    REPORTED_HEALTHY = "reported_healthy"
    NEEDS_ATTENTION = "needs_attention"
    ALERT = "alert"
    NO_PROVIDER_REPORTED = "no_provider_reported"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class ProviderObservation:
    tenant_id: str
    device_id: str
    provider_id: str
    display_name: str | None
    category: SecurityCategory
    status: ProviderStatus
    evidence_source: str
    observed_at_unix_ms: int
    product_identity_known: bool = False
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class DevicePosture:
    tenant_id: str
    device_id: str
    category: SecurityCategory
    posture: Posture
    fresh_observations: int
    product_identity_known: bool
    capabilities: tuple[str, ...]
    recommendation: str


def _identifier(value: str) -> bool:
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))


def assess_device_category(
    *,
    tenant_id: str,
    device_id: str,
    category: SecurityCategory,
    observations: tuple[ProviderObservation, ...] | list[ProviderObservation],
    now_unix_ms: int,
    max_age_ms: int,
) -> DevicePosture:
    if not _identifier(tenant_id) or not _identifier(device_id):
        raise InventoryError("tenant or device identity is invalid")
    if isinstance(now_unix_ms, bool) or not isinstance(now_unix_ms, int) or now_unix_ms < 0:
        raise InventoryError("current timestamp is invalid")
    if isinstance(max_age_ms, bool) or not isinstance(max_age_ms, int) or max_age_ms < 0:
        raise InventoryError("evidence age limit is invalid")
    if len(observations) > MAX_OBSERVATIONS:
        raise InventoryError("provider observation limit exceeded")

    relevant = []
    for item in observations:
        if item.tenant_id != tenant_id or item.device_id != device_id:
            raise InventoryError("cross-tenant or cross-device evidence rejected")
        if not _identifier(item.provider_id):
            raise InventoryError("provider identifier is invalid")
        if not isinstance(item.evidence_source, str) or not 1 <= len(item.evidence_source) <= MAX_SOURCE:
            raise InventoryError("evidence source is invalid")
        if any(ord(ch) < 32 for ch in item.evidence_source):
            raise InventoryError("evidence source contains control characters")
        if item.display_name is not None and (
            not isinstance(item.display_name, str)
            or not 1 <= len(item.display_name) <= MAX_LABEL
            or any(ord(ch) < 32 for ch in item.display_name)
        ):
            raise InventoryError("provider display name is invalid")
        if isinstance(item.observed_at_unix_ms, bool) or not isinstance(item.observed_at_unix_ms, int):
            raise InventoryError("provider timestamp is invalid")
        if item.category is category:
            if (
                item.observed_at_unix_ms <= now_unix_ms + MAX_CLOCK_SKEW_MS
                and now_unix_ms - item.observed_at_unix_ms <= max_age_ms
            ):
                relevant.append(item)

    if any(item.status is ProviderStatus.ALERT for item in relevant):
        posture = Posture.ALERT
        recommendation = "Review the existing endpoint security product's alert and follow the organisation's incident procedure."
    elif any(item.status is ProviderStatus.ATTENTION for item in relevant):
        posture = Posture.NEEDS_ATTENTION
        recommendation = "Ask the device owner or administrator to review the existing product's warning."
    elif any(item.status is ProviderStatus.HEALTHY for item in relevant):
        posture = Posture.REPORTED_HEALTHY
        recommendation = "Keep the existing product enabled; verify update, scan and response capabilities where the provider exposes them."
    elif any(item.status is ProviderStatus.NOT_MONITORED for item in relevant):
        posture = Posture.NO_PROVIDER_REPORTED
        recommendation = "No provider is reported for this category; ask the administrator to review approved protection options."
    else:
        posture = Posture.UNVERIFIED
        recommendation = "Security posture is unverified; do not assume protection. Check the operating system or configured security console."

    capabilities = tuple(sorted({cap for item in relevant for cap in item.capabilities if _identifier(cap)}))
    return DevicePosture(
        tenant_id=tenant_id,
        device_id=device_id,
        category=category,
        posture=posture,
        fresh_observations=len(relevant),
        product_identity_known=any(item.product_identity_known for item in relevant),
        capabilities=capabilities,
        recommendation=recommendation,
    )
