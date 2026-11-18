"""Tenant-scoped inventory and posture assessment for existing security products.

This is a pure policy/data-normalisation layer. It does not install agents, connect
to vendor APIs, store credentials, scan files, quarantine, isolate devices, or
perform remote actions. A trusted connector must authenticate upstream and bind
tenant/device identity before passing observations here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re
from typing import Mapping

IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_LABEL = 160
MAX_SOURCE = 96
MAX_PROVIDER_ID = 96
MAX_CAPABILITY_LEN = 96
MAX_EVIDENCE_FIELDS = 32
MAX_FIELD_KEY_BYTES = 96
MAX_FIELD_VALUE_BYTES = 1024
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


class UpdateStatus(str, Enum):
    """Provider-verified update state; UJANI does not compare guessed version numbers."""

    CURRENT = "current"
    OUT_OF_DATE = "out_of_date"
    UNKNOWN = "unknown"


class UpdatePosture(str, Enum):
    CURRENT = "current"
    OUT_OF_DATE = "out_of_date"
    UNVERIFIED = "unverified"
    NOT_REPORTED = "not_reported"


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
    update_status: UpdateStatus = UpdateStatus.UNKNOWN
    update_checked_at_unix_ms: int | None = None
    update_channel: str | None = None


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
    update_posture: UpdatePosture
    update_recommendation: str


def _identifier(value: str) -> bool:
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))



def observation_from_validated_connector_record(
    *,
    authenticated_tenant_id: str,
    enrolled_device_id: str,
    expected_provider_id: str,
    record: Mapping[str, object],
) -> ProviderObservation:
    """Map one already-validated Rust EvidenceRecord into inventory posture.

    The caller must first run the existing connector contract's request/page
    validation and supply tenant/device identity from authenticated host state.
    EvidenceRecord itself does not carry an enrolled device ID; never derive that
    identity from provider-controlled fields or payloads.
    """
    if (
        not _identifier(authenticated_tenant_id)
        or not _identifier(enrolled_device_id)
        or not _identifier(expected_provider_id)
        or len(expected_provider_id) > MAX_PROVIDER_ID
    ):
        raise InventoryError("authenticated tenant, device or provider identity is invalid")
    if not isinstance(record, Mapping):
        raise InventoryError("connector evidence record is invalid")
    if record.get("tenant_id") != authenticated_tenant_id:
        raise InventoryError("cross-tenant connector evidence rejected")
    if record.get("provider_id") != expected_provider_id:
        raise InventoryError("unexpected connector provider identity")
    observed_at = record.get("observed_at_unix_ms")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise InventoryError("connector observation timestamp is invalid")
    fields = record.get("fields")
    if (
        not isinstance(fields, Mapping)
        or len(fields) > MAX_EVIDENCE_FIELDS
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or len(key.encode("utf-8")) > MAX_FIELD_KEY_BYTES
            or len(value.encode("utf-8")) > MAX_FIELD_VALUE_BYTES
            for key, value in fields.items()
        )
    ):
        raise InventoryError("connector evidence fields are invalid")

    try:
        category = SecurityCategory(fields.get("category", ""))
        status = ProviderStatus(fields.get("status", "unknown"))
        update_status = UpdateStatus(fields.get("update_status", "unknown"))
    except ValueError as exc:
        raise InventoryError("connector evidence contains an unsupported category or status") from exc

    identity_flag = fields.get("product_identity_known", "false")
    if identity_flag not in ("true", "false"):
        raise InventoryError("connector product-identity flag is invalid")

    raw_capabilities = fields.get("capabilities", "[]")
    try:
        capabilities = json.loads(raw_capabilities)
    except (TypeError, ValueError) as exc:
        raise InventoryError("connector capability list is invalid") from exc
    if (
        not isinstance(capabilities, list)
        or len(capabilities) > 32
        or any(
            not isinstance(item, str) or not _identifier(item) or len(item) > MAX_CAPABILITY_LEN
            for item in capabilities
        )
    ):
        raise InventoryError("connector capability list is invalid")

    raw_update_checked = fields.get("update_checked_at_unix_ms")
    if raw_update_checked is None:
        update_checked_at = None
    elif re.fullmatch(r"[0-9]{1,16}", raw_update_checked):
        update_checked_at = int(raw_update_checked)
    else:
        raise InventoryError("connector update-check timestamp is invalid")

    display_name = fields.get("display_name")
    if display_name is not None and (
        not 1 <= len(display_name) <= MAX_LABEL
        or any(ord(ch) < 32 for ch in display_name)
    ):
        raise InventoryError("connector display name is invalid")

    update_channel = fields.get("update_channel")
    if update_channel is not None and (
        not 1 <= len(update_channel) <= MAX_LABEL
        or any(ord(ch) < 32 for ch in update_channel)
    ):
        raise InventoryError("connector update channel is invalid")

    return ProviderObservation(
        tenant_id=authenticated_tenant_id,
        device_id=enrolled_device_id,
        provider_id=expected_provider_id,
        display_name=display_name,
        category=category,
        status=status,
        evidence_source="validated read-only connector evidence",
        observed_at_unix_ms=observed_at,
        product_identity_known=(identity_flag == "true"),
        capabilities=tuple(capabilities),
        update_status=update_status,
        update_checked_at_unix_ms=update_checked_at,
        update_channel=update_channel,
    )


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
    if not isinstance(observations, (tuple, list)) or len(observations) > MAX_OBSERVATIONS:
        raise InventoryError("provider observation limit exceeded")

    relevant = []
    for item in observations:
        if not isinstance(item, ProviderObservation):
            raise InventoryError("provider observation record is invalid")
        if not isinstance(item.category, SecurityCategory) or not isinstance(item.status, ProviderStatus):
            raise InventoryError("provider category or health status is invalid")
        if not isinstance(item.product_identity_known, bool):
            raise InventoryError("provider product-identity flag is invalid")
        if not isinstance(item.capabilities, tuple) or len(item.capabilities) > 32 or any(
            not _identifier(capability) or len(capability) > MAX_CAPABILITY_LEN
            for capability in item.capabilities
        ):
            raise InventoryError("provider capability list is invalid")
        if item.tenant_id != tenant_id or item.device_id != device_id:
            raise InventoryError("cross-tenant or cross-device evidence rejected")
        if not _identifier(item.provider_id) or len(item.provider_id) > MAX_PROVIDER_ID:
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
        if (
            isinstance(item.observed_at_unix_ms, bool)
            or not isinstance(item.observed_at_unix_ms, int)
            or item.observed_at_unix_ms <= 0
        ):
            raise InventoryError("provider timestamp is invalid")
        if not isinstance(item.update_status, UpdateStatus):
            raise InventoryError("update status is invalid")
        if item.update_checked_at_unix_ms is not None and (
            isinstance(item.update_checked_at_unix_ms, bool)
            or not isinstance(item.update_checked_at_unix_ms, int)
            or item.update_checked_at_unix_ms <= 0
        ):
            raise InventoryError("update-check timestamp is invalid")
        if item.update_channel is not None and (
            not isinstance(item.update_channel, str)
            or not 1 <= len(item.update_channel) <= MAX_LABEL
            or any(ord(ch) < 32 for ch in item.update_channel)
        ):
            raise InventoryError("update channel is invalid")
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

    # Update currency is independent from provider health. Only a fresh,
    # provider-authenticated explicit state is accepted; version strings alone
    # and old observations never prove that a product is current.
    update_evidence = []
    for item in relevant:
        checked = item.update_checked_at_unix_ms
        if item.update_status is UpdateStatus.UNKNOWN or checked is None:
            continue
        if isinstance(checked, bool) or not isinstance(checked, int):
            raise InventoryError("update-check timestamp is invalid")
        if checked < 0 or checked > now_unix_ms + MAX_CLOCK_SKEW_MS:
            raise InventoryError("update-check timestamp is invalid")
        if now_unix_ms - checked <= max_age_ms:
            update_evidence.append(item)

    if any(item.update_status is UpdateStatus.OUT_OF_DATE for item in update_evidence):
        update_posture = UpdatePosture.OUT_OF_DATE
        update_recommendation = (
            "Security product updates are reported out of date. Warn the device owner or "
            "administrator and ask them to update the antivirus security intelligence/engine "
            "or firewall software and rule/signature feeds through the existing vendor or OS workflow."
        )
    elif relevant and len(update_evidence) == len(relevant) and all(item.update_status is UpdateStatus.CURRENT for item in update_evidence):
        update_posture = UpdatePosture.CURRENT
        update_recommendation = "The configured provider reports its checked security updates are current; continue normal update monitoring."
    elif any(item.update_status is not UpdateStatus.UNKNOWN for item in relevant):
        update_posture = UpdatePosture.UNVERIFIED
        update_recommendation = (
            "Update status evidence is stale or incomplete. Ask the device owner or administrator "
            "to check the product's latest security intelligence, engine, platform and firewall updates."
        )
    else:
        update_posture = UpdatePosture.NOT_REPORTED
        update_recommendation = (
            "UJANI cannot verify whether antivirus definitions, engine/platform or firewall "
            "updates are current. Check the existing product or operating-system security console."
        )

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
        update_posture=update_posture,
        update_recommendation=update_recommendation,
    )
