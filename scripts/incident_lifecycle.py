"""Pure incident lifecycle policy for UJANI Enterprise.

This module validates proposed state transitions only. It does not authenticate actors,
persist incidents, revoke leases, contact devices, isolate networks, or execute commands.
The host service must supply trusted tenant/actor context and durable replay protection.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import re

IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")


class IncidentError(ValueError):
    """A transition failed closed."""


class IncidentState(str, Enum):
    OBSERVED = "observed"
    TRIAGED = "triaged"
    COMPUTE_SUSPENSION_REQUESTED = "compute_suspension_requested"
    COMPUTE_SUSPENSION_CONFIRMED = "compute_suspension_confirmed"
    RECOVERY_PENDING = "recovery_pending"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentAction(str, Enum):
    TRIAGE = "triage"
    REQUEST_COMPUTE_SUSPENSION = "request_compute_suspension"
    CONFIRM_COMPUTE_SUSPENSION = "confirm_compute_suspension"
    BEGIN_RECOVERY = "begin_recovery"
    RESOLVE = "resolve"
    DISMISS = "dismiss"


@dataclass(frozen=True)
class IncidentSnapshot:
    tenant_id: str
    incident_id: str
    device_id: str
    state: IncidentState = IncidentState.OBSERVED
    version: int = 0


@dataclass(frozen=True)
class TransitionCommand:
    tenant_id: str
    actor_role: str
    action: IncidentAction
    expected_version: int
    evidence_ref: str
    tenant_admin_opt_in: bool = False
    device_owner_opt_in: bool = False
    approval_digest_valid: bool = False
    controller_receipt_valid: bool = False


def _valid_identifier(value: str) -> bool:
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))


def transition_incident(
    current: IncidentSnapshot,
    command: TransitionCommand,
) -> IncidentSnapshot:
    """Return a new snapshot or reject; never performs the represented action."""
    if not all(_valid_identifier(value) for value in (
        current.tenant_id, current.incident_id, current.device_id, command.tenant_id
    )):
        raise IncidentError("incident or tenant identifier is invalid")
    if command.tenant_id != current.tenant_id:
        raise IncidentError("tenant boundary violation")
    if (isinstance(command.expected_version, bool)
            or not isinstance(command.expected_version, int)
            or command.expected_version < 0
            or isinstance(current.version, bool)
            or not isinstance(current.version, int)
            or current.version < 0
            or command.expected_version != current.version):
        raise IncidentError("stale or invalid incident version")
    if not _valid_identifier(command.evidence_ref):
        raise IncidentError("a bounded evidence reference is required")

    role = command.actor_role
    if not isinstance(role, str) or role not in {"tenant_admin", "security_operator", "device_owner", "trusted_controller"}:
        raise IncidentError("actor role is not authorised for incident workflow")

    next_state: IncidentState
    if command.action is IncidentAction.TRIAGE:
        if role not in {"tenant_admin", "security_operator"} or current.state is not IncidentState.OBSERVED:
            raise IncidentError("triage is not permitted from this state or role")
        next_state = IncidentState.TRIAGED

    elif command.action is IncidentAction.REQUEST_COMPUTE_SUSPENSION:
        if role not in {"tenant_admin", "security_operator"}:
            raise IncidentError("only an authorised tenant operator may request suspension")
        if current.state not in {IncidentState.OBSERVED, IncidentState.TRIAGED}:
            raise IncidentError("compute suspension request is not valid from this state")
        if not (command.tenant_admin_opt_in and command.device_owner_opt_in):
            raise IncidentError("tenant and device-owner opt-in are both required")
        if not command.approval_digest_valid:
            raise IncidentError("digest-bound approval is required")
        next_state = IncidentState.COMPUTE_SUSPENSION_REQUESTED

    elif command.action is IncidentAction.CONFIRM_COMPUTE_SUSPENSION:
        if role != "trusted_controller" or current.state is not IncidentState.COMPUTE_SUSPENSION_REQUESTED:
            raise IncidentError("only the trusted controller may confirm a pending suspension")
        if not command.controller_receipt_valid:
            raise IncidentError("a verified controller receipt is required")
        next_state = IncidentState.COMPUTE_SUSPENSION_CONFIRMED

    elif command.action is IncidentAction.BEGIN_RECOVERY:
        if role not in {"tenant_admin", "security_operator", "device_owner"}:
            raise IncidentError("recovery review requires an authorised human")
        if current.state is not IncidentState.COMPUTE_SUSPENSION_CONFIRMED:
            raise IncidentError("recovery cannot begin before suspension is confirmed")
        if not command.approval_digest_valid:
            raise IncidentError("digest-bound recovery approval is required")
        next_state = IncidentState.RECOVERY_PENDING

    elif command.action is IncidentAction.RESOLVE:
        if role not in {"tenant_admin", "security_operator"} or current.state is not IncidentState.RECOVERY_PENDING:
            raise IncidentError("incident cannot be resolved from this state or role")
        if not command.approval_digest_valid:
            raise IncidentError("verified recovery evidence and approval are required")
        next_state = IncidentState.RESOLVED

    elif command.action is IncidentAction.DISMISS:
        if role not in {"tenant_admin", "security_operator"} or current.state not in {
            IncidentState.OBSERVED, IncidentState.TRIAGED
        }:
            raise IncidentError("incident cannot be dismissed from this state or role")
        if not command.approval_digest_valid:
            raise IncidentError("digest-bound dismissal approval is required")
        next_state = IncidentState.DISMISSED

    else:  # Defensive against values arriving from untyped boundaries.
        raise IncidentError("unsupported incident action")

    return replace(current, state=next_state, version=current.version + 1)
