"""Dual opt-in policy for organization-coordinated defensive signals."""
from dataclasses import dataclass

ALLOWED_SIGNAL_TYPES = {"malware_hash", "ransomware_indicator", "network_ioc"}

@dataclass(frozen=True)
class DefenceSignalRequest:
    organization_enabled: bool
    participant_enabled: bool
    signal_type: str
    contains_file_content: bool
    contains_personal_data: bool
    operator_approved: bool

def defence_signal_denials(request: DefenceSignalRequest) -> list[str]:
    denials = []
    if not request.organization_enabled:
        denials.append("organization_opt_in_missing")
    if not request.participant_enabled:
        denials.append("participant_opt_in_missing")
    if request.signal_type not in ALLOWED_SIGNAL_TYPES:
        denials.append("signal_type_not_allowlisted")
    if request.contains_file_content:
        denials.append("file_content_prohibited")
    if request.contains_personal_data:
        denials.append("personal_data_prohibited")
    if not request.operator_approved:
        denials.append("operator_approval_missing")
    return denials

def may_share_defence_signal(request: DefenceSignalRequest) -> bool:
    return not defence_signal_denials(request)
