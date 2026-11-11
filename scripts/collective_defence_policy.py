"""Strict dual-opt-in policy for organization-coordinated defensive signals."""
from dataclasses import dataclass

ALLOWED_SIGNAL_TYPES = frozenset({"malware_hash", "ransomware_indicator", "network_ioc"})

@dataclass(frozen=True)
class DefenceSignalRequest:
    organization_enabled: bool
    participant_enabled: bool
    signal_type: str
    contains_file_content: bool
    contains_personal_data: bool
    operator_approved: bool

def defence_signal_denials(request: DefenceSignalRequest) -> list[str]:
    if not isinstance(request, DefenceSignalRequest):
        return ["invalid_request"]

    denials: list[str] = []
    if request.organization_enabled is not True:
        denials.append("organization_opt_in_missing")
    if request.participant_enabled is not True:
        denials.append("participant_opt_in_missing")
    if not isinstance(request.signal_type, str) or request.signal_type not in ALLOWED_SIGNAL_TYPES:
        denials.append("signal_type_not_allowlisted")
    # Unknown or malformed data classification is treated as prohibited.
    if request.contains_file_content is not False:
        denials.append("file_content_prohibited")
    if request.contains_personal_data is not False:
        denials.append("personal_data_prohibited")
    if request.operator_approved is not True:
        denials.append("operator_approval_missing")
    return denials

def may_share_defence_signal(request: DefenceSignalRequest) -> bool:
    return not defence_signal_denials(request)
