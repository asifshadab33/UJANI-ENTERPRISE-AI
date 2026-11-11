"""Fail-closed customer-hosted Enterprise acceptance evidence checklist."""
REQUIRED_EVIDENCE = {
    "customer_controlled_deployment",
    "tenant_isolation_negative_tests",
    "device_identity_and_revocation_tests",
    "authenticated_lease_expiry_tests",
    "database_backup_restore_drill",
    "tls_and_secret_rotation_tests",
    "operator_access_audit",
    "resource_admission_and_opt_out_tests",
    "customer_lab_signoff",
}

def missing_lab_evidence(evidence: set[str]) -> list[str]:
    return sorted(REQUIRED_EVIDENCE - evidence)

def lab_ready(evidence: set[str]) -> bool:
    return not missing_lab_evidence(evidence)
