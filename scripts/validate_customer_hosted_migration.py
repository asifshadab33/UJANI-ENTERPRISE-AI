#!/usr/bin/env python3
"""Static safety checks for the customer-hosted PostgreSQL migration."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = ROOT / "migrations" / "0001_customer_hosted_control_plane.sql"
TEST_SQL_PATH = ROOT / "scripts" / "test_customer_hosted_migration.sql"


def main() -> None:
    sql = SQL_PATH.read_text(encoding="utf-8")
    required_tables = (
        "tenants", "operator_subjects", "devices", "device_keys",
        "owner_consents", "workloads", "approvals", "leases",
        "request_replays", "audit_events",
    )
    for table in required_tables:
        marker = f"CREATE TABLE IF NOT EXISTS ujani_control.{table}"
        if marker not in sql:
            raise SystemExit(f"missing required tenant table: {table}")
    if "ENABLE ROW LEVEL SECURITY" not in sql or "FORCE ROW LEVEL SECURITY" not in sql:
        raise SystemExit("tenant tables must enable and force row-level security")
    if "DROP POLICY IF EXISTS tenant_isolation" not in sql:
        raise SystemExit("tenant RLS policy creation must be repeat-safe")
    if sql.count("current_setting(''ujani.tenant_id'', true)") < 2:
        raise SystemExit("tenant RLS policy must constrain both reads and writes")
    if "BEFORE UPDATE OR DELETE ON ujani_control.audit_events" not in sql:
        raise SystemExit("audit event rows must reject update and delete")
    if "reject_audit_mutation" not in sql:
        raise SystemExit("append-only audit trigger function is missing")
    if "octet_length(event_digest) = 32" not in sql:
        raise SystemExit("audit digest must be a SHA-256-sized value")
    if "octet_length(request_id) = 16" not in sql:
        raise SystemExit("replay request identifiers must be at least 128 bits")
    if "BYPASSRLS" in sql or "GRANT ALL" in sql or "CREATE ROLE" in sql:
        raise SystemExit("migration must not create a privileged runtime role")
    test_sql = TEST_SQL_PATH.read_text(encoding="utf-8")
    if "REVOKE INSERT, UPDATE, DELETE ON ujani_control.tenants FROM ujani_runtime" not in test_sql:
        raise SystemExit("runtime role must not mutate the tenant registry")
    for privilege in ("INSERT", "UPDATE", "DELETE"):
        if f"has_table_privilege(current_user, 'ujani_control.tenants', '{privilege}')" not in test_sql:
            raise SystemExit(f"PostgreSQL test must verify runtime tenant-registry {privilege} privilege is absent")
    if "GET DIAGNOSTICS affected_rows = ROW_COUNT;" in test_sql and "affected_rows bigint;" not in test_sql:
        raise SystemExit("PostgreSQL isolation test reads affected_rows without declaring it")
    telemetry_sql = (ROOT / "migrations" / "0002_authenticated_device_telemetry.sql").read_text(encoding="utf-8")
    telemetry_test = (ROOT / "scripts" / "test_authenticated_telemetry.sql").read_text(encoding="utf-8")
    for required in (
        "CREATE TABLE IF NOT EXISTS ujani_control.device_telemetry_samples",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "SECURITY INVOKER",
        "current_setting('ujani.tenant_id', true)",
        "p_generation > telemetry_generation",
        "p_generation = telemetry_generation AND p_sequence > telemetry_sequence",
        "owner_consent_state = 'granted'",
        "admin_approval_state = 'approved'",
        "trust_state = 'enrolled'",
        "interval '5 minutes'",
        "interval '60 seconds'",
        "ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING",
    ):
        if required not in telemetry_sql:
            raise SystemExit(f"authenticated telemetry migration is missing invariant: {required}")
    if "SECURITY DEFINER" in telemetry_sql:
        raise SystemExit("telemetry admission must not bypass tenant RLS with SECURITY DEFINER")
    for required in (
        "replayed request id should be rejected",
        "duplicate generation/sequence should be rejected",
        "stale telemetry timestamp should be rejected",
        "future telemetry timestamp should be rejected",
        "owner opt-out should reject admission",
        "organization denial should reject admission",
        "revoked device should reject admission",
    ):
        if required not in telemetry_test:
            raise SystemExit(f"telemetry PostgreSQL regression test missing: {required}")
    print("Customer-hosted and authenticated telemetry migration static checks passed.")


if __name__ == "__main__":
    main()
