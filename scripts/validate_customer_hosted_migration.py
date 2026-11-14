#!/usr/bin/env python3
"""Static safety checks for the customer-hosted PostgreSQL migration."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = ROOT / "migrations" / "0001_customer_hosted_control_plane.sql"
TASK_REPLAY_SQL_PATH = ROOT / "migrations" / "0002_task_contract_replay_storage.sql"
SELF_EVOLUTION_REPLAY_SQL_PATH = ROOT / "migrations" / "0006_self_evolution_approval_replay.sql"
SELF_EVOLUTION_REPLAY_TEST_PATH = ROOT / "scripts" / "test_self_evolution_approval_replay.sql"
TENANT_TEST_SQL_PATH = ROOT / "scripts" / "test_customer_hosted_migration.sql"


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
    replay_sql = TASK_REPLAY_SQL_PATH.read_text(encoding="utf-8")
    for table in ("task_contract_replays", "task_contract_sequences"):
        if f"CREATE TABLE IF NOT EXISTS ujani_control.{table}" not in replay_sql:
            raise SystemExit(f"missing shared task-contract storage table: {table}")
    if "octet_length(nonce) = 32" not in replay_sql:
        raise SystemExit("task-contract nonce must be exactly 32 bytes")
    if "UNIQUE (tenant_id, sender_device_id, nonce)" not in replay_sql:
        raise SystemExit("task replay claim must atomically reject sender nonce reuse")
    if "last_sequence BETWEEN 1 AND 9007199254740991" not in replay_sql:
        raise SystemExit("message sequence must be a positive I-JSON safe integer")
    if "message_type IN ('task_status','execution_receipt')" not in replay_sql:
        raise SystemExit("status and receipt sequence streams must be distinct")
    if "ENABLE ROW LEVEL SECURITY" not in replay_sql or "FORCE ROW LEVEL SECURITY" not in replay_sql:
        raise SystemExit("task-contract storage must enable and force row-level security")
    if "current_setting(''ujani.tenant_id'', true)" not in replay_sql:
        raise SystemExit("task-contract storage must fail closed without tenant context")
    if "SECURITY DEFINER" in replay_sql or "GRANT ALL" in replay_sql:
        raise SystemExit("task-contract migration must not add privileged functions or grants")
    self_evolution_replay_sql = SELF_EVOLUTION_REPLAY_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "CREATE TABLE IF NOT EXISTS ujani_control.self_evolution_approval_replays",
        "PRIMARY KEY (tenant_id, approval_id)",
        "UNIQUE (tenant_id, nonce)",
        "octet_length(nonce) = 16",
        "octet_length(proposal_sha256) = 32",
        "octet_length(target_sha256) = 32",
        "octet_length(approved_scope_sha256) = 32",
        "approved_scope_count BETWEEN 1 AND 32",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "current_setting('ujani.tenant_id', true)",
    ):
        if required not in self_evolution_replay_sql:
            raise SystemExit(f"Self-Evolution approval replay migration is missing invariant: {required}")
    if "SECURITY DEFINER" in self_evolution_replay_sql or "GRANT ALL" in self_evolution_replay_sql:
        raise SystemExit("Self-Evolution replay migration must not add privileged functions or broad grants")
    self_evolution_replay_test = SELF_EVOLUTION_REPLAY_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "replayed approval nonce was consumed twice",
        "replayed approval ID was consumed twice",
        "tenant-b can see tenant-a approval replay rows",
        "missing tenant context did not fail closed",
        "runtime role can mutate or erase consumed approval tombstones",
        "cross-tenant approval replay insert unexpectedly succeeded",
    ):
        if required not in self_evolution_replay_test:
            raise SystemExit(f"Self-Evolution approval replay regression test missing: {required}")
    replay_record_module = (ROOT / "crates" / "ujani-enterprise-policy" / "src" / "self_evolution_approval_replay.rs").read_text(encoding="utf-8")
    for required in (
        "SelfEvolutionApprovalReplayRecord",
        "from_verified(",
        "approver_subject_id: &str",
        "self_evolution_target_sha256",
        "self_evolution_scope_sha256",
        "UJANI-ENTERPRISE-SELF-EVOLUTION-TARGET-V1",
        "UJANI-ENTERPRISE-SELF-EVOLUTION-SCOPE-V1",
        "tenant_id and approver-subject identity",
        "tenant_id: tenant_id.to_owned()",
        "approval_id: approval.approval_id().to_owned()",
        "proposal_sha256: *approval.proposal_sha256()",
        "target_sha256: self_evolution_target_sha256",
        "approved_scope_sha256: self_evolution_scope_sha256",
    ):
        if required not in replay_record_module:
            raise SystemExit(f"Self-Evolution replay record adapter contract missing: {required}")
    if "DATABASE_URL" in replay_record_module or "sqlx::" in replay_record_module or "tokio_postgres" in replay_record_module:
        raise SystemExit("Policy crate replay record contract must remain database-adapter neutral")
    approval_module = (ROOT / "crates" / "ujani-enterprise-policy" / "src" / "self_evolution_approval.rs").read_text(encoding="utf-8")
    for required in ("pub fn repository(", "pub fn base_ref(", "pub fn source_revision(", "pub fn proposal_sha256("):
        if required not in approval_module:
            raise SystemExit(f"Verified approval is missing replay binding accessor: {required}")
    telemetry_sql = (ROOT / "migrations" / "0003_monotonic_device_telemetry.sql").read_text(encoding="utf-8")
    telemetry_test = (ROOT / "scripts" / "test_monotonic_device_telemetry.sql").read_text(encoding="utf-8")
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
        "p_observed_at >= last_seen_at",
        "ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING",
    ):
        if required not in telemetry_sql:
            raise SystemExit(f"monotonic telemetry migration is missing invariant: {required}")
    if "SECURITY DEFINER" in telemetry_sql:
        raise SystemExit("telemetry admission must not bypass tenant RLS with SECURITY DEFINER")
    for required in (
        "replayed request id should be rejected",
        "duplicate generation/sequence should be rejected",
        "older observation timestamp must not roll back last_seen",
        "stale telemetry timestamp should be rejected",
        "future telemetry timestamp should be rejected",
        "owner opt-out should reject admission",
        "organization denial should reject admission",
        "revoked device should reject admission",
        "caller rollback did not atomically restore telemetry state",
    ):
        if required not in telemetry_test:
            raise SystemExit(f"telemetry PostgreSQL regression test missing: {required}")
    if "DO $\n" in telemetry_test or "END $;" in telemetry_test:
        raise SystemExit("telemetry PostgreSQL test contains a malformed dollar-quoted block")
    if "verify the signed device request" not in telemetry_sql:
        raise SystemExit("telemetry migration must document upstream signature verification boundary")
    concurrency_test = (ROOT / "scripts" / "test_monotonic_device_telemetry_concurrency.sh").read_text(encoding="utf-8")
    for required in ("pg_stat_activity", "pg_sleep(1)", "1:2:2", "--quiet"):
        if required not in concurrency_test:
            raise SystemExit(f"telemetry concurrency regression test missing: {required}")
    tenant_test = TENANT_TEST_SQL_PATH.read_text(encoding="utf-8")
    if "REVOKE INSERT, UPDATE, DELETE ON ujani_control.tenants FROM ujani_runtime" not in tenant_test:
        raise SystemExit("runtime role must not mutate the tenant registry")
    for required in (
        "has_table_privilege(current_user, 'ujani_control.tenants', 'INSERT')",
        "has_table_privilege(current_user, 'ujani_control.tenants', 'UPDATE')",
        "has_table_privilege(current_user, 'ujani_control.tenants', 'DELETE')",
        "runtime role can mutate tenant registry",
    ):
        if required not in tenant_test:
            raise SystemExit(f"tenant provisioning privilege regression test missing: {required}")
    concurrency_test = (ROOT / "scripts" / "test_monotonic_device_telemetry_concurrency.sh").read_text(encoding="utf-8")
    if 'PSQL_BIN="${PSQL_BIN:-psql}"' not in concurrency_test:
        raise SystemExit("telemetry concurrency test must use the configured PostgreSQL client adapter")
    print("Customer-hosted, task-contract, Self-Evolution approval replay and monotonic telemetry migration static checks passed.")


if __name__ == "__main__":
    main()
