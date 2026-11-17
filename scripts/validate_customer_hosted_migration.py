#!/usr/bin/env python3
"""Static safety checks for the customer-hosted PostgreSQL migration."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = ROOT / "migrations" / "0001_customer_hosted_control_plane.sql"
TASK_REPLAY_SQL_PATH = ROOT / "migrations" / "0002_task_contract_replay_storage.sql"
TASK_REPLAY_FUNCTIONS_SQL_PATH = ROOT / "migrations" / "0009_task_contract_replay_functions.sql"
TASK_REPLAY_FUNCTIONS_TEST_PATH = ROOT / "scripts" / "test_task_contract_replay_functions.sql"
SELF_EVOLUTION_REPLAY_SQL_PATH = ROOT / "migrations" / "0006_self_evolution_approval_replay.sql"
SELF_EVOLUTION_REPLAY_TEST_PATH = ROOT / "scripts" / "test_self_evolution_approval_replay.sql"
SELF_EVOLUTION_CONSUMPTION_SQL_PATH = ROOT / "migrations" / "0007_self_evolution_approval_consumption_function.sql"
SELF_EVOLUTION_CONSUMPTION_TEST_PATH = ROOT / "scripts" / "test_self_evolution_approval_consumption_function.sql"
SELF_EVOLUTION_CONCURRENCY_TEST_PATH = ROOT / "scripts" / "test_self_evolution_approval_consumption_concurrency.sh"
ATOMIC_ADMISSION_SQL_PATH = ROOT / "migrations" / "0008_atomic_device_lease_admission.sql"
ATOMIC_ADMISSION_TEST_PATH = ROOT / "scripts" / "test_atomic_device_lease_admission.sql"
ATOMIC_ADMISSION_CONCURRENCY_PATH = ROOT / "scripts" / "test_atomic_device_lease_admission_concurrency.sh"
TELEMETRY_V2_TEST_PATH = ROOT / "scripts" / "test_monotonic_device_telemetry_v2.sql"
TELEMETRY_V2_CONCURRENCY_PATH = ROOT / "scripts" / "test_monotonic_device_telemetry_v2_concurrency.sh"
ATOMIC_TELEMETRY_LEASE_SQL_PATH = ROOT / "migrations" / "0010_atomic_telemetry_lease_admission.sql"
ATOMIC_TELEMETRY_LEASE_TEST_PATH = ROOT / "scripts" / "test_atomic_telemetry_lease_admission.sql"
LEASE_APPROVAL_SQL_PATH = ROOT / "migrations" / "0011_persist_lease_approval_reference.sql"
LEASE_AUDIT_VIEW_SQL_PATH = ROOT / "migrations" / "0012_lease_audit_evidence_view.sql"
OWNER_CONSENT_REVOCATION_SQL_PATH = ROOT / "migrations" / "0013_revoke_leases_on_owner_consent_change.sql"
MODEL_INVENTORY_V2_ADMISSION_SQL_PATH = ROOT / "migrations" / "0014_atomic_model_inventory_v2_admission.sql"
MODEL_INVENTORY_V2_ADMISSION_TEST_PATH = ROOT / "scripts" / "test_model_inventory_v2_admission.sql"
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
    replay_functions_sql = TASK_REPLAY_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "CREATE OR REPLACE FUNCTION ujani_control.claim_task_contract_replay",
        "CREATE OR REPLACE FUNCTION ujani_control.advance_task_contract_sequence",
        "SECURITY INVOKER",
        "pg_catalog.current_setting('ujani.tenant_id', true)",
        "ON CONFLICT DO NOTHING",
        "RETURNING task_id INTO v_claimed_task_id",
        "last_sequence < EXCLUDED.last_sequence",
        "interval '5 minutes'",
        "REVOKE ALL ON FUNCTION",
    ):
        if required not in replay_functions_sql:
            raise SystemExit(f"task-contract replay helper is missing invariant: {required}")
    if "SECURITY DEFINER" in replay_functions_sql or "GRANT ALL" in replay_functions_sql:
        raise SystemExit("task-contract replay helpers must preserve caller RLS and least privilege")
    replay_functions_test = TASK_REPLAY_FUNCTIONS_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "replayed sender nonce was accepted for a second task",
        "replayed task ID was accepted with a different nonce",
        "replayed task-status sequence unexpectedly advanced",
        "stale task-status sequence unexpectedly advanced",
        "cross-tenant replay claim unexpectedly succeeded",
        "replay claim without tenant context unexpectedly succeeded",
        "task-contract runtime privileges are not least-privilege",
    ):
        if required not in replay_functions_test:
            raise SystemExit(f"task-contract replay regression test missing: {required}")
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
    self_evolution_consumption_sql = SELF_EVOLUTION_CONSUMPTION_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "CREATE OR REPLACE FUNCTION ujani_control.consume_self_evolution_approval",
        "SECURITY INVOKER",
        "current_setting('ujani.tenant_id', true)",
        "pg_advisory_xact_lock",
        "hashtextextended",
        "clock_timestamp()",
        "ON CONFLICT DO NOTHING",
        "RETURNING approval_id INTO inserted_approval_id",
        "REVOKE ALL ON FUNCTION",
    ):
        if required not in self_evolution_consumption_sql:
            raise SystemExit(f"Self-Evolution consumption function is missing invariant: {required}")
    if "SECURITY DEFINER" in self_evolution_consumption_sql:
        raise SystemExit("Self-Evolution consumption must preserve caller RLS and privileges")
    self_evolution_consumption_test = SELF_EVOLUTION_CONSUMPTION_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "duplicate approval ID was consumed twice",
        "duplicate approval nonce was consumed twice",
        "expired approval was consumed",
        "cross-tenant approval consumption unexpectedly succeeded",
        "approval consumption without tenant context unexpectedly succeeded",
    ):
        if required not in self_evolution_consumption_test:
            raise SystemExit(f"Self-Evolution consumption regression test missing: {required}")
    self_evolution_concurrency_test = SELF_EVOLUTION_CONCURRENCY_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "pg_sleep(2)",
        "clock_timestamp() + interval '1 second'",
        "pg_stat_activity",
        "wait_event_type = 'Lock'",
        "wait_event = 'advisory'",
        "approval request was not observed waiting on the advisory nonce lock",
        "approval that expired while waiting on the nonce lock was consumed",
    ):
        if required not in self_evolution_concurrency_test:
            raise SystemExit(f"Self-Evolution approval concurrency regression missing: {required}")
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
    if "pg_sleep(1)" in concurrency_test:
        raise SystemExit("telemetry concurrency test must use an observed lock-wait handshake, not a fixed sleep")
    for required in ("pg_stat_activity", "UJANI_TELEMETRY_RELEASE_FILE", "idle in transaction", "wait_event_type='Lock'", "pg_blocking_pids", "blocker.application_name", "1:2:2", "--quiet"):
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
    atomic_sql = ATOMIC_ADMISSION_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "CREATE OR REPLACE FUNCTION ujani_control.admit_device_lease",
        "SECURITY INVOKER",
        "current_setting('ujani.tenant_id', true)",
        "FOR UPDATE",
        "consent_generation = p_consent_generation",
        "device_key_generation",
        "valid_from <= v_now AND revoked_at IS NULL",
        "owner_consents",
        "state = 'approved'",
        "s.enabled IS TRUE AND s.role = 'administrator'",
        "received_at DESC",
        "participation_state <> 'idle'",
        "ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING",
        "requested_cpu_millis",
        "requested_memory_mb",
        "reservation_revision",
        "device.lease.admitted",
        "owner_consent_state = 'unknown'",
        "v_approval_expires_at",
        "admission_lock_marker",
        "reject_admission_lock_marker_mutation",
        "FOR SHARE OF a, s",
        "REVOKE ALL ON FUNCTION",
    ):
        if required not in atomic_sql:
            raise SystemExit(f"atomic device admission migration is missing invariant: {required}")
    if "SECURITY DEFINER" in atomic_sql:
        raise SystemExit("atomic device admission must preserve caller RLS and privileges")
    atomic_test = ATOMIC_ADMISSION_TEST_PATH.read_text(encoding="utf-8")
    if "GRANT SELECT,INSERT,UPDATE ON" in atomic_test or "UPDATE ujani_control.devices SET owner_consent_state" in atomic_test:
        raise SystemExit("atomic admission test must not grant broad runtime mutation privileges or let runtime change owner consent")
    for required in (
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ujani_control FROM ujani_runtime",
        "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ujani_control FROM ujani_runtime",
        "REVOKE ALL ON SCHEMA ujani_control FROM ujani_runtime",
        "REVOKE ALL ON FUNCTION ujani_control.admit_device_lease(",
        "GRANT UPDATE (reservation_revision, updated_at)",
        "GRANT UPDATE (admission_lock_marker)",
        "runtime role is missing the narrow row-lock-only column privileges",
        "runtime role can update protected column",
        "pg_catalog.pg_attribute",
        "runtime role changed immutable admission lock marker",
        "GRANT INSERT ON ujani_control.leases,ujani_control.request_replays",
        "runtime role can mutate device trust or consent state",
        "ujani_control.device_keys','INSERT",
        "ujani_control.device_keys','UPDATE",
        "runtime role can rewrite lease, replay or audit history",
        "runtime role does not have only the required reservation update columns",
        "valid admission was not committed",
        "replayed request was admitted",
        "over-capacity request was admitted",
        "admission-device-paused",
        "owner binding change did not invalidate prior consent",
        "paused owner consent admitted work",
        "approval from a disabled administrator was accepted",
        "approval from a non-administrator was accepted",
        "future-dated active device key was accepted",
        "revoked active device key was accepted",
        "admission writes were not atomic",
        "late failure left partial admission state",
    ):
        if required not in atomic_test:
            raise SystemExit(f"atomic device admission regression test missing: {required}")
    atomic_concurrency = ATOMIC_ADMISSION_CONCURRENCY_PATH.read_text(encoding="utf-8")
    for required in (
        "UJANI_ADMISSION_RELEASE_FILE",
        'release_dir="$(mktemp -d)"',
        "\\! for i in $(seq 1 300)",
        "state='idle in transaction'",
        "FOR UPDATE;",
        "PGAPPNAME=ujani-admission-first",
        "application_name='ujani-admission-first'",
        "application_name='ujani-admission-second'",
        "wait_event_type='Lock'",
        "second admission was not observed waiting on the device row lock",
        "second admission should be rejected",
        "1:2500",
    ):
        if required not in atomic_concurrency:
            raise SystemExit(f"atomic admission concurrency regression missing: {required}")
    # Lock ordering is part of the concurrency contract: audit writers serialize
    # per tenant before taking device locks; telemetry locks its device before
    # inserting the replay row that has a device foreign key.
    for function_name in (
        "ujani_control.apply_owner_consent_revision",
        "ujani_control.admit_device_lease",
    ):
        function_start = atomic_sql.index("CREATE OR REPLACE FUNCTION " + function_name)
        function_end = atomic_sql.index("$function$;", function_start)
        function_body = atomic_sql[function_start:function_end]
        if function_body.index("pg_advisory_xact_lock") > function_body.index("FOR UPDATE"):
            raise SystemExit(function_name + " must acquire the tenant audit lock before the device lock")
    if "lock_device_owner_binding_audit_chain" not in atomic_sql or "FOR EACH STATEMENT EXECUTE FUNCTION ujani_control.lock_device_owner_binding_audit_chain()" not in atomic_sql:
        raise SystemExit("owner-binding writes must acquire the tenant audit lock before row locks")
    telemetry_v2_start = atomic_sql.index("CREATE OR REPLACE FUNCTION ujani_control.accept_device_telemetry_v2")
    telemetry_v2_end = atomic_sql.index("$function$;", telemetry_v2_start)
    telemetry_v2_body = atomic_sql[telemetry_v2_start:telemetry_v2_end]
    if telemetry_v2_body.index("FOR UPDATE") > telemetry_v2_body.index("INSERT INTO ujani_control.request_replays"):
        raise SystemExit("telemetry v2 must lock the device before claiming a replay identifier")
    if "DO $\\n" in atomic_test or "END $;" in atomic_test:
        raise SystemExit("atomic admission PostgreSQL test contains a malformed dollar-quoted block")
    telemetry_v2_test = TELEMETRY_V2_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "accept_device_telemetry_v2(text,text,bigint,bigint,bigint,bytea",
        "duplicate generation/sequence should be rejected",
        "older observation timestamp must not roll back last_seen",
        "stale telemetry timestamp should be rejected",
        "future telemetry timestamp should be rejected",
        "owner opt-out should reject admission",
        "organization denial should reject admission",
        "revoked device should reject admission",
        "caller rollback did not atomically restore telemetry state",
    ):
        if required not in telemetry_v2_test:
            raise SystemExit("telemetry v2 PostgreSQL regression test missing: " + required)
    telemetry_v2_concurrency = TELEMETRY_V2_CONCURRENCY_PATH.read_text(encoding="utf-8")
    if "pg_sleep(1)" in telemetry_v2_concurrency:
        raise SystemExit("telemetry v2 concurrency test must use an observed lock-wait handshake, not a fixed sleep")
    for required in ("accept_device_telemetry_v2", "pg_stat_activity", "UJANI_TELEMETRY_RELEASE_FILE", "idle in transaction", "wait_event_type='Lock'", "pg_blocking_pids", "blocker.application_name", "1:1:1:0", "--quiet"):
        if required not in telemetry_v2_concurrency:
            raise SystemExit("telemetry v2 concurrency regression missing: " + required)
    atomic_telemetry_lease_sql = ATOMIC_TELEMETRY_LEASE_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "CREATE OR REPLACE FUNCTION ujani_control.admit_device_lease_with_telemetry",
        "SECURITY INVOKER",
        "p_device_key_generation",
        "p_consent_generation",
        "FOR UPDATE",
        "v_key_generation IS DISTINCT FROM p_device_key_generation",
        "v_consent_generation IS DISTINCT FROM p_consent_generation",
        "ujani_control.accept_device_telemetry_v2(",
        "ujani_control.admit_device_lease(",
        "ERRCODE = 'UJ001'",
        "EXCEPTION WHEN SQLSTATE 'UJ001'",
        "REVOKE ALL ON FUNCTION",
    ):
        if required not in atomic_telemetry_lease_sql:
            raise SystemExit("atomic telemetry-plus-lease migration is missing invariant: " + required)
    if "SECURITY DEFINER" in atomic_telemetry_lease_sql:
        raise SystemExit("atomic telemetry-plus-lease wrapper must preserve caller RLS and privileges")
    lease_approval_sql = LEASE_APPROVAL_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "ALTER TABLE ujani_control.leases",
        "ADD COLUMN IF NOT EXISTS approval_id text",
        "FOREIGN KEY (tenant_id, approval_id)",
        "REFERENCES ujani_control.approvals(tenant_id, approval_id)",
        "INSERT INTO ujani_control.leases",
        "p_approval_id, p_manifest_digest",
        "REVOKE ALL ON FUNCTION ujani_control.admit_device_lease",
    ):
        if required not in lease_approval_sql:
            raise SystemExit("lease approval-reference migration is missing invariant: " + required)
    if "SECURITY DEFINER" in lease_approval_sql:
        raise SystemExit("lease approval-reference update must preserve caller RLS and privileges")
    lease_audit_view_sql = LEASE_AUDIT_VIEW_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "ADD COLUMN IF NOT EXISTS request_digest bytea",
        "p_request_id, p_operation_digest",
        "CREATE OR REPLACE FUNCTION ujani_control.reject_lease_admission_evidence_mutation()",
        "OLD.request_digest IS DISTINCT FROM NEW.request_digest",
        "OLD.approval_id IS DISTINCT FROM NEW.approval_id",
        "leases_admission_evidence_immutable",
        "CREATE OR REPLACE FUNCTION ujani_control.list_device_lease_audit_evidence(",
        "p_before_sequence bigint DEFAULT NULL",
        "p_limit integer DEFAULT 100",
        "LIMIT GREATEST(1, LEAST(COALESCE(p_limit, 100), 200))",
        "SECURITY INVOKER",
        "ae.event_digest",
        "ae.event_type LIKE 'device.lease.%'",
        "l.request_digest",
        "l.approval_id",
        "REVOKE ALL ON FUNCTION ujani_control.list_device_lease_audit_evidence(bigint,integer) FROM PUBLIC",
    ):
        if required not in lease_audit_view_sql:
            raise SystemExit("lease audit evidence migration is missing invariant: " + required)
    if "SECURITY DEFINER" in lease_audit_view_sql:
        raise SystemExit("lease audit evidence function must preserve caller RLS")
    owner_consent_revocation_sql = OWNER_CONSENT_REVOCATION_SQL_PATH.read_text(encoding="utf-8")
    if "SECURITY INVOKER" not in owner_consent_revocation_sql or "SECURITY DEFINER" in owner_consent_revocation_sql:
        raise SystemExit("owner-consent lease revocation must preserve caller privilege checks")
    for required in (
        "CREATE OR REPLACE FUNCTION ujani_control.apply_owner_consent_revision()",
        "IF NEW.state <> 'granted' THEN",
        "SET state = 'revoked', revision = revision + 1",
        "'device.lease.revoked'",
        "'owner_consent_' || NEW.state",
    ):
        if required not in owner_consent_revocation_sql:
            raise SystemExit("owner-consent lease revocation migration is missing invariant: " + required)
    atomic_telemetry_lease_test = ATOMIC_TELEMETRY_LEASE_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "atomic telemetry-plus-lease admission was rejected",
        "approval_ref IS DISTINCT FROM 'admission-approval'",
        "stored_request_digest IS DISTINCT FROM decode(repeat('d4',32),'hex')",
        "GRANT SELECT ON ujani_control.audit_events,ujani_control.leases,ujani_control.approvals TO ujani_runtime",
        "audit evidence function leaked a lease across tenant context",
        "lease request digest mutation was not rejected",
        "lease approval reference mutation was not rejected",
        "owner consent withdrawal did not atomically revoke outstanding leases",
        "withdrawn owner consent must block new lease admission",
        "fresh owner consent grant did not permit a new lease",
        "owner consent pause did not atomically revoke the active reservation",
        "a later owner consent grant reactivated a revoked lease",
        "interactive telemetry must deny lease admission",
        "expected denial left partial telemetry or lease state",
        "duplicate audit event did not abort atomic admission",
        "late audit failure left partial telemetry or lease state",
        "stale device key generation was accepted",
    ):
        if required not in atomic_telemetry_lease_test:
            raise SystemExit("atomic telemetry-plus-lease regression is missing: " + required)
    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    if "UJANI_ADMISSION_RELEASE_FILE=${UJANI_ADMISSION_RELEASE_FILE:-}" not in ci_workflow:
        raise SystemExit("CI PostgreSQL adapter must pass the bounded admission release-marker path")
    if "UJANI_TELEMETRY_RELEASE_FILE=${UJANI_TELEMETRY_RELEASE_FILE:-}" not in ci_workflow:
        raise SystemExit("CI PostgreSQL adapter must pass the bounded telemetry release-marker path")
    if not (
        ci_workflow.index("migrations/0008_atomic_device_lease_admission.sql")
        < ci_workflow.index("scripts/test_monotonic_device_telemetry_v2.sql")
        < ci_workflow.index("migrations/0009_task_contract_replay_functions.sql")
    ):
        raise SystemExit("telemetry v2 regression tests must run after migration 0008 and before migration 0009")

    if not (
        ci_workflow.index("migrations/0009_task_contract_replay_functions.sql")
        < ci_workflow.index("migrations/0010_atomic_telemetry_lease_admission.sql")
        < ci_workflow.index("migrations/0011_persist_lease_approval_reference.sql")
        < ci_workflow.index("migrations/0012_lease_audit_evidence_view.sql")
        < ci_workflow.index("migrations/0013_revoke_leases_on_owner_consent_change.sql")
        < ci_workflow.index("scripts/test_atomic_telemetry_lease_admission.sql")
    ):
        raise SystemExit("atomic telemetry-plus-lease test must run after migrations 0009-0013")

    model_inventory_v2_sql = MODEL_INVENTORY_V2_ADMISSION_SQL_PATH.read_text(encoding="utf-8")
    for required in (
        "CREATE TABLE IF NOT EXISTS ujani_control.model_inventory_policies",
        "CREATE TABLE IF NOT EXISTS ujani_control.device_model_inventory",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "CREATE OR REPLACE FUNCTION ujani_control.accept_model_runtime_inventory_v2",
        "SECURITY INVOKER",
        "pg_advisory_xact_lock",
        "device_model_inventory_authority_audit_lock",
        "FOR UPDATE",
        "key_generation IS DISTINCT FROM p_device_key_generation",
        "consent_generation IS DISTINCT FROM p_consent_generation",
        "admin_approval_state <> 'approved'",
        "organisation_authorisation",
        "request_replays",
        "ON CONFLICT (tenant_id,device_id,request_id) DO NOTHING",
        "generated_at_unix_ms",
        "max_age_ms",
        "jsonb_array_length",
        "contains_prompts",
        "device.model_inventory.accepted",
        "REVOKE ALL ON FUNCTION",
    ):
        if required not in model_inventory_v2_sql:
            raise SystemExit("model inventory v2 admission migration is missing invariant: " + required)
    if "SECURITY DEFINER" in model_inventory_v2_sql:
        raise SystemExit("model inventory v2 admission must preserve caller RLS and privileges")
    model_inventory_v2_test = MODEL_INVENTORY_V2_ADMISSION_TEST_PATH.read_text(encoding="utf-8")
    for required in (
        "valid dual-consented model inventory was not committed",
        "replayed model inventory request was accepted",
        "non-monotonic inventory timestamp was accepted",
        "future-dated model inventory was accepted",
        "stale model inventory was accepted",
        "unapproved policy version was accepted",
        "inventory claiming prompt collection was accepted",
        "spoofed inventory device reference was accepted",
        "stale device key generation was accepted",
        "cross-tenant model inventory was accepted",
        "caller rollback did not restore inventory revision",
        "late audit failure left an inventory replay claim",
        "disabled organisation inventory policy was accepted",
        "organisation device approval denial was accepted",
        "paused owner consent was accepted",
        "policy update did not invalidate",
        "organisation denial did not hide stored model inventory",
        "owner consent pause did not clear the stored model inventory",
        "fresh inventory under the new policy was not accepted",
        "fresh inventory before owner pause was not accepted",
        "policy update did not invalidate the stored model inventory",
        "model inventory leaked across tenant RLS",
    ):
        if required not in model_inventory_v2_test:
            raise SystemExit("model inventory v2 admission regression is missing: " + required)
    if not (
        ci_workflow.index("migrations/0013_revoke_leases_on_owner_consent_change.sql")
        < ci_workflow.index("migrations/0014_atomic_model_inventory_v2_admission.sql")
        < ci_workflow.index("scripts/test_model_inventory_v2_admission.sql")
    ):
        raise SystemExit("model inventory v2 admission test must run after migration 0013")

    print("Customer-hosted, task-contract, Self-Evolution approval replay, monotonic telemetry, atomic lease admission and model inventory v2 transaction checks passed.")


if __name__ == "__main__":
    main()
