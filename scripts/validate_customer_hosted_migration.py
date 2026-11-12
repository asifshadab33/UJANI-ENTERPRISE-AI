#!/usr/bin/env python3
"""Static safety checks for the customer-hosted PostgreSQL migration."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL_PATH = ROOT / "migrations" / "0001_customer_hosted_control_plane.sql"
TASK_REPLAY_SQL_PATH = ROOT / "migrations" / "0002_task_contract_replay_storage.sql"


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
    print("Customer-hosted and task-contract migration static checks passed.")


if __name__ == "__main__":
    main()
