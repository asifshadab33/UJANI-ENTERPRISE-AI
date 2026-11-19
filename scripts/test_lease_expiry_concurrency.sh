#!/usr/bin/env bash
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD must be set for PostgreSQL integration}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

first_out="$(mktemp)"
second_out="$(mktemp)"
first_pid=""
second_pid=""
cleanup() {
  if [[ -n "$first_pid" ]]; then wait "$first_pid" 2>/dev/null || true; fi
  if [[ -n "$second_pid" ]]; then wait "$second_pid" 2>/dev/null || true; fi
  rm -f "$first_out" "$second_out"
}
trap cleanup EXIT

# The SQL fixture created one due-but-still-reserved lease. The first worker
# expires it and deliberately holds the transaction-scoped tenant/device locks
# while sleeping. The second worker must wait, then observe an already-expired
# lease and return zero rather than writing a duplicate transition or receipt.
(
  PGAPPNAME=ujani-lease-expiry-first "${PSQL[@]}" >"$first_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';
SELECT ujani_control.expire_device_leases('admission-test','admission-atomic-device',10);
SELECT pg_catalog.pg_sleep(5);
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

first_ready=0
for _ in $(seq 1 100); do
  active="$(${PSQL[@]} -c "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='ujani-lease-expiry-first' AND state='active' AND query LIKE '%pg_sleep%'")"
  if [[ "$active" == "1" ]] && grep -qx '1' "$first_out"; then
    first_ready=1
    break
  fi
  sleep 0.1
done
if [[ "$first_ready" != "1" ]]; then
  echo "first expiry worker did not transition the due lease and hold its transaction" >&2
  cat "$first_out" >&2
  exit 1
fi

(
  PGAPPNAME=ujani-lease-expiry-second "${PSQL[@]}" >"$second_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';
SELECT ujani_control.expire_device_leases('admission-test','admission-atomic-device',10);
COMMIT;
RESET ROLE;
SQL
) &
second_pid=$!

second_waiting=0
for _ in $(seq 1 100); do
  waiting="$(${PSQL[@]} -c "SELECT count(*) FROM pg_catalog.pg_stat_activity AS waiting WHERE waiting.application_name='ujani-lease-expiry-second' AND waiting.state='active' AND waiting.wait_event_type='Lock' AND EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity AS blocker WHERE blocker.pid = ANY(pg_catalog.pg_blocking_pids(waiting.pid)) AND blocker.application_name='ujani-lease-expiry-first')")"
  if [[ "$waiting" == "1" ]]; then
    second_waiting=1
    break
  fi
  sleep 0.1
done

set +e
wait "$first_pid"
first_status=$?
first_pid=""
wait "$second_pid"
second_status=$?
second_pid=""
set -e

if [[ "$first_status" -ne 0 || "$second_status" -ne 0 ]]; then
  echo "concurrent lease expiry worker failed" >&2
  cat "$first_out" "$second_out" >&2
  exit 1
fi
if [[ "$second_waiting" != "1" ]]; then
  echo "second expiry worker was not observed waiting on the tenant/device lock" >&2
  cat "$first_out" "$second_out" >&2
  exit 1
fi
if ! grep -qx '1' "$first_out"; then
  echo "exactly one due lease should be expired by the first worker" >&2
  cat "$first_out" >&2
  exit 1
fi
if ! grep -qx '0' "$second_out"; then
  echo "second worker should be an idempotent no-op after the first commit" >&2
  cat "$second_out" >&2
  exit 1
fi

state="$("${PSQL[@]}" -c "SELECT CASE WHEN l.state='expired' AND l.revision=d.reservation_revision AND (SELECT count(*) FROM ujani_control.audit_events a WHERE a.tenant_id=l.tenant_id AND a.event_type='device.lease.expired' AND a.object_ref=l.lease_id)=1 AND NOT EXISTS (SELECT 1 FROM ujani_control.leases active WHERE active.tenant_id=l.tenant_id AND active.device_id=l.device_id AND active.state IN ('reserved','active') AND active.expires_at>clock_timestamp()) THEN 'ok' ELSE 'bad' END FROM ujani_control.leases l JOIN ujani_control.devices d USING (tenant_id,device_id) WHERE l.tenant_id='admission-test' AND l.lease_id='admission-lifecycle-expiry-race'")"
if [[ "$state" != "ok" ]]; then
  echo "lease expiry did not atomically update state, capacity revision and exactly one audit receipt: $state" >&2
  exit 1
fi

echo "Concurrent lease expiry reconciliation passed."
