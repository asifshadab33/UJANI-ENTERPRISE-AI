#!/usr/bin/env bash
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD must be set for the PostgreSQL integration test}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=( "$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align )
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

# Session one holds an uncommitted unique-key claim, then rolls it back only
# after the envelope expiry used by session two. This forces the second INSERT
# to wait on PostgreSQL's unique-index conflict resolution path.
PGAPPNAME=ujani-replay-conflict-holder "${PSQL[@]}" >"$first_out" 2>&1 <<'SQL' &
BEGIN;
INSERT INTO ujani_control.task_contract_replays
 (tenant_id, task_id, sender_device_id, nonce, envelope_digest, payload_digest, expires_at, state)
VALUES
 ('tenant-a','task-expiry-race','device-a',decode(repeat('ab',32),'hex'),
  decode(repeat('bc',32),'hex'),decode(repeat('cd',32),'hex'),
  clock_timestamp() + interval '5 minutes','received');
SELECT pg_sleep(2);
ROLLBACK;
SQL
first_pid=$!

# Wait until the conflicting uncommitted row is visible in pg_stat_activity.
ready=0
for _ in {1..50}; do
  active="$("${PSQL[@]}" --command "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-replay-conflict-holder' AND state='active' AND query LIKE '%pg_sleep(2)%';" | tr -d '[:space:]')"
  if [[ "$active" == "1" ]]; then ready=1; break; fi
  if ! kill -0 "$first_pid" 2>/dev/null; then
    cat "$first_out" >&2
    echo "conflict-holder session exited before entering its lock-holding phase" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  cat "$first_out" >&2
  echo "timed out waiting for conflict-holder session" >&2
  exit 1
fi

set +e
PGAPPNAME=ujani-replay-expiring-claim "${PSQL[@]}" >"$second_out" 2>&1 <<'SQL' &
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';
SELECT ujani_control.claim_task_contract_replay(
 'tenant-a','task-expiry-race','device-a',decode(repeat('ab',32),'hex'),
 decode(repeat('bc',32),'hex'),decode(repeat('cd',32),'hex'),
 clock_timestamp() + interval '1 second'
);
COMMIT;
RESET ROLE;
SQL
second_pid=$!

# Confirm that session two is blocked on the first transaction, rather than
# merely testing an already-expired timestamp without exercising the race.
waiting=0
for _ in {1..50}; do
  waiter_count="$("${PSQL[@]}" --command "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-replay-expiring-claim' AND state='active' AND wait_event_type='Lock';" | tr -d '[:space:]')"
  if [[ "$waiter_count" =~ ^[1-9][0-9]*$ ]]; then waiting=1; break; fi
  if ! kill -0 "$second_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$waiting" != "1" ]]; then
  cat "$second_out" >&2
  echo "second replay claim was not observed waiting on the conflicting transaction" >&2
  wait "$first_pid" || true
  first_pid=""
  wait "$second_pid" || true
  second_pid=""
  exit 1
fi

wait "$first_pid"
first_pid=""
wait "$second_pid"
second_status=$?
second_pid=""
set -e

if [[ "$second_status" -eq 0 ]]; then
  cat "$second_out" >&2
  echo "replay claim unexpectedly committed after its expiry while waiting" >&2
  exit 1
fi
if ! grep -q 'task-contract replay claim expired during admission' "$second_out"; then
  cat "$second_out" >&2
  echo "replay claim failed for an unexpected reason; expected post-wait expiry rejection" >&2
  exit 1
fi

echo "Task-contract replay claim rechecked expiry after a unique-key transaction wait and rolled back."
