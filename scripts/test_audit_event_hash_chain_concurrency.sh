#!/usr/bin/env bash
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD must be set for the PostgreSQL integration test}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

run_id="$(date -u +%Y%m%d%H%M%S)-$$-${RANDOM}"
tenant_id="audit-concurrency-${run_id}"
first_event_id="$("${PSQL[@]}" -c "SELECT gen_random_uuid()")"
second_event_id="$("${PSQL[@]}" -c "SELECT gen_random_uuid()")"

"${PSQL[@]}" -v tenant_id="$tenant_id" <<'SQL'
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES (:'tenant_id','Audit Concurrency Test');
SQL

first_out="$(mktemp)"
second_out="$(mktemp)"
cleanup() { rm -f "$first_out" "$second_out"; }
trap cleanup EXIT

(
 PGAPPNAME=ujani-audit-first "${PSQL[@]}" -v tenant_id="$tenant_id" -v event_id="$first_event_id" >"$first_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = :'tenant_id';
INSERT INTO ujani_control.audit_events
 (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
VALUES
 (:'tenant_id', :'event_id'::uuid, 'operator-a','administrator','audit.concurrent.first','accepted');
SELECT pg_sleep(15);
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

first_locked=0
for _ in $(seq 1 100); do
 active="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-audit-first' AND state='active' AND query LIKE '%pg_sleep(15)%'")"
 if [[ "$active" == "1" ]]; then first_locked=1; break; fi
 sleep 0.1
done
if [[ "$first_locked" != "1" ]]; then
 echo "first audit session did not reach its lock-holding phase" >&2
 cat "$first_out" >&2
 set +e
 wait "$first_pid"
 set -e
 exit 1
fi

(
 PGAPPNAME=ujani-audit-second "${PSQL[@]}" -v tenant_id="$tenant_id" -v event_id="$second_event_id" >"$second_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL ujani.tenant_id = :'tenant_id';
-- Establish the transaction snapshot before waiting for the first writer.
SELECT count(*) FROM ujani_control.audit_events WHERE tenant_id = :'tenant_id';
INSERT INTO ujani_control.audit_events
 (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
VALUES
 (:'tenant_id', :'event_id'::uuid, 'operator-b','administrator','audit.concurrent.second','accepted');
COMMIT;
RESET ROLE;
SQL
) &
second_pid=$!

second_waiting=0
for _ in $(seq 1 100); do
 waiting="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-audit-second' AND wait_event_type='Lock' AND wait_event='advisory'")"
 if [[ "$waiting" == "1" ]]; then second_waiting=1; break; fi
 sleep 0.1
done

set +e
wait "$first_pid"
first_status=$?
wait "$second_pid"
second_status=$?
set -e

if [[ "$first_status" -ne 0 ]]; then
 echo "first audit writer failed" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if [[ "$second_waiting" != "1" ]]; then
 echo "second audit writer was not observed waiting on the tenant advisory lock" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if [[ "$second_status" -eq 0 ]]; then
 echo "stale REPEATABLE READ writer unexpectedly committed instead of failing closed" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if ! grep -Eq 'duplicate key value violates unique constraint|could not serialize access' "$second_out"; then
 echo "stale REPEATABLE READ writer failed for an unexpected reason" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi

# Retry with a fresh READ COMMITTED transaction; it must link to the committed tip.
PGAPPNAME=ujani-audit-second-retry "${PSQL[@]}" -v tenant_id="$tenant_id" -v event_id="$second_event_id" >"$second_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL ujani.tenant_id = :'tenant_id';
INSERT INTO ujani_control.audit_events
 (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
VALUES
 (:'tenant_id', :'event_id'::uuid, 'operator-b','administrator','audit.concurrent.second','accepted');
COMMIT;
RESET ROLE;
SQL

chain_state="$("${PSQL[@]}" -c "
 SELECT
  count(*) || ':' ||
  ((array_agg(previous_digest ORDER BY sequence_id))[1] IS NULL)::text || ':' ||
  ((array_agg(previous_digest ORDER BY sequence_id))[2] =
   (array_agg(event_digest ORDER BY sequence_id))[1])::text
 FROM ujani_control.audit_events
 WHERE tenant_id='${tenant_id}'
")"
if [[ "$chain_state" != "2:true:true" ]]; then
 echo "concurrent audit writes forked or lost the tenant hash chain: $chain_state" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi

echo "Concurrent audit hash-chain serialization passed."
