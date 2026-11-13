#!/usr/bin/env bash
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD must be set for the PostgreSQL integration test}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

"${PSQL[@]}" <<'SQL'
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('audit-concurrency-test','Audit Concurrency Test')
ON CONFLICT (tenant_id) DO NOTHING;
SQL

first_out="$(mktemp)"
second_out="$(mktemp)"
cleanup() { rm -f "$first_out" "$second_out"; }
trap cleanup EXIT

(
 PGAPPNAME=ujani-audit-first "${PSQL[@]}" >"$first_out" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'audit-concurrency-test';
INSERT INTO ujani_control.audit_events
 (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
VALUES
 ('audit-concurrency-test','00000000-0000-4000-8000-000000000201',
  'operator-a','administrator','audit.concurrent.first','accepted');
SELECT pg_sleep(1);
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

locked=0
for _ in $(seq 1 100); do
 active="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-audit-first' AND state='active' AND query LIKE '%pg_sleep(1)%'")"
 if [[ "$active" == "1" ]]; then locked=1; break; fi
 sleep 0.1
done
if [[ "$locked" != "1" ]]; then
 echo "first audit session did not reach its lock-holding phase" >&2
 cat "$first_out" >&2
 exit 1
fi

"${PSQL[@]}" >"$second_out" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'audit-concurrency-test';
INSERT INTO ujani_control.audit_events
 (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
VALUES
 ('audit-concurrency-test','00000000-0000-4000-8000-000000000202',
  'operator-b','administrator','audit.concurrent.second','accepted');
COMMIT;
RESET ROLE;
SQL
wait "$first_pid"

chain_state="$("${PSQL[@]}" -c "
 SELECT
  count(*) || ':' ||
  ((array_agg(previous_digest ORDER BY sequence_id))[1] IS NULL)::text || ':' ||
  ((array_agg(previous_digest ORDER BY sequence_id))[2] =
   (array_agg(event_digest ORDER BY sequence_id))[1])::text
 FROM ujani_control.audit_events
 WHERE tenant_id='audit-concurrency-test'
")"
if [[ "$chain_state" != "2:true:true" ]]; then
 echo "concurrent audit writes forked or lost the tenant hash chain: $chain_state" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi

echo "Concurrent audit hash-chain serialization passed."
