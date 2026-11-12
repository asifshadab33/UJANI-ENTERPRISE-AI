#!/usr/bin/env bash
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD must be set for the PostgreSQL integration test}"
PSQL=(psql --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

"${PSQL[@]}" <<'SQL'
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('telemetry-concurrency-test','Telemetry Concurrency Test')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.devices
 (tenant_id, device_id, display_name, platform, trust_state, owner_consent_state, admin_approval_state)
VALUES
 ('telemetry-concurrency-test','worker-1','Concurrency Worker','linux','enrolled','granted','approved')
ON CONFLICT (tenant_id, device_id) DO UPDATE
 SET trust_state='enrolled', owner_consent_state='granted', admin_approval_state='approved',
     telemetry_generation=0, telemetry_sequence=0, last_seen_at=NULL;
SQL

first_out="$(mktemp)"
second_out="$(mktemp)"
cleanup() { rm -f "$first_out" "$second_out"; }
trap cleanup EXIT

(
 PGAPPNAME=ujani-telemetry-first "${PSQL[@]}" >"$first_out" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'telemetry-concurrency-test';
SELECT ujani_control.accept_device_telemetry(
 'telemetry-concurrency-test','worker-1',1,1,decode(repeat('a1',16),'hex'),
 clock_timestamp(),decode(repeat('b1',32),'hex'),2000,4096,'cool','ac','idle');
SELECT pg_sleep(1);
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

# Wait until session one is holding the device-row lock inside pg_sleep.
locked=0
for _ in $(seq 1 100); do
  active="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-telemetry-first' AND state='active' AND query LIKE '%pg_sleep(1)%'")"
  if [[ "$active" == "1" ]]; then locked=1; break; fi
  sleep 0.1
done
if [[ "$locked" != "1" ]]; then
  echo "first telemetry session did not reach its lock-holding phase" >&2
  cat "$first_out" >&2
  exit 1
fi
"${PSQL[@]}" >"$second_out" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'telemetry-concurrency-test';
SELECT ujani_control.accept_device_telemetry(
 'telemetry-concurrency-test','worker-1',1,2,decode(repeat('a2',16),'hex'),
 clock_timestamp(),decode(repeat('b2',32),'hex'),1800,3584,'cool','ac','idle');
COMMIT;
RESET ROLE;
SQL
wait "$first_pid"

if ! grep -qx 't' "$first_out"; then
  echo "first concurrent telemetry transaction was not accepted" >&2
  cat "$first_out" >&2
  exit 1
fi
if ! grep -qx 't' "$second_out"; then
  echo "second concurrent telemetry transaction was not accepted after row-lock serialization" >&2
  cat "$second_out" >&2
  exit 1
fi

final_state="$("${PSQL[@]}" -c "SELECT telemetry_generation || ':' || telemetry_sequence || ':' || (SELECT count(*) FROM ujani_control.device_telemetry_samples WHERE tenant_id='telemetry-concurrency-test' AND device_id='worker-1') FROM ujani_control.devices WHERE tenant_id='telemetry-concurrency-test' AND device_id='worker-1'")"
if [[ "$final_state" != "1:2:2" ]]; then
  echo "unexpected serialized telemetry checkpoint/sample count: $final_state" >&2
  exit 1
fi

echo "Concurrent telemetry row-lock serialization passed."
