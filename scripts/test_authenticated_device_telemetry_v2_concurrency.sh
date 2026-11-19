#!/usr/bin/env bash
set -euo pipefail

: "\${PGPASSWORD:?PGPASSWORD must be set for PostgreSQL integration}"
PSQL_BIN="\${PSQL_BIN:-psql}"
PSQL=( "$PSQL_BIN" --host "\${PGHOST:-localhost}" --username "\${PGUSER:-postgres}" --dbname "\${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align )

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

(
  PGAPPNAME=ujani-auth-telemetry-first "\${PSQL[@]}" >"$first_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='authenticated-telemetry-test';
SELECT CASE WHEN ujani_control.accept_authenticated_device_telemetry_v2(
 'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
 1,1,1,2,0,decode(repeat('b1',16),'hex'),
 floor(date_part('epoch',clock_timestamp()+interval '20 seconds')*1000)::bigint,
 clock_timestamp(),decode(repeat('b2',32),'hex'),4000,8192,'cool','ac','idle'
) THEN 'accepted' ELSE 'rejected' END;
SELECT pg_sleep(5);
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

first_ready=0
for _ in $(seq 1 100); do
  active="$("\${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='ujani-auth-telemetry-first' AND state='active' AND query LIKE '%pg_sleep%'")"
  if [[ "$active" == "1" ]] && grep -qx 'accepted' "$first_out"; then
    first_ready=1
    break
  fi
  sleep 0.1
done
if [[ "$first_ready" != "1" ]]; then
  echo "first telemetry worker did not accept the sample and hold its transaction" >&2
  cat "$first_out" >&2
  exit 1
fi

(
  PGAPPNAME=ujani-auth-telemetry-second "\${PSQL[@]}" >"$second_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='authenticated-telemetry-test';
SELECT CASE WHEN ujani_control.accept_authenticated_device_telemetry_v2(
 'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
 1,1,1,2,0,decode(repeat('b3',16),'hex'),
 floor(date_part('epoch',clock_timestamp()+interval '20 seconds')*1000)::bigint,
 clock_timestamp(),decode(repeat('b4',32),'hex'),4000,8192,'cool','ac','idle'
) THEN 'accepted' ELSE 'rejected' END;
COMMIT;
RESET ROLE;
SQL
) &
second_pid=$!

second_waiting=0
for _ in $(seq 1 100); do
  waiting="$("\${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity AS waiting WHERE waiting.application_name='ujani-auth-telemetry-second' AND waiting.state='active' AND waiting.wait_event_type='Lock' AND EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity AS blocker WHERE blocker.pid = ANY(pg_catalog.pg_blocking_pids(waiting.pid)) AND blocker.application_name='ujani-auth-telemetry-first')")"
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
  echo "concurrent authenticated telemetry worker failed" >&2
  cat "$first_out" "$second_out" >&2
  exit 1
fi
if [[ "$second_waiting" != "1" ]]; then
  echo "second telemetry worker was not observed waiting on the tenant/device lock" >&2
  cat "$first_out" "$second_out" >&2
  exit 1
fi
if ! grep -qx 'accepted' "$first_out" || ! grep -qx 'rejected' "$second_out"; then
  echo "exactly one concurrent sample with the same generation/sequence must be accepted" >&2
  cat "$first_out" "$second_out" >&2
  exit 1
fi

state="$("\${PSQL[@]}" -c "SELECT CASE WHEN (SELECT telemetry_sequence=2 FROM ujani_control.devices WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device') AND (SELECT count(*)=1 FROM ujani_control.device_telemetry_samples WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device' AND generation=1 AND sequence=2) AND (SELECT count(*)=1 FROM ujani_control.request_replays WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device' AND request_id=decode(repeat('b1',16),'hex')) AND (SELECT count(*)=0 FROM ujani_control.request_replays WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device' AND request_id=decode(repeat('b3',16),'hex')) AND (SELECT count(*)=2 FROM ujani_control.audit_events WHERE tenant_id='authenticated-telemetry-test' AND event_type='device.telemetry.accepted' AND object_ref='telemetry-device') THEN 'ok' ELSE 'bad' END")"
if [[ "$state" != "ok" ]]; then
  echo "concurrent telemetry admission did not preserve one sample, replay claim and audit receipt: $state" >&2
  exit 1
fi

echo "Concurrent authenticated telemetry admission passed."
