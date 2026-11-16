#!/usr/bin/env bash
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD must be set for the PostgreSQL integration test}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

"${PSQL[@]}" <<'SQL'
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('telemetry-v2-concurrency-test','Telemetry Concurrency Test')
ON CONFLICT (tenant_id) DO NOTHING;
DELETE FROM ujani_control.request_replays
 WHERE tenant_id='telemetry-v2-concurrency-test' AND device_id='worker-v2-1';
DELETE FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='telemetry-v2-concurrency-test' AND device_id='worker-v2-1';
INSERT INTO ujani_control.devices
 (tenant_id, device_id, display_name, platform, trust_state, owner_consent_state, admin_approval_state)
VALUES
 ('telemetry-v2-concurrency-test','worker-v2-1','Concurrency Worker','linux','enrolled','granted','approved')
ON CONFLICT (tenant_id, device_id) DO UPDATE
 SET trust_state='enrolled', owner_consent_state='granted', admin_approval_state='approved',
     telemetry_generation=0, telemetry_sequence=0, last_seen_at=NULL;
SQL

first_out="$(mktemp)"
second_out="$(mktemp)"
release_dir=""
first_pid=""
second_pid=""
if [[ -n "${POSTGRES_CONTAINER_ID:-}" ]]; then
  # PSQL_BIN executes psql inside the PostgreSQL service container. The release
  # marker must be created in that same container filesystem.
  release_file="/tmp/ujani-telemetry-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
  release_controller(){ docker exec "$POSTGRES_CONTAINER_ID" touch "$release_file"; }
  release_cleanup(){ docker exec "$POSTGRES_CONTAINER_ID" rm -f "$release_file" 2>/dev/null || true; }
else
  release_dir="$(mktemp -d)"
  release_file="$release_dir/release"
  release_controller(){ touch "$release_file"; }
  release_cleanup(){ rm -rf "$release_dir"; }
fi
export UJANI_TELEMETRY_RELEASE_FILE="$release_file"

cleanup(){
  release_controller 2>/dev/null || true
  if [[ -n "$first_pid" ]]; then wait "$first_pid" 2>/dev/null || true; fi
  if [[ -n "$second_pid" ]]; then wait "$second_pid" 2>/dev/null || true; fi
  rm -f "$first_out" "$second_out"
  release_cleanup
}
trap cleanup EXIT

(
 PGAPPNAME=ujani-telemetry-v2-first "${PSQL[@]}" >"$first_out" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'telemetry-v2-concurrency-test';
SELECT ujani_control.accept_device_telemetry_v2(
 'telemetry-v2-concurrency-test','worker-v2-1',1,1,0,decode(repeat('c1',16),'hex'),
 clock_timestamp() - interval '4 minutes 59 seconds',decode(repeat('b1',32),'hex'),2000,4096,'cool','ac','idle');
-- Hold the transaction and device-row lock until the controller has observed
-- the second connection blocked on that same row.
\! for i in $(seq 1 300); do [ -f "$UJANI_TELEMETRY_RELEASE_FILE" ] && exit 0; sleep 0.05; done; exit 1
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

first_ready=0
for _ in $(seq 1 100); do
  ready="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-telemetry-v2-first' AND state='idle in transaction' AND xact_start IS NOT NULL")"
  if [[ "$ready" == "1" ]] && grep -qx 't' "$first_out"; then first_ready=1; break; fi
  sleep 0.1
done
if [[ "$first_ready" != "1" ]]; then
  echo "first telemetry transaction did not enter its bounded lock-holding handshake" >&2
  cat "$first_out" >&2
  exit 1
fi

(
 PGAPPNAME=ujani-telemetry-v2-second "${PSQL[@]}" >"$second_out" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'telemetry-v2-concurrency-test';
SELECT ujani_control.accept_device_telemetry_v2(
 'telemetry-v2-concurrency-test','worker-v2-1',1,2,0,decode(repeat('c2',16),'hex'),
 clock_timestamp() - interval '4 minutes 58 seconds',decode(repeat('b2',32),'hex'),1800,3584,'cool','ac','idle');
COMMIT;
RESET ROLE;
SQL
) &
second_pid=$!

second_waiting=0
for _ in $(seq 1 100); do
  waiting="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity AS waiting WHERE waiting.application_name='ujani-telemetry-v2-second' AND waiting.state='active' AND waiting.wait_event_type='Lock' AND EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity AS blocker WHERE blocker.pid = ANY(pg_catalog.pg_blocking_pids(waiting.pid)) AND blocker.application_name='ujani-telemetry-v2-first')")"
  if [[ "$waiting" == "1" ]]; then second_waiting=1; break; fi
  sleep 0.1
done
if [[ "$second_waiting" != "1" ]]; then
  echo "second telemetry transaction was not observed waiting on the device-row lock" >&2
  cat "$second_out" >&2
  exit 1
fi

# Let the observation cross the five-minute age boundary while the second
# transaction is blocked on the device row. It must be rejected after the lock.
sleep 2
# Release only after PostgreSQL reports the second connection waiting on a lock.
release_controller

set +e
wait "$first_pid"
first_status=$?
wait "$second_pid"
second_status=$?
set -e
if [[ "$first_status" != "0" || "$second_status" != "0" ]]; then
  echo "concurrent telemetry transaction failed after the lock was released" >&2
  cat "$first_out" >&2
  cat "$second_out" >&2
  exit 1
fi
if ! grep -qx 't' "$first_out"; then
  echo "first concurrent telemetry transaction was not accepted" >&2
  cat "$first_out" >&2
  exit 1
fi
if ! grep -qx 'f' "$second_out"; then
  echo "second telemetry transaction should be rejected after its observation aged while waiting for the device lock" >&2
  cat "$second_out" >&2
  exit 1
fi

final_state="$("${PSQL[@]}" -c "SELECT telemetry_generation || ':' || telemetry_sequence || ':' || (SELECT count(*) FROM ujani_control.device_telemetry_samples WHERE tenant_id='telemetry-v2-concurrency-test' AND device_id='worker-v2-1') || ':' || (SELECT count(*) FROM ujani_control.request_replays WHERE tenant_id='telemetry-v2-concurrency-test' AND device_id='worker-v2-1' AND request_id=decode(repeat('c2',16),'hex')) FROM ujani_control.devices WHERE tenant_id='telemetry-v2-concurrency-test' AND device_id='worker-v2-1'")"
if [[ "$final_state" != "1:1:1:0" ]]; then
  echo "stale lock-wait telemetry changed the checkpoint, sample or replay ledger: $final_state" >&2
  exit 1
fi
echo "Concurrent telemetry row-lock serialization passed."
