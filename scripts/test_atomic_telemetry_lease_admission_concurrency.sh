#!/usr/bin/env bash
set -euo pipefail
: "${PGPASSWORD:?PGPASSWORD must be set for PostgreSQL integration}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

# Use a dedicated tenant so this test is repeatable and independent of the
# existing lease-admission concurrency fixture.
"${PSQL[@]}" <<'SQL'
SELECT pg_catalog.set_config('ujani.tenant_id','telemetry-lease-concurrency',false);
INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('telemetry-lease-concurrency','Telemetry Lease Concurrency') ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('telemetry-lease-concurrency','admin','administrator',true,'ci','admin'),
 ('telemetry-lease-concurrency','owner','operator',true,'ci','owner')
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES ('telemetry-lease-concurrency','device','Device','linux','enrolled','granted',
 'approved','key',1,0,1,1,clock_timestamp(),0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='granted',admin_approval_state='approved',
 active_key_id='key',key_generation=1,consent_generation=0,
 telemetry_generation=1,telemetry_sequence=1,last_seen_at=clock_timestamp(),
 reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES ('telemetry-lease-concurrency','device','key',decode(repeat('71',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('telemetry-lease-concurrency', 0));
SELECT 1 FROM ujani_control.devices
WHERE tenant_id='telemetry-lease-concurrency' AND device_id='device' FOR UPDATE;
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES ('telemetry-lease-concurrency','device','owner','admin',1,true,decode(repeat('70',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,
 bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('72',32),'hex'),bound_at=clock_timestamp();
COMMIT;
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('telemetry-lease-concurrency','device',1,'granted','owner',decode(repeat('72',32),'hex'))
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.device_telemetry_samples
 (tenant_id,device_id,generation,sequence,request_id,observed_at,payload_digest,reservation_revision,
  cpu_available_millis,memory_available_mb,thermal_state,power_state,participation_state)
VALUES ('telemetry-lease-concurrency','device',1,1,decode(repeat('73',16),'hex'),
 clock_timestamp(),decode(repeat('74',32),'hex'),0,4000,8192,'cool','ac','idle')
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES ('telemetry-lease-concurrency','workload',decode(repeat('75',32),'hex'),'inference','approved','admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET state='approved';
INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES ('telemetry-lease-concurrency','approval','workload','admin','approved',
 decode(repeat('75',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET decision='approved',
 expires_at=clock_timestamp()+interval '10 minutes';
SQL

first_out="$(mktemp)"; second_out="$(mktemp)"
release_dir=""
if [[ -n "${POSTGRES_CONTAINER_ID:-}" ]]; then
 release_file="/tmp/ujani-telemetry-lease-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
 release_controller(){ docker exec "$POSTGRES_CONTAINER_ID" touch "$release_file"; }
 release_cleanup(){ docker exec "$POSTGRES_CONTAINER_ID" rm -f "$release_file" 2>/dev/null || true; }
else
 release_dir="$(mktemp -d)"
 release_file="$release_dir/release"
 release_controller(){ touch "$release_file"; }
 release_cleanup(){ rm -rf "$release_dir"; }
fi
export UJANI_TELEMETRY_LEASE_RELEASE_FILE="$release_file"
first_pid=""; second_pid=""
cleanup(){
 release_controller 2>/dev/null || true
 if [[ -n "$first_pid" ]]; then wait "$first_pid" 2>/dev/null || true; fi
 if [[ -n "$second_pid" ]]; then wait "$second_pid" 2>/dev/null || true; fi
 rm -f "$first_out" "$second_out"
 release_cleanup
}
trap cleanup EXIT

# The first transaction admits telemetry and a lease, then deliberately keeps
# the device row lock until the second transaction is observed waiting on it.
(
 PGAPPNAME=ujani-telemetry-lease-first "${PSQL[@]}" >"$first_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='telemetry-lease-concurrency';
SELECT ujani_control.admit_device_lease_with_telemetry(
 'telemetry-lease-concurrency','device',
 1,1,1,2,0,
 decode(repeat('81',16),'hex'),clock_timestamp(),decode(repeat('82',32),'hex'),
 4000,8192,'cool','ac','idle',
 'workload','approval','lease-a',
 decode(repeat('83',16),'hex'),decode(repeat('84',32),'hex'),
 decode(repeat('75',32),'hex'),2500,1024,decode(repeat('85',32),'hex'),
 clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000191');
\! for i in $(seq 1 300); do [ -f "$UJANI_TELEMETRY_LEASE_RELEASE_FILE" ] && exit 0; sleep 0.05; done; exit 1
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!
first_ready=0
for _ in $(seq 1 100); do
 ready="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-telemetry-lease-first' AND state='idle in transaction' AND xact_start IS NOT NULL")"
 if [[ "$ready" == "1" ]] && grep -qx 't' "$first_out"; then first_ready=1; break; fi
 sleep 0.1
done
if [[ "$first_ready" != "1" ]]; then
 echo "first combined admission did not enter its lock-holding handshake" >&2
 cat "$first_out" >&2
 exit 1
fi

# The second call carries a distinct replay ID but the same telemetry sequence
# and reservation watermark. It must wait, then fail closed after the first
# transaction commits; it must not create a second lease or partial telemetry.
(
 PGAPPNAME=ujani-telemetry-lease-second "${PSQL[@]}" >"$second_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='telemetry-lease-concurrency';
SELECT ujani_control.admit_device_lease_with_telemetry(
 'telemetry-lease-concurrency','device',
 1,1,1,2,0,
 decode(repeat('86',16),'hex'),clock_timestamp(),decode(repeat('87',32),'hex'),
 4000,8192,'cool','ac','idle',
 'workload','approval','lease-b',
 decode(repeat('88',16),'hex'),decode(repeat('89',32),'hex'),
 decode(repeat('75',32),'hex'),2500,1024,decode(repeat('8a',32),'hex'),
 clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000192');
COMMIT;
RESET ROLE;
SQL
) &
second_pid=$!
second_waiting=0
for _ in $(seq 1 100); do
 waiting="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-telemetry-lease-second' AND state='active' AND wait_event_type='Lock'")"
 if [[ "$waiting" == "1" ]]; then second_waiting=1; break; fi
 sleep 0.1
done
release_controller

set +e
wait "$first_pid"; first_status=$?
wait "$second_pid"; second_status=$?
set -e
if [[ "$first_status" -ne 0 ]]; then
 echo "first combined admission failed" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if [[ "$second_waiting" != "1" ]]; then
 echo "second combined admission was not observed waiting on the device row lock" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if [[ "$second_status" -ne 0 ]]; then
 echo "second combined admission query failed instead of returning a denial" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if ! grep -qx 't' "$first_out"; then
 echo "first combined admission should succeed" >&2
 cat "$first_out" >&2
 exit 1
fi
if ! grep -qx 'f' "$second_out"; then
 echo "second combined admission should be rejected after serialized telemetry recheck" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
state="$("${PSQL[@]}" -c "SELECT (SELECT count(*) FROM ujani_control.leases WHERE tenant_id='telemetry-lease-concurrency' AND device_id='device' AND state='reserved' AND expires_at>clock_timestamp()) || ':' || (SELECT count(*) FROM ujani_control.device_telemetry_samples WHERE tenant_id='telemetry-lease-concurrency' AND device_id='device' AND generation=1 AND sequence=2) || ':' || (SELECT count(*) FROM ujani_control.request_replays WHERE tenant_id='telemetry-lease-concurrency' AND device_id='device' AND request_id IN (decode(repeat('81',16),'hex'),decode(repeat('83',16),'hex'))) || ':' || (SELECT count(*) FROM ujani_control.request_replays WHERE tenant_id='telemetry-lease-concurrency' AND device_id='device' AND request_id IN (decode(repeat('86',16),'hex'),decode(repeat('88',16),'hex')))")"
if [[ "$state" != "1:1:2:0" ]]; then
 echo "combined admission left unexpected lease, telemetry or replay state: $state" >&2
 exit 1
fi
echo "Concurrent atomic telemetry-plus-lease admission passed."
