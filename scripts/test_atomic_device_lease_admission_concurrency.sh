#!/usr/bin/env bash
set -euo pipefail
: "${PGPASSWORD:?PGPASSWORD must be set for PostgreSQL integration}"
PSQL_BIN="${PSQL_BIN:-psql}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --quiet --tuples-only --no-align)

"${PSQL[@]}" <<'SQL'
SELECT pg_catalog.set_config('ujani.tenant_id','admission-concurrency',false);
INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('admission-concurrency','Admission Concurrency') ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('admission-concurrency','admin','administrator',true,'ci','admin'),
 ('admission-concurrency','owner','operator',true,'ci','owner')
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at)
VALUES ('admission-concurrency','device','Device','linux','enrolled','granted',
 'approved','key',1,0,1,1,clock_timestamp())
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='granted',admin_approval_state='approved',
 active_key_id='key',key_generation=1,consent_generation=0,
 telemetry_generation=1,telemetry_sequence=1,last_seen_at=clock_timestamp(),
 reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES ('admission-concurrency','device','key',decode(repeat('71',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('admission-concurrency', 0));
SELECT 1 FROM ujani_control.devices
WHERE tenant_id='admission-concurrency' AND device_id='device' FOR UPDATE;
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES ('admission-concurrency','device','owner','admin',1,true,decode(repeat('70',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,
 bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('72',32),'hex'),bound_at=clock_timestamp();
COMMIT;
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-concurrency','device',1,'granted','owner',decode(repeat('72',32),'hex'))
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.device_telemetry_samples
 (tenant_id,device_id,generation,sequence,request_id,observed_at,payload_digest,reservation_revision,
  cpu_available_millis,memory_available_mb,thermal_state,power_state,participation_state)
VALUES ('admission-concurrency','device',1,1,decode(repeat('73',16),'hex'),
 clock_timestamp(),decode(repeat('74',32),'hex'),0,4000,8192,'cool','ac','idle')
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES ('admission-concurrency','workload',decode(repeat('75',32),'hex'),'inference','approved','admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET state='approved';
INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES ('admission-concurrency','approval','workload','admin','approved',
 decode(repeat('75',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET decision='approved',
 expires_at=clock_timestamp()+interval '10 minutes';
SQL

first_out="$(mktemp)"; second_out="$(mktemp)"
release_dir=""
if [[ -n "${POSTGRES_CONTAINER_ID:-}" ]]; then
 # PSQL_BIN executes psql inside the PostgreSQL service container. The marker
 # must live in that same container filesystem, not the Actions runner.
 release_file="/tmp/ujani-admission-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
 release_controller(){ docker exec "$POSTGRES_CONTAINER_ID" touch "$release_file"; }
 release_cleanup(){ docker exec "$POSTGRES_CONTAINER_ID" rm -f "$release_file" 2>/dev/null || true; }
else
 release_dir="$(mktemp -d)"
 release_file="$release_dir/release"
 release_controller(){ touch "$release_file"; }
 release_cleanup(){ rm -rf "$release_dir"; }
fi
export UJANI_ADMISSION_RELEASE_FILE="$release_file"
first_pid=""; second_pid=""
cleanup(){
 release_controller 2>/dev/null || true
 if [[ -n "$first_pid" ]]; then wait "$first_pid" 2>/dev/null || true; fi
 if [[ -n "$second_pid" ]]; then wait "$second_pid" 2>/dev/null || true; fi
 rm -f "$first_out" "$second_out"
 release_cleanup
}
trap cleanup EXIT
(
 PGAPPNAME=ujani-admission-first "${PSQL[@]}" >"$first_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-concurrency';
-- Keep CPU well below the 4,000 milli-core headroom. Memory alone is the
-- limiting resource: the two 5,000 MiB requests cannot fit in 8,192 MiB.
SELECT ujani_control.admit_device_lease(
 'admission-concurrency','device','workload','approval','lease-a',
 decode(repeat('81',16),'hex'),decode(repeat('82',32),'hex'),decode(repeat('75',32),'hex'),
 1,1,500,5000,decode(repeat('83',32),'hex'),
 clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000091');
-- Keep the transaction and device lock until the controller observes the
-- second connection waiting. The release is an explicit file handshake.
\! for i in $(seq 1 300); do [ -f "$UJANI_ADMISSION_RELEASE_FILE" ] && exit 0; sleep 0.05; done; exit 1
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!
first_ready=0
for _ in $(seq 1 100); do
 ready="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-admission-first' AND state='idle in transaction' AND xact_start IS NOT NULL")"
 if [[ "$ready" == "1" ]] && grep -qx 't' "$first_out"; then first_ready=1; break; fi
 sleep 0.1
done
if [[ "$first_ready" != "1" ]]; then
 echo "first admission did not enter its lock-holding handshake" >&2
 cat "$first_out" >&2
 exit 1
fi

(
 PGAPPNAME=ujani-admission-second "${PSQL[@]}" >"$second_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-concurrency';
SELECT ujani_control.admit_device_lease(
 'admission-concurrency','device','workload','approval','lease-b',
 decode(repeat('84',16),'hex'),decode(repeat('85',32),'hex'),decode(repeat('75',32),'hex'),
 1,1,500,5000,decode(repeat('86',32),'hex'),
 clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000092');
COMMIT;
RESET ROLE;
SQL
) &
second_pid=$!
second_waiting=0
for _ in $(seq 1 100); do
 waiting="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='ujani-admission-second' AND state='active' AND wait_event_type='Lock'")"
 if [[ "$waiting" == "1" ]]; then second_waiting=1; break; fi
 sleep 0.1
done
# Release only after observing the second admission blocked on the device lock.
release_controller

set +e
wait "$first_pid"
first_status=$?
wait "$second_pid"
second_status=$?
set -e
if [[ "$first_status" -ne 0 ]]; then
 echo "first admission failed" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if [[ "$second_waiting" != "1" ]]; then
 echo "second admission was not observed waiting on the device row lock" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if [[ "$second_status" -ne 0 ]]; then
 echo "second admission query failed instead of returning a denial" >&2
 cat "$first_out" "$second_out" >&2
 exit 1
fi
if ! grep -qx 't' "$first_out"; then echo "first admission did not succeed" >&2; cat "$first_out" >&2; exit 1; fi
if ! grep -qx 'f' "$second_out"; then echo "second admission should be rejected after serialized capacity recheck" >&2; cat "$second_out" >&2; exit 1; fi
state="$(\"${PSQL[@]}\" -c "SELECT (SELECT count(*) FROM ujani_control.leases WHERE tenant_id='admission-concurrency' AND device_id='device' AND state='reserved' AND expires_at>clock_timestamp()) || ':' || (SELECT COALESCE(sum(requested_cpu_millis),0) FROM ujani_control.leases WHERE tenant_id='admission-concurrency' AND device_id='device' AND state='reserved' AND expires_at>clock_timestamp()) || ':' || (SELECT COALESCE(sum(requested_memory_mb),0) FROM ujani_control.leases WHERE tenant_id='admission-concurrency' AND device_id='device' AND state='reserved' AND expires_at>clock_timestamp()) || ':' || (SELECT count(*) FROM ujani_control.request_replays WHERE tenant_id='admission-concurrency' AND device_id='device' AND request_id=decode(repeat('81',16),'hex')) || ':' || (SELECT count(*) FROM ujani_control.request_replays WHERE tenant_id='admission-concurrency' AND device_id='device' AND request_id=decode(repeat('84',16),'hex')) || ':' || (SELECT count(*) FROM ujani_control.leases WHERE tenant_id='admission-concurrency' AND device_id='device' AND lease_id='lease-a' AND state='reserved' AND requested_cpu_millis=500 AND requested_memory_mb=5000 AND expires_at>clock_timestamp()) || ':' || (SELECT count(*) FROM ujani_control.leases WHERE tenant_id='admission-concurrency' AND device_id='device' AND lease_id='lease-b')")"
if [[ "$state" != "1:500:5000:1:0:1:0" ]]; then
 echo "memory admission or exact replay/lease invariants failed: $state" >&2
 exit 1
fi
echo "Concurrent memory admission serialization passed."
