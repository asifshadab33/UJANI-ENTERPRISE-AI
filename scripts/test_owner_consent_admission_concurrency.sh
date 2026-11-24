#!/usr/bin/env bash
set -euo pipefail
: "${PGPASSWORD:?PGPASSWORD must be set for PostgreSQL integration}"
PSQL_BIN="${PSQL_BIN:-psql}"
tenant="consent-admission-race-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --set tenant="$tenant" --quiet --tuples-only --no-align)

# Race a combined telemetry+lease admission against owner withdrawal. The
# admission must acquire the tenant audit advisory lock before the device row,
# so withdrawal waits on that same lock rather than holding it while waiting
# for the device row (the inverse order can deadlock).
"${PSQL[@]}" <<'SQL'
SELECT pg_catalog.set_config('ujani.tenant_id', :'tenant', false);
INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES (:'tenant','Consent Admission Lock Order') ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 (:'tenant','race-admin','administrator',true,'ci','race-admin'),
 (:'tenant','race-owner','operator',true,'ci','race-owner')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET enabled=true;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES (:'tenant','race-device','Race Device','linux','enrolled','unknown',
 'approved','race-key',1,0,0,0,NULL,0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='race-key',key_generation=1,consent_generation=0,
 telemetry_generation=0,telemetry_sequence=0,last_seen_at=NULL,reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES (:'tenant','race-device','race-key',decode(repeat('41',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES (:'tenant','race-device','race-owner','race-admin',1,true,decode(repeat('42',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id='race-owner',bound_by_subject_id='race-admin',
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('43',32),'hex'),bound_at=clock_timestamp();
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES (:'tenant','race-device',1,'granted','race-owner',decode(repeat('44',32),'hex'));
INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES (:'tenant','race-workload',decode(repeat('45',32),'hex'),'inference','approved','race-admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET state='approved';
INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES (:'tenant','race-approval','race-workload','race-admin','approved',
 decode(repeat('45',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET decision='approved',
 expires_at=clock_timestamp()+interval '10 minutes';
GRANT EXECUTE ON FUNCTION ujani_control.admit_device_lease_with_telemetry(
 text,text,bigint,bigint,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text,
 text,text,text,bytea,bytea,bytea,integer,bigint,bytea,timestamptz,uuid
) TO ujani_runtime;
SQL

first_out="$(mktemp)"; withdraw_out="$(mktemp)"
release_dir=""
if [[ -n "${POSTGRES_CONTAINER_ID:-}" ]]; then
 release_file="/tmp/ujani-consent-admission-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
 release_controller(){ docker exec "$POSTGRES_CONTAINER_ID" touch "$release_file"; }
 release_cleanup(){ docker exec "$POSTGRES_CONTAINER_ID" rm -f "$release_file" 2>/dev/null || true; }
else
 release_dir="$(mktemp -d)"
 release_file="$release_dir/release"
 release_controller(){ touch "$release_file"; }
 release_cleanup(){ rm -rf "$release_dir"; }
fi
export UJANI_TELEMETRY_RELEASE_FILE="$release_file"
first_pid=""; withdraw_pid=""
cleanup(){
 release_controller 2>/dev/null || true
 if [[ -n "$first_pid" ]]; then wait "$first_pid" 2>/dev/null || true; fi
 if [[ -n "$withdraw_pid" ]]; then wait "$withdraw_pid" 2>/dev/null || true; fi
 rm -f "$first_out" "$withdraw_out"
 release_cleanup
}
trap cleanup EXIT

# Hold the successful admission transaction open after it has acquired the
# tenant advisory lock and device row. The shell handshake makes the overlap
# deterministic without relying on wall-clock timing.
(
 PGAPPNAME=ujani-consent-admission-first "${PSQL[@]}" >"$first_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id=:'tenant';
SELECT ujani_control.admit_device_lease_with_telemetry(
 :'tenant','race-device',
 1,1,1,1,0,
 decode(repeat('51',16),'hex'),clock_timestamp(),decode(repeat('52',32),'hex'),
 4000,8192,'cool','ac','idle',
 'race-workload','race-approval','race-lease',
 decode(repeat('53',16),'hex'),decode(repeat('54',32),'hex'),
 decode(repeat('45',32),'hex'),500,512,decode(repeat('55',32),'hex'),
 clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000401');
\! for i in $(seq 1 300); do [ -f "$UJANI_TELEMETRY_RELEASE_FILE" ] && exit 0; sleep 0.05; done; exit 1
COMMIT;
RESET ROLE;
SQL
) &
first_pid=$!

first_ready=0
for _ in $(seq 1 100); do
 ready="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='ujani-consent-admission-first' AND state='idle in transaction' AND xact_start IS NOT NULL")"
 if [[ "$ready" == "1" ]] && grep -qx 't' "$first_out"; then first_ready=1; break; fi
 sleep 0.1
done
if [[ "$first_ready" != "1" ]]; then
 echo "combined admission did not enter its lock-holding handshake" >&2
 cat "$first_out" >&2
 exit 1
fi

# The withdrawal trigger must wait for the same advisory lock, not acquire it
# first and then wait on the device row. The old lock order produces a deadlock.
(
 PGAPPNAME=ujani-consent-admission-withdraw "${PSQL[@]}" >"$withdraw_out" 2>&1 <<'SQL'
BEGIN;
SET LOCAL ujani.tenant_id=:'tenant';
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES (:'tenant','race-device',2,'withdrawn','race-owner',decode(repeat('56',32),'hex'));
COMMIT;
SQL
) &
withdraw_pid=$!

withdraw_waiting=0
for _ in $(seq 1 100); do
 waiting="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity w JOIN pg_catalog.pg_locks wl ON wl.pid=w.pid AND wl.locktype='advisory' AND wl.granted IS FALSE WHERE w.application_name='ujani-consent-admission-withdraw' AND EXISTS (SELECT 1 FROM pg_catalog.pg_locks bl WHERE bl.pid=ANY(pg_catalog.pg_blocking_pids(w.pid)) AND bl.locktype='advisory' AND bl.granted IS TRUE AND bl.classid=wl.classid AND bl.objid=wl.objid AND bl.objsubid=wl.objsubid)")"
 if [[ "$waiting" == "1" ]]; then withdraw_waiting=1; break; fi
 sleep 0.1
done

release_controller
set +e
wait "$first_pid"; first_status=$?; first_pid=""
wait "$withdraw_pid"; withdraw_status=$?; withdraw_pid=""
set -e
if [[ "$first_status" -ne 0 || "$withdraw_status" -ne 0 || "$withdraw_waiting" != "1" ]]; then
 echo "admission/withdrawal did not serialize on the tenant advisory lock" >&2
 cat "$first_out" "$withdraw_out" >&2
 exit 1
fi
if ! grep -qx 't' "$first_out"; then
 echo "combined admission should succeed before the waiting withdrawal" >&2
 cat "$first_out" >&2
 exit 1
fi

state="$("${PSQL[@]}" -c "SELECT CASE WHEN d.owner_consent_state='withdrawn' AND d.consent_generation=2 AND l.state='revoked' AND l.revision=2 AND (SELECT count(*) FROM ujani_control.audit_events a WHERE a.tenant_id=l.tenant_id AND a.object_ref=l.lease_id AND a.event_type IN ('device.lease.admitted','device.lease.revoked'))=2 AND (SELECT count(*) FROM ujani_control.device_telemetry_samples s WHERE s.tenant_id=l.tenant_id AND s.device_id=l.device_id AND s.generation=1 AND s.sequence=1)=1 AND (SELECT count(*) FROM ujani_control.request_replays r WHERE r.tenant_id=l.tenant_id AND r.device_id=l.device_id AND r.request_id IN (decode(repeat('51',16),'hex'),decode(repeat('53',16),'hex')))=2 THEN 'ok' ELSE 'bad' END FROM ujani_control.devices d JOIN ujani_control.leases l USING (tenant_id,device_id) WHERE d.tenant_id='${tenant}' AND d.device_id='race-device' AND l.lease_id='race-lease'")"
if [[ "$state" != "ok" ]]; then
 echo "withdrawal did not revoke the admitted lease atomically with consent and audit: $state" >&2
 "${PSQL[@]}" -c "SELECT d.owner_consent_state,d.consent_generation,l.state,l.revision FROM ujani_control.devices d JOIN ujani_control.leases l USING (tenant_id,device_id) WHERE d.tenant_id='${tenant}' AND l.lease_id='race-lease'" >&2
 exit 1
fi

echo "Owner-consent withdrawal serialized before/after combined admission using the tenant advisory lock."
