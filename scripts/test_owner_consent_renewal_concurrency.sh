#!/usr/bin/env bash
set -euo pipefail
: "${PGPASSWORD:?PGPASSWORD must be set for PostgreSQL integration}"
PSQL_BIN="${PSQL_BIN:-psql}"
tenant="consent-renewal-race-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
PSQL=("$PSQL_BIN" --host "${PGHOST:-localhost}" --username "${PGUSER:-postgres}" --dbname "${PGDATABASE:-ujani_test}" --set ON_ERROR_STOP=1 --set tenant="$tenant" --quiet --tuples-only --no-align)

# Isolated tenant fixture: owner withdrawal must serialize against an authenticated
# lease-renewal SQL primitive and revoke the renewed lease in the same transaction.
"${PSQL[@]}" <<'SQL'
SELECT pg_catalog.set_config('ujani.tenant_id',:'tenant',false);
INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES (:'tenant','Consent Renewal Race') ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 (:'tenant','race-admin','administrator',true,'ci','race-admin'),
 (:'tenant','race-owner','operator',true,'ci','race-owner')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET enabled=true;
INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES (:'tenant','race-workload',decode(repeat('31',32),'hex'),'inference','approved','race-admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET state='approved';
INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES (:'tenant','race-approval','race-workload','race-admin','approved',
 decode(repeat('31',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET decision='approved',expires_at=clock_timestamp()+interval '10 minutes';
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES (:'tenant','race-device','Race Device','linux','enrolled','unknown',
 'approved','race-key',1,0,1,1,clock_timestamp(),0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='race-key',key_generation=1,consent_generation=0,
 telemetry_generation=1,telemetry_sequence=1,last_seen_at=clock_timestamp(),reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES (:'tenant','race-device','race-key',decode(repeat('32',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES (:'tenant','race-device','race-owner','race-admin',1,true,decode(repeat('33',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET owner_subject_id='race-owner',
 bound_by_subject_id='race-admin',binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('34',32),'hex'),bound_at=clock_timestamp();
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES (:'tenant','race-device',1,'granted','race-owner',decode(repeat('35',32),'hex'))
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.device_telemetry_samples
 (tenant_id,device_id,generation,sequence,request_id,observed_at,payload_digest,reservation_revision,
  cpu_available_millis,memory_available_mb,thermal_state,power_state,participation_state)
VALUES (:'tenant','race-device',1,1,decode(repeat('36',16),'hex'),clock_timestamp(),
 decode(repeat('37',32),'hex'),0,4000,8192,'cool','ac','idle')
ON CONFLICT DO NOTHING;
SQL

# Admit a lease under generation 1. The following race exercises renewal and
# withdrawal, not the admission implementation itself.
"${PSQL[@]}" <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id=:'tenant';
SELECT ujani_control.admit_device_lease(
 :'tenant','race-device','race-workload','race-approval','race-lease',
 decode(repeat('38',16),'hex'),decode(repeat('39',32),'hex'),decode(repeat('31',32),'hex'),
 1,1,500,512,decode(repeat('3a',32),'hex'),clock_timestamp()+interval '4 minutes',
 '00000000-0000-4000-8000-000000000301');
COMMIT;
RESET ROLE;
SQL

renew_out="$(mktemp)"; withdraw_out="$(mktemp)"
renew_pid=""; withdraw_pid=""
cleanup() {
 if [[ -n "$renew_pid" ]]; then wait "$renew_pid" 2>/dev/null || true; fi
 if [[ -n "$withdraw_pid" ]]; then wait "$withdraw_pid" 2>/dev/null || true; fi
 rm -f "$renew_out" "$withdraw_out"
}
trap cleanup EXIT

(
 PGAPPNAME=ujani-consent-race-renew "${PSQL[@]}" >"$renew_out" 2>&1 <<'SQL'
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id=:'tenant';
SELECT ujani_control.renew_device_lease(
 :'tenant','race-device','race-workload','race-lease',1,1,
 decode(repeat('3b',16),'hex'),decode(repeat('3c',32),'hex'),decode(repeat('31',32),'hex'),
 clock_timestamp()+interval '4 minutes 30 seconds','00000000-0000-4000-8000-000000000302');
SELECT pg_catalog.pg_sleep(4);
COMMIT;
RESET ROLE;
SQL
) &
renew_pid=$!

renew_holding=0
for _ in $(seq 1 100); do
 state="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name='ujani-consent-race-renew' AND state='active' AND query LIKE '%pg_sleep%'")"
 if [[ "$state" == "1" ]] && grep -qx 't' "$renew_out"; then renew_holding=1; break; fi
 sleep 0.1
done
if [[ "$renew_holding" != "1" ]]; then
 echo "renewal worker did not successfully renew and hold its transaction" >&2
 cat "$renew_out" >&2
 exit 1
fi

(
 PGAPPNAME=ujani-consent-race-withdraw "${PSQL[@]}" >"$withdraw_out" 2>&1 <<'SQL'
BEGIN;
SET LOCAL ujani.tenant_id=:'tenant';
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES (:'tenant','race-device',2,'withdrawn','race-owner',decode(repeat('3d',32),'hex'));
COMMIT;
SQL
) &
withdraw_pid=$!

withdraw_waiting=0
for _ in $(seq 1 100); do
 waiting="$("${PSQL[@]}" -c "SELECT count(*) FROM pg_catalog.pg_stat_activity AS waiting WHERE waiting.application_name='ujani-consent-race-withdraw' AND waiting.state='active' AND waiting.wait_event_type='Lock' AND EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity AS blocker WHERE blocker.pid=ANY(pg_catalog.pg_blocking_pids(waiting.pid)) AND blocker.application_name='ujani-consent-race-renew')")"
 if [[ "$waiting" == "1" ]]; then withdraw_waiting=1; break; fi
 sleep 0.1
done

set +e
wait "$renew_pid"; renew_status=$?; renew_pid=""
wait "$withdraw_pid"; withdraw_status=$?; withdraw_pid=""
set -e
if [[ "$renew_status" -ne 0 || "$withdraw_status" -ne 0 || "$withdraw_waiting" != "1" ]]; then
 echo "renewal/withdrawal race did not complete through the expected lock ordering" >&2
 cat "$renew_out" "$withdraw_out" >&2
 exit 1
fi
if ! grep -qx 't' "$renew_out"; then echo "renewal should complete before the waiting withdrawal commits" >&2; cat "$renew_out" >&2; exit 1; fi

state="$("${PSQL[@]}" -c "SELECT CASE WHEN d.owner_consent_state='withdrawn' AND d.consent_generation=2 AND l.state='revoked' AND (SELECT count(*) FROM ujani_control.audit_events a WHERE a.tenant_id=l.tenant_id AND a.object_ref=l.lease_id AND a.event_type IN ('device.lease.renewed','device.lease.revoked'))=2 THEN 'ok' ELSE 'bad' END FROM ujani_control.devices d JOIN ujani_control.leases l USING (tenant_id,device_id) WHERE d.tenant_id='$tenant' AND d.device_id='race-device' AND l.lease_id='race-lease'")"
if [[ "$state" != "ok" ]]; then
 echo "withdrawal did not revoke the renewed lease and preserve both audit events: $state" >&2
 "${PSQL[@]}" -c "SELECT owner_consent_state,consent_generation,l.state,l.revision FROM ujani_control.devices d JOIN ujani_control.leases l USING (tenant_id,device_id) WHERE d.tenant_id='$tenant' AND l.lease_id='race-lease'" >&2
 exit 1
fi
echo "Owner-consent withdrawal serialized against renewal and revoked the renewed lease."
