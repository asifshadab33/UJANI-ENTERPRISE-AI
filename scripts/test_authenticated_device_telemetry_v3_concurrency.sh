#!/usr/bin/env bash
set -euo pipefail

: "${PSQL_BIN:?PSQL_BIN must point to the CI psql wrapper}"
: "${PGUSER:?PGUSER must be set}"
: "${PGDATABASE:?PGDATABASE must be set}"

psql_cmd() {
  "$PSQL_BIN" --username "$PGUSER" --dbname "$PGDATABASE" --set ON_ERROR_STOP=1 --file -
}

psql_cmd <<'SQL'
SELECT pg_catalog.set_config('ujani.tenant_id','telemetry-v3-concurrency',false);
INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('telemetry-v3-concurrency','Telemetry V3 Concurrency')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('telemetry-v3-concurrency','telemetry-admin','administrator',true,'ci','telemetry-admin'),
 ('telemetry-v3-concurrency','telemetry-owner','operator',true,'ci','telemetry-owner')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET role=EXCLUDED.role,enabled=true;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES
 ('telemetry-v3-concurrency','telemetry-device','Telemetry V3 Concurrency Device','linux',
  'enrolled','unknown','approved','telemetry-key',1,0,0,0,NULL,0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='telemetry-key',key_generation=1,consent_generation=0,
 telemetry_generation=0,telemetry_sequence=0,last_seen_at=NULL,reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES
 ('telemetry-v3-concurrency','telemetry-device','telemetry-key',decode(repeat('c1',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE
 SET state='active',revoked_at=NULL,valid_from=clock_timestamp();
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES
 ('telemetry-v3-concurrency','telemetry-device','telemetry-owner','telemetry-admin',1,true,
  decode(repeat('c2',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,
 bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('c3',32),'hex');
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('telemetry-v3-concurrency','telemetry-device',1,'granted','telemetry-owner',decode(repeat('c4',32),'hex'))
ON CONFLICT DO NOTHING;
SQL

# The first transaction holds the device/audit locks after accepting. The
# second submits the same watermark with a distinct request ID and must wait,
# then reject after observing the committed watermark.
psql_cmd <<'SQL' &
BEGIN;
SET LOCAL ROLE ujani_runtime;
SET LOCAL ujani.tenant_id = 'telemetry-v3-concurrency';
DO $first$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-concurrency','telemetry-device','telemetry-key',1,1,1,0,
  decode(repeat('d1',16),'hex'),clock_timestamp(),decode(repeat('d2',32),'hex'),
  1000,2048,'cool','ac','idle','00000000-0000-4000-8000-000000000401');
 IF accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'first concurrent telemetry admission should succeed';
 END IF;
 PERFORM pg_catalog.pg_sleep(1);
END;
$first$;
COMMIT;
SQL
first_pid=$!

sleep 0.2
psql_cmd <<'SQL'
BEGIN;
SET LOCAL ROLE ujani_runtime;
SET LOCAL ujani.tenant_id = 'telemetry-v3-concurrency';
DO $second$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-concurrency','telemetry-device','telemetry-key',1,1,1,0,
  decode(repeat('d3',16),'hex'),clock_timestamp(),decode(repeat('d4',32),'hex'),
  1000,2048,'cool','ac','idle','00000000-0000-4000-8000-000000000402');
 IF accepted THEN
  RAISE EXCEPTION 'concurrent duplicate watermark was accepted';
 END IF;
END;
$second$;
COMMIT;
SQL
wait "$first_pid"

psql_cmd <<'SQL'
BEGIN;
SET LOCAL ROLE ujani_runtime;
SET LOCAL ujani.tenant_id = 'telemetry-v3-concurrency';
DO $verify$
DECLARE sample_count integer;
DECLARE replay_count integer;
DECLARE audit_count integer;
DECLARE current_sequence bigint;
BEGIN
 SELECT count(*) INTO sample_count FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='telemetry-v3-concurrency' AND device_id='telemetry-device';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='telemetry-v3-concurrency' AND device_id='telemetry-device';
 SELECT count(*) INTO audit_count FROM ujani_control.audit_events
 WHERE tenant_id='telemetry-v3-concurrency'
   AND event_type='device.telemetry.accepted';
 SELECT telemetry_sequence INTO current_sequence FROM ujani_control.devices
 WHERE tenant_id='telemetry-v3-concurrency' AND device_id='telemetry-device';
 IF sample_count <> 1 OR replay_count <> 1 OR audit_count <> 1 OR current_sequence <> 1 THEN
  RAISE EXCEPTION 'concurrent telemetry admission was not serialized: samples %, replay %, audit %, sequence %',
   sample_count,replay_count,audit_count,current_sequence;
 END IF;
END;
$verify$;
COMMIT;
SQL
