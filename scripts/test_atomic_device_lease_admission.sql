-- Run after migrations 0001-0008 on PostgreSQL 16.
-- This exercises the post-authentication transaction only. Cryptographic
-- verification remains the responsibility of the trusted HTTP adapter.
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('admission-test','Admission Test') ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES ('admission-test','admission-admin','administrator',true,'ci','admission-admin')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET enabled=true,role='administrator';
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('admission-test','admission-disabled-admin','administrator',false,'ci','admission-disabled-admin'),
 ('admission-test','admission-viewer','viewer',true,'ci','admission-viewer')
ON CONFLICT (tenant_id,subject_id) DO UPDATE
 SET role=EXCLUDED.role,enabled=EXCLUDED.enabled;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at)
VALUES ('admission-test','admission-device','Admission Device','linux','enrolled',
 'granted','approved','device-key-1',1,1,1,1,clock_timestamp())
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='granted',admin_approval_state='approved',
 active_key_id='device-key-1',key_generation=1,consent_generation=1,
 telemetry_generation=1,telemetry_sequence=1,last_seen_at=clock_timestamp(),
 reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES ('admission-test','admission-device','device-key-1',decode(repeat('11',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','admission-device',1,'granted','device-owner',decode(repeat('22',32),'hex'))
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.device_telemetry_samples
 (tenant_id,device_id,generation,sequence,request_id,observed_at,payload_digest,
  cpu_available_millis,memory_available_mb,thermal_state,power_state,participation_state)
VALUES ('admission-test','admission-device',1,1,decode(repeat('31',16),'hex'),
 clock_timestamp(),decode(repeat('33',32),'hex'),4000,8192,'cool','ac','idle')
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES ('admission-test','admission-workload',decode(repeat('44',32),'hex'),'inference','approved','admission-admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET
 manifest_digest=decode(repeat('44',32),'hex'),state='approved';
INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES ('admission-test','admission-approval','admission-workload','admission-admin',
 'approved',decode(repeat('44',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET
 decision='approved',expires_at=clock_timestamp()+interval '10 minutes';
INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES
 ('admission-test','admission-disabled-approval','admission-workload','admission-disabled-admin',
  'approved',decode(repeat('44',32),'hex'),clock_timestamp()+interval '10 minutes'),
 ('admission-test','admission-viewer-approval','admission-workload','admission-viewer',
  'approved',decode(repeat('44',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET
 decision='approved',expires_at=clock_timestamp()+interval '10 minutes';

GRANT USAGE ON SCHEMA ujani_control TO ujani_runtime;
GRANT SELECT ON ujani_control.devices,ujani_control.device_keys,
 ujani_control.owner_consents,ujani_control.workloads,ujani_control.approvals,
 ujani_control.operator_subjects,ujani_control.device_telemetry_samples,
 ujani_control.leases,ujani_control.request_replays,ujani_control.audit_events
 TO ujani_runtime;
GRANT UPDATE (reservation_revision, updated_at)
 ON ujani_control.devices TO ujani_runtime;
GRANT INSERT ON ujani_control.leases,ujani_control.request_replays,
 ujani_control.audit_events TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.admit_device_lease(
 text,text,text,text,text,bytea,bytea,bytea,bigint,bigint,integer,bigint,bytea,timestamptz,uuid
) TO ujani_runtime;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';
DO $$
DECLARE admitted boolean;
DECLARE lease_count integer;
DECLARE replay_count integer;
DECLARE audit_count integer;
DECLARE revision_value bigint;
BEGIN
 IF has_table_privilege(current_user,'ujani_control.devices','INSERT')
    OR has_table_privilege(current_user,'ujani_control.devices','DELETE')
    OR has_column_privilege(current_user,'ujani_control.devices','trust_state','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.devices','owner_consent_state','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.devices','admin_approval_state','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.devices','active_key_id','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.owner_consents','INSERT')
    OR has_table_privilege(current_user,'ujani_control.owner_consents','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.owner_consents','DELETE')
    OR has_table_privilege(current_user,'ujani_control.device_keys','INSERT')
    OR has_table_privilege(current_user,'ujani_control.device_keys','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.approvals','INSERT')
    OR has_table_privilege(current_user,'ujani_control.approvals','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.approvals','DELETE')
    OR has_table_privilege(current_user,'ujani_control.operator_subjects','UPDATE')
 THEN RAISE EXCEPTION 'runtime role can mutate device trust or consent state'; END IF;
 IF has_table_privilege(current_user,'ujani_control.leases','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.leases','DELETE')
    OR has_table_privilege(current_user,'ujani_control.request_replays','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.request_replays','DELETE')
    OR has_table_privilege(current_user,'ujani_control.audit_events','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.audit_events','DELETE')
 THEN RAISE EXCEPTION 'runtime role can rewrite lease, replay or audit history'; END IF;
 IF NOT has_column_privilege(current_user,'ujani_control.devices','reservation_revision','UPDATE')
    OR NOT has_column_privilege(current_user,'ujani_control.devices','updated_at','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.devices','trust_state','UPDATE')
 THEN RAISE EXCEPTION 'runtime role does not have only the required reservation update columns'; END IF;

 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-device','admission-workload','admission-approval',
  'admission-lease-1',decode(repeat('51',16),'hex'),decode(repeat('52',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,1000,1024,decode(repeat('53',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000081');
 IF admitted IS DISTINCT FROM true THEN RAISE EXCEPTION 'valid admission was not committed'; END IF;

 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-device','admission-workload','admission-approval',
  'admission-lease-replay',decode(repeat('51',16),'hex'),decode(repeat('52',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,1000,1024,decode(repeat('54',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000082');
 IF admitted THEN RAISE EXCEPTION 'replayed request was admitted'; END IF;

 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-device','admission-workload','admission-approval',
  'admission-lease-over-capacity',decode(repeat('55',16),'hex'),decode(repeat('56',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,3500,1024,decode(repeat('57',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000083');
 IF admitted THEN RAISE EXCEPTION 'over-capacity request was admitted'; END IF;

 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-device','admission-workload','admission-disabled-approval',
  'admission-lease-disabled-admin',decode(repeat('65',16),'hex'),decode(repeat('66',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,100,100,decode(repeat('67',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000085');
 IF admitted THEN RAISE EXCEPTION 'approval from a disabled administrator was accepted'; END IF;

 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-device','admission-workload','admission-viewer-approval',
  'admission-lease-viewer',decode(repeat('68',16),'hex'),decode(repeat('69',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,100,100,decode(repeat('6a',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000086');
 IF admitted THEN RAISE EXCEPTION 'approval from a non-administrator was accepted'; END IF;

 UPDATE ujani_control.devices SET owner_consent_state='paused'
 WHERE tenant_id='admission-test' AND device_id='admission-device';
 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-device','admission-workload','admission-approval',
  'admission-lease-optout',decode(repeat('58',16),'hex'),decode(repeat('59',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,100,100,decode(repeat('5a',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000084');
 IF admitted THEN RAISE EXCEPTION 'paused owner consent admitted work'; END IF;
 UPDATE ujani_control.devices SET owner_consent_state='granted'
 WHERE tenant_id='admission-test' AND device_id='admission-device';

 SELECT count(*) INTO lease_count FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND device_id='admission-device';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='admission-test' AND device_id='admission-device';
 SELECT count(*) INTO audit_count FROM ujani_control.audit_events
 WHERE tenant_id='admission-test' AND event_type='device.lease.admitted';
 SELECT reservation_revision INTO revision_value FROM ujani_control.devices
 WHERE tenant_id='admission-test' AND device_id='admission-device';
 IF lease_count <> 1 OR replay_count <> 1 OR audit_count <> 1 OR revision_value <> 1 THEN
  RAISE EXCEPTION 'admission writes were not atomic: leases %, replays %, audit %, revision %',
   lease_count,replay_count,audit_count,revision_value;
 END IF;

 -- A late audit failure must roll back the nonce, lease and revision as well.
 BEGIN
  PERFORM ujani_control.admit_device_lease(
   'admission-test','admission-device','admission-workload','admission-approval',
   'admission-lease-rollback',decode(repeat('61',16),'hex'),decode(repeat('62',32),'hex'),
   decode(repeat('44',32),'hex'),1,1,100,100,decode(repeat('63',32),'hex'),
   clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000081');
  RAISE EXCEPTION 'duplicate audit event id did not fail';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;
 SELECT count(*) INTO lease_count FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-lease-rollback';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='admission-test' AND request_id=decode(repeat('61',16),'hex');
 SELECT reservation_revision INTO revision_value FROM ujani_control.devices
 WHERE tenant_id='admission-test' AND device_id='admission-device';
 IF lease_count <> 0 OR replay_count <> 0 OR revision_value <> 1 THEN
  RAISE EXCEPTION 'late failure left partial admission state';
 END IF;
END $$;
ROLLBACK;
RESET ROLE;
