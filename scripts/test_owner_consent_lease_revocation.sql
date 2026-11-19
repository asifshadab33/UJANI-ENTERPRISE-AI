-- Verify that owner consent withdrawal revokes existing leases atomically,
-- and that a later grant never silently reactivates revoked reservations.
-- Run after migrations 0001-0013 and the atomic telemetry-plus-lease admission tests.
SELECT pg_catalog.set_config('ujani.tenant_id','admission-test',false);

INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('admission-test','Admission Test')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('admission-test','admission-admin','administrator',true,'ci','admission-admin'),
 ('admission-test','admission-owner','operator',true,'ci','admission-owner')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET enabled=true;

INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES ('admission-test','admission-workload',decode(repeat('44',32),'hex'),'inference','approved','admission-admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET state='approved';

INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES ('admission-test','admission-approval','admission-workload','admission-admin',
 'approved',decode(repeat('44',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET
 decision='approved',expires_at=clock_timestamp()+interval '10 minutes';

INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES ('admission-test','consent-revocation-device','Consent Revocation Test Device','linux',
 'enrolled','unknown','approved','consent-revocation-key',1,0,1,1,clock_timestamp(),0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='consent-revocation-key',key_generation=1,consent_generation=0,
 telemetry_generation=1,telemetry_sequence=1,last_seen_at=clock_timestamp(),reservation_revision=0;

INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES ('admission-test','consent-revocation-device','consent-revocation-key',
 decode(repeat('b1',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';

INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES ('admission-test','consent-revocation-device','admission-owner','admission-admin',1,true,
 decode(repeat('b2',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('b3',32),'hex'),bound_at=clock_timestamp();

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','consent-revocation-device',1,'granted','admission-owner',decode(repeat('b4',32),'hex'))
ON CONFLICT DO NOTHING;

INSERT INTO ujani_control.device_telemetry_samples
 (tenant_id,device_id,generation,sequence,request_id,observed_at,payload_digest,reservation_revision,
  cpu_available_millis,memory_available_mb,thermal_state,power_state,participation_state)
VALUES ('admission-test','consent-revocation-device',1,1,decode(repeat('b5',16),'hex'),
 clock_timestamp(),decode(repeat('b6',32),'hex'),0,4000,8192,'cool','ac','idle')
ON CONFLICT DO NOTHING;

DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease(
  'admission-test','consent-revocation-device','admission-workload','admission-approval',
  'consent-revocation-lease',decode(repeat('b7',16),'hex'),decode(repeat('b8',32),'hex'),
  decode(repeat('44',32),'hex'),1,1,500,512,decode(repeat('b9',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000301');
 IF admitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'test lease admission failed before consent revocation';
 END IF;
END;
$block$;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','consent-revocation-device',2,'withdrawn','admission-owner',decode(repeat('ba',32),'hex'));

DO $block$
BEGIN
 IF (SELECT owner_consent_state FROM ujani_control.devices
     WHERE tenant_id='admission-test' AND device_id='consent-revocation-device') <> 'withdrawn' THEN
  RAISE EXCEPTION 'withdrawal state was not applied to the device';
 END IF;
 IF (SELECT consent_generation FROM ujani_control.devices
     WHERE tenant_id='admission-test' AND device_id='consent-revocation-device') <> 2 THEN
  RAISE EXCEPTION 'withdrawal generation did not advance';
 END IF;
 IF (SELECT state FROM ujani_control.leases
     WHERE tenant_id='admission-test' AND lease_id='consent-revocation-lease') <> 'revoked' THEN
  RAISE EXCEPTION 'withdrawal did not revoke the reserved lease';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM ujani_control.audit_events
     WHERE tenant_id='admission-test' AND event_type='device.lease.revoked'
       AND object_ref='consent-revocation-lease' AND outcome='owner_consent_withdrawn') THEN
  RAISE EXCEPTION 'lease revocation audit evidence is missing';
 END IF;
END;
$block$;

-- A subsequent grant creates a new consent generation but must not revive the
-- prior lease; only a fresh admission may reserve work.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','consent-revocation-device',3,'granted','admission-owner',decode(repeat('bb',32),'hex'));

DO $block$
BEGIN
 IF (SELECT owner_consent_state FROM ujani_control.devices
     WHERE tenant_id='admission-test' AND device_id='consent-revocation-device') <> 'granted' THEN
  RAISE EXCEPTION 'fresh grant was not applied';
 END IF;
 IF (SELECT state FROM ujani_control.leases
     WHERE tenant_id='admission-test' AND lease_id='consent-revocation-lease') <> 'revoked' THEN
  RAISE EXCEPTION 'fresh consent silently reactivated an old lease';
 END IF;
END;
$block$;
