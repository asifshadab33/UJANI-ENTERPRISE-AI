-- Run after migrations 0001-0019 on PostgreSQL 16.
-- Covers immediate lease revocation, dual-consent invalidation, capacity
-- watermark updates, no silent reactivation and transaction rollback.
BEGIN;
SELECT pg_catalog.set_config('ujani.tenant_id','device-authority-revocation-test',true);

INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('device-authority-revocation-test','Device Authority Revocation Test')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('device-authority-revocation-test','authority-admin','administrator',true,'ci','authority-admin'),
 ('device-authority-revocation-test','authority-owner','operator',true,'ci','authority-owner'),
 ('device-authority-revocation-test','authority-owner-2','operator',true,'ci','authority-owner-2'),
 ('device-authority-revocation-test','authority-admin-2','administrator',true,'ci','authority-admin-2')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET
 role=EXCLUDED.role,enabled=true;

INSERT INTO ujani_control.workloads
 (tenant_id,workload_id,manifest_digest,class,state,created_by)
VALUES
 ('device-authority-revocation-test','authority-workload',decode(repeat('a1',32),'hex'),
  'inference','approved','authority-admin')
ON CONFLICT (tenant_id,workload_id) DO UPDATE SET state='approved';

INSERT INTO ujani_control.approvals
 (tenant_id,approval_id,workload_id,approver_subject_id,decision,manifest_digest,expires_at)
VALUES
 ('device-authority-revocation-test','authority-approval','authority-workload',
  'authority-admin','approved',decode(repeat('a1',32),'hex'),clock_timestamp()+interval '10 minutes'),
 ('device-authority-revocation-test','authority-approval-admin2','authority-workload',
  'authority-admin-2','approved',decode(repeat('a1',32),'hex'),clock_timestamp()+interval '10 minutes'),
 ('device-authority-revocation-test','authority-approval-revocable','authority-workload',
  'authority-admin','approved',decode(repeat('a2',32),'hex'),clock_timestamp()+interval '10 minutes')
ON CONFLICT (tenant_id,approval_id) DO UPDATE SET
 decision='approved',expires_at=clock_timestamp()+interval '10 minutes';

INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES
 ('device-authority-revocation-test','trust-device','Trust Revocation Device','linux',
  'enrolled','unknown','approved','trust-key-v1',1,0,1,1,clock_timestamp(),2),
 ('device-authority-revocation-test','key-device','Key Rotation Device','linux',
  'enrolled','unknown','approved','key-key-v1',1,0,1,1,clock_timestamp(),1),
 ('device-authority-revocation-test','approval-device','Approval Revocation Device','linux',
  'enrolled','unknown','approved','approval-key-v1',1,0,1,1,clock_timestamp(),1),
 ('device-authority-revocation-test','binding-device','Owner Binding Device','linux',
  'enrolled','unknown','approved','binding-key-v1',1,0,1,1,clock_timestamp(),1),
 ('device-authority-revocation-test','rollback-device','Rollback Device','linux',
  'enrolled','unknown','approved','rollback-key-v1',1,0,1,1,clock_timestamp(),1),
 ('device-authority-revocation-test','legacy-device','Legacy Invalid Device','linux',
  'revoked','unknown','approved','legacy-key-v1',1,0,1,1,clock_timestamp(),1),
 ('device-authority-revocation-test','subject-device','Owner Subject Disable Device','linux',
  'enrolled','unknown','approved','subject-key-v1',1,0,1,1,clock_timestamp(),1),
 ('device-authority-revocation-test','approver-device','Approver Demotion Device','linux',
  'enrolled','unknown','approved','approver-key-v1',1,0,1,1,clock_timestamp(),1)
ON CONFLICT (tenant_id,device_id) DO NOTHING;

INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES
 ('device-authority-revocation-test','trust-device','trust-key-v1',decode(repeat('b1',32),'hex'),1,'active'),
 ('device-authority-revocation-test','key-device','key-key-v1',decode(repeat('b2',32),'hex'),1,'active'),
 ('device-authority-revocation-test','approval-device','approval-key-v1',decode(repeat('b3',32),'hex'),1,'active'),
 ('device-authority-revocation-test','binding-device','binding-key-v1',decode(repeat('b4',32),'hex'),1,'active'),
 ('device-authority-revocation-test','rollback-device','rollback-key-v1',decode(repeat('b5',32),'hex'),1,'active'),
 ('device-authority-revocation-test','legacy-device','legacy-key-v1',decode(repeat('b6',32),'hex'),1,'active'),
 ('device-authority-revocation-test','subject-device','subject-key-v1',decode(repeat('b7',32),'hex'),1,'active'),
 ('device-authority-revocation-test','approver-device','approver-key-v1',decode(repeat('b9',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO NOTHING;

INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES
 ('device-authority-revocation-test','trust-device','authority-owner','authority-admin',1,true,decode(repeat('c1',32),'hex')),
 ('device-authority-revocation-test','key-device','authority-owner','authority-admin',1,true,decode(repeat('c2',32),'hex')),
 ('device-authority-revocation-test','approval-device','authority-owner','authority-admin',1,true,decode(repeat('c3',32),'hex')),
 ('device-authority-revocation-test','binding-device','authority-owner','authority-admin',1,true,decode(repeat('c4',32),'hex')),
 ('device-authority-revocation-test','rollback-device','authority-owner','authority-admin',1,true,decode(repeat('c5',32),'hex')),
 ('device-authority-revocation-test','subject-device','authority-owner-2','authority-admin',1,true,decode(repeat('c6',32),'hex')),
 ('device-authority-revocation-test','approver-device','authority-owner','authority-admin',1,true,decode(repeat('c7',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO NOTHING;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('device-authority-revocation-test','trust-device',1,'granted','authority-owner',decode(repeat('d1',32),'hex')),
 ('device-authority-revocation-test','key-device',1,'granted','authority-owner',decode(repeat('d2',32),'hex')),
 ('device-authority-revocation-test','approval-device',1,'granted','authority-owner',decode(repeat('d3',32),'hex')),
 ('device-authority-revocation-test','binding-device',1,'granted','authority-owner',decode(repeat('d4',32),'hex')),
 ('device-authority-revocation-test','rollback-device',1,'granted','authority-owner',decode(repeat('d5',32),'hex')),
 ('device-authority-revocation-test','subject-device',1,'granted','authority-owner-2',decode(repeat('d6',32),'hex')),
 ('device-authority-revocation-test','approver-device',1,'granted','authority-owner',decode(repeat('d7',32),'hex'))
ON CONFLICT DO NOTHING;

INSERT INTO ujani_control.leases
 (tenant_id,lease_id,device_id,workload_id,approval_id,manifest_digest,
  device_key_generation,state,expires_at,revision,requested_cpu_millis,
  requested_memory_mb,capability_digest,consent_generation,request_id,request_digest)
VALUES
 ('device-authority-revocation-test','trust-lease-1','trust-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e1',32),'hex'),1,decode(repeat('f1',16),'hex'),decode(repeat('11',32),'hex')),
 ('device-authority-revocation-test','trust-lease-2','trust-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'active',clock_timestamp()+interval '4 minutes',2,500,512,
  decode(repeat('e2',32),'hex'),1,decode(repeat('f2',16),'hex'),decode(repeat('12',32),'hex')),
 ('device-authority-revocation-test','key-lease','key-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e3',32),'hex'),1,decode(repeat('f3',16),'hex'),decode(repeat('13',32),'hex')),
 ('device-authority-revocation-test','approval-lease','approval-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e4',32),'hex'),1,decode(repeat('f4',16),'hex'),decode(repeat('14',32),'hex')),
 ('device-authority-revocation-test','binding-lease','binding-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e5',32),'hex'),1,decode(repeat('f5',16),'hex'),decode(repeat('15',32),'hex')),
 ('device-authority-revocation-test','rollback-lease','rollback-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e6',32),'hex'),1,decode(repeat('f6',16),'hex'),decode(repeat('16',32),'hex')),
 ('device-authority-revocation-test','legacy-lease','legacy-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e7',32),'hex'),0,decode(repeat('f7',16),'hex'),decode(repeat('17',32),'hex')),
 ('device-authority-revocation-test','subject-lease','subject-device','authority-workload','authority-approval',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e8',32),'hex'),1,decode(repeat('f8',16),'hex'),decode(repeat('18',32),'hex')),
 ('device-authority-revocation-test','approver-lease','approver-device','authority-workload','authority-approval-admin2',
  decode(repeat('a1',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('e9',32),'hex'),1,decode(repeat('f9',16),'hex'),decode(repeat('19',32),'hex')),
 ('device-authority-revocation-test','approval-record-lease','approval-device','authority-workload','authority-approval-revocable',
  decode(repeat('a2',32),'hex'),1,'reserved',clock_timestamp()+interval '4 minutes',1,500,512,
  decode(repeat('ea',32),'hex'),1,decode(repeat('fa',16),'hex'),decode(repeat('1a',32),'hex'));

DO $privileges$
BEGIN
 IF pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','trust_state','UPDATE')
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','owner_consent_state','UPDATE')
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','admin_approval_state','UPDATE')
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','active_key_id','UPDATE')
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','key_generation','UPDATE') THEN
  RAISE EXCEPTION 'runtime role unexpectedly has direct device-authority mutation privileges';
 END IF;
END;
$privileges$;

-- Trust revocation invalidates the owner opt-in and all active reservations.
UPDATE ujani_control.devices
SET trust_state='revoked'
WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device';

DO $trust$
DECLARE v_revision bigint; v_owner_state text; v_live_count bigint; v_revoked_count bigint;
BEGIN
 SELECT reservation_revision,owner_consent_state
 INTO v_revision,v_owner_state
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device';
 SELECT count(*) INTO v_live_count FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device'
   AND state IN ('reserved','active');
 SELECT count(*) INTO v_revoked_count FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device'
   AND state='revoked';
 IF v_owner_state <> 'unknown' OR v_live_count <> 0 OR v_revoked_count <> 2 OR v_revision <> 4 THEN
  RAISE EXCEPTION 'trust revocation did not atomically invalidate consent, both leases and capacity watermark: owner %, live %, revoked %, revision %',
   v_owner_state,v_live_count,v_revoked_count,v_revision;
 END IF;
 IF (SELECT count(*) FROM ujani_control.audit_events
     WHERE tenant_id='device-authority-revocation-test'
       AND event_type='device.lease.revoked'
       AND outcome='device_trust_changed'
       AND object_ref IN ('trust-lease-1','trust-lease-2')) <> 2 THEN
  RAISE EXCEPTION 'trust revocation audit receipts are incomplete';
 END IF;
END;
$trust$;

-- Re-enrollment and a fresh owner grant must never revive the old leases.
UPDATE ujani_control.devices
SET trust_state='enrolled'
WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device';
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('device-authority-revocation-test','trust-device',2,'granted','authority-owner',decode(repeat('d8',32),'hex'));
DO $trust_reenroll$
BEGIN
 IF (SELECT owner_consent_state FROM ujani_control.devices
     WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device') <> 'granted'
    OR EXISTS (SELECT 1 FROM ujani_control.leases
      WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device'
        AND state IN ('reserved','active'))
    OR (SELECT count(*) FROM ujani_control.leases
      WHERE tenant_id='device-authority-revocation-test' AND device_id='trust-device'
        AND state='revoked') <> 2 THEN
  RAISE EXCEPTION 'fresh trust/owner re-consent silently reactivated an old reservation';
 END IF;
END;
$trust_reenroll$;

-- Key rotation changes the key generation, invalidates the old owner grant and
-- immediately releases every reservation tied to the previous key generation.
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES
 ('device-authority-revocation-test','key-device','key-key-v2',decode(repeat('b8',32),'hex'),2,'active');
UPDATE ujani_control.device_keys
SET state='retired'
WHERE tenant_id='device-authority-revocation-test' AND device_id='key-device'
  AND key_id='key-key-v1';
UPDATE ujani_control.devices
SET active_key_id='key-key-v2',key_generation=2
WHERE tenant_id='device-authority-revocation-test' AND device_id='key-device';

DO $key_rotation$
DECLARE v_owner_state text; v_revision bigint; v_lease_state text;
BEGIN
 SELECT owner_consent_state,reservation_revision
 INTO v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='key-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='key-lease';
 IF v_owner_state <> 'unknown' OR v_revision <> 2 OR v_lease_state <> 'revoked' THEN
  RAISE EXCEPTION 'key rotation did not invalidate owner consent and old lease: owner %, revision %, lease %',
   v_owner_state,v_revision,v_lease_state;
 END IF;
END;
$key_rotation$;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('device-authority-revocation-test','key-device',2,'granted','authority-owner',decode(repeat('d9',32),'hex'));
DO $key_reconsent$
BEGIN
 IF (SELECT state FROM ujani_control.leases
     WHERE tenant_id='device-authority-revocation-test' AND lease_id='key-lease') <> 'revoked' THEN
  RAISE EXCEPTION 'fresh post-rotation consent reactivated the old lease';
 END IF;
END;
$key_reconsent$;

-- Organisation-level device approval is independent of owner consent. Its
-- revocation releases leases but does not erase the still-valid owner decision.
UPDATE ujani_control.devices
SET admin_approval_state='revoked'
WHERE tenant_id='device-authority-revocation-test' AND device_id='approval-device';
DO $approval_revoke$
DECLARE v_owner_state text; v_revision bigint; v_lease_state text;
BEGIN
 SELECT owner_consent_state,reservation_revision
 INTO v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='approval-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='approval-lease';
 IF v_owner_state <> 'granted' OR v_revision <> 2 OR v_lease_state <> 'revoked' THEN
  RAISE EXCEPTION 'administrator denial did not revoke only the lease authority: owner %, revision %, lease %',
   v_owner_state,v_revision,v_lease_state;
 END IF;
END;
$approval_revoke$;
UPDATE ujani_control.devices
SET admin_approval_state='approved'
WHERE tenant_id='device-authority-revocation-test' AND device_id='approval-device';
DO $approval_regrant$
BEGIN
 IF (SELECT state FROM ujani_control.leases
     WHERE tenant_id='device-authority-revocation-test' AND lease_id='approval-lease') <> 'revoked' THEN
  RAISE EXCEPTION 'administrator re-approval silently reactivated an old lease';
 END IF;
END;
$approval_regrant$;

-- Rebinding a device to another owner invalidates the former owner's consent
-- and revokes its leases in the same transaction.
UPDATE ujani_control.device_owner_bindings
SET owner_subject_id='authority-owner-2',
    binding_revision=binding_revision+1,
    binding_digest=decode(repeat('c8',32),'hex')
WHERE tenant_id='device-authority-revocation-test' AND device_id='binding-device';
DO $binding_change$
DECLARE v_owner_state text; v_revision bigint; v_lease_state text;
BEGIN
 SELECT owner_consent_state,reservation_revision
 INTO v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='binding-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='binding-lease';
 IF v_owner_state <> 'unknown' OR v_revision <> 2 OR v_lease_state <> 'revoked' THEN
  RAISE EXCEPTION 'owner rebinding did not invalidate the old owner grant and lease: owner %, revision %, lease %',
   v_owner_state,v_revision,v_lease_state;
 END IF;
END;
$binding_change$;

-- Disabling an owner subject invalidates every active device-owner grant
-- and revokes its leases. Re-enabling the subject never restores old consent.
UPDATE ujani_control.operator_subjects
SET enabled=false
WHERE tenant_id='device-authority-revocation-test' AND subject_id='authority-owner-2';

DO $owner_subject_disable$
DECLARE v_owner_state text; v_revision bigint; v_lease_state text;
BEGIN
 SELECT owner_consent_state,reservation_revision
 INTO v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='subject-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='subject-lease';
 IF v_owner_state <> 'unknown' OR v_revision <> 2 OR v_lease_state <> 'revoked' THEN
  RAISE EXCEPTION 'disabling owner subject did not invalidate consent and revoke lease: owner %, revision %, lease %',
   v_owner_state,v_revision,v_lease_state;
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM ujani_control.audit_events
  WHERE tenant_id='device-authority-revocation-test'
    AND event_type='device.lease.revoked'
    AND outcome='owner_subject_disabled'
    AND object_ref='subject-lease'
 ) OR NOT EXISTS (
  SELECT 1 FROM ujani_control.audit_events
  WHERE tenant_id='device-authority-revocation-test'
    AND event_type='operator.subject.disabled'
    AND object_ref='subject=authority-owner-2'
 ) THEN
  RAISE EXCEPTION 'owner subject disablement audit evidence is incomplete';
 END IF;
END;
$owner_subject_disable$;

UPDATE ujani_control.operator_subjects
SET enabled=true
WHERE tenant_id='device-authority-revocation-test' AND subject_id='authority-owner-2';
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('device-authority-revocation-test','subject-device',2,'granted','authority-owner-2',decode(repeat('d7',32),'hex'));
DO $owner_subject_reenable$
BEGIN
 IF (SELECT owner_consent_state FROM ujani_control.devices
     WHERE tenant_id='device-authority-revocation-test' AND device_id='subject-device') <> 'granted'
    OR (SELECT state FROM ujani_control.leases
     WHERE tenant_id='device-authority-revocation-test' AND lease_id='subject-lease') <> 'revoked' THEN
  RAISE EXCEPTION 're-enabling owner subject or fresh consent reactivated an old lease';
 END IF;
END;
$owner_subject_reenable$;

-- Demoting an administrator invalidates leases backed by that approver
-- without erasing the independent device owner's consent.
UPDATE ujani_control.operator_subjects
SET role='operator'
WHERE tenant_id='device-authority-revocation-test' AND subject_id='authority-admin-2';

DO $approver_demotion$
DECLARE v_owner_state text; v_revision bigint; v_lease_state text;
BEGIN
 SELECT owner_consent_state,reservation_revision
 INTO v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='approver-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='approver-lease';
 IF v_owner_state <> 'granted' OR v_revision <> 2 OR v_lease_state <> 'revoked' THEN
  RAISE EXCEPTION 'administrator demotion did not revoke only approver-authorized lease: owner %, revision %, lease %',
   v_owner_state,v_revision,v_lease_state;
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM ujani_control.audit_events
  WHERE tenant_id='device-authority-revocation-test'
    AND event_type='device.lease.revoked'
    AND outcome='approver_role_changed'
    AND object_ref='approver-lease'
 ) OR NOT EXISTS (
  SELECT 1 FROM ujani_control.audit_events
  WHERE tenant_id='device-authority-revocation-test'
    AND event_type='operator.subject.role_changed'
    AND object_ref='subject=authority-admin-2'
 ) THEN
  RAISE EXCEPTION 'approver demotion audit evidence is incomplete';
 END IF;
END;
$approver_demotion$;

UPDATE ujani_control.operator_subjects
SET role='administrator'
WHERE tenant_id='device-authority-revocation-test' AND subject_id='authority-admin-2';
DO $approver_repromotion$
BEGIN
 IF (SELECT state FROM ujani_control.leases
     WHERE tenant_id='device-authority-revocation-test' AND lease_id='approver-lease') <> 'revoked' THEN
  RAISE EXCEPTION 'administrator re-promotion silently reactivated an old lease';
 END IF;
END;
$approver_repromotion$;

-- Revoking an approval invalidates all outstanding leases bound to it.
-- Re-approving later must not reactivate the old lease.
UPDATE ujani_control.approvals
SET decision='revoked'
WHERE tenant_id='device-authority-revocation-test'
  AND approval_id='authority-approval-revocable';

DO $approval_revocation$
DECLARE v_owner_state text; v_revision bigint; v_lease_state text;
BEGIN
 SELECT owner_consent_state,reservation_revision
 INTO v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='approval-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='approval-record-lease';
 IF v_owner_state <> 'granted' OR v_revision <> 3 OR v_lease_state <> 'revoked' THEN
  RAISE EXCEPTION 'approval revocation did not revoke lease independently of owner consent: owner %, revision %, lease %',
   v_owner_state,v_revision,v_lease_state;
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM ujani_control.audit_events
  WHERE tenant_id='device-authority-revocation-test'
    AND event_type='device.lease.revoked'
    AND outcome='approval_revoked'
    AND object_ref='approval-record-lease'
 ) THEN
  RAISE EXCEPTION 'approval revocation audit evidence is missing';
 END IF;
END;
$approval_revocation$;

UPDATE ujani_control.approvals
SET decision='approved'
WHERE tenant_id='device-authority-revocation-test'
  AND approval_id='authority-approval-revocable';
DO $approval_reapproval$
BEGIN
 IF (SELECT state FROM ujani_control.leases
     WHERE tenant_id='device-authority-revocation-test' AND lease_id='approval-record-lease') <> 'revoked' THEN
  RAISE EXCEPTION 're-approving an approval silently reactivated an old lease';
 END IF;
END;
$approval_reapproval$;

-- Legacy reconciliation is also fail-closed when a no-op authority update
-- reaches a device that has active leases but no current owner evidence.
UPDATE ujani_control.devices
SET trust_state=trust_state
WHERE tenant_id='device-authority-revocation-test' AND device_id='legacy-device';
DO $legacy$
DECLARE v_revision bigint; v_state text;
BEGIN
 SELECT reservation_revision INTO v_revision FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='legacy-device';
 SELECT state INTO v_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='legacy-lease';
 IF v_revision <> 2 OR v_state <> 'revoked' THEN
  RAISE EXCEPTION 'legacy invalid authority did not reconcile its reservation: revision %, lease %',
   v_revision,v_state;
 END IF;
END;
$legacy$;

-- An audit failure must roll back the authority update, lease state, audit
-- event and capacity revision together.
CREATE OR REPLACE FUNCTION ujani_control.test_fail_device_lease_revocation_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
 IF NEW.event_type='device.lease.revoked' AND NEW.object_ref='rollback-lease' THEN
  RAISE EXCEPTION 'injected lease revocation audit failure';
 END IF;
 RETURN NEW;
END;
$function$;
CREATE TRIGGER zz_test_fail_device_lease_revocation_audit
BEFORE INSERT ON ujani_control.audit_events
FOR EACH ROW EXECUTE FUNCTION ujani_control.test_fail_device_lease_revocation_audit();

DO $rollback$
DECLARE v_failed boolean := false; v_trust_state text; v_owner_state text;
DECLARE v_revision bigint; v_lease_state text;
BEGIN
 BEGIN
  UPDATE ujani_control.devices
  SET trust_state='revoked'
  WHERE tenant_id='device-authority-revocation-test' AND device_id='rollback-device';
 EXCEPTION WHEN OTHERS THEN
  v_failed := true;
 END;
 IF NOT v_failed THEN
  RAISE EXCEPTION 'injected audit failure did not abort authority revocation';
 END IF;
 SELECT trust_state,owner_consent_state,reservation_revision
 INTO v_trust_state,v_owner_state,v_revision
 FROM ujani_control.devices
 WHERE tenant_id='device-authority-revocation-test' AND device_id='rollback-device';
 SELECT state INTO v_lease_state FROM ujani_control.leases
 WHERE tenant_id='device-authority-revocation-test' AND lease_id='rollback-lease';
 IF v_trust_state <> 'enrolled' OR v_owner_state <> 'granted'
    OR v_revision <> 1 OR v_lease_state <> 'reserved' THEN
  RAISE EXCEPTION 'failed revocation did not roll back device, consent, lease and capacity state';
 END IF;
 IF EXISTS (SELECT 1 FROM ujani_control.audit_events
   WHERE tenant_id='device-authority-revocation-test'
     AND event_type='device.lease.revoked' AND object_ref='rollback-lease') THEN
  RAISE EXCEPTION 'failed revocation left an audit receipt behind';
 END IF;
END;
$rollback$;

DROP TRIGGER zz_test_fail_device_lease_revocation_audit ON ujani_control.audit_events;
DROP FUNCTION ujani_control.test_fail_device_lease_revocation_audit();

ROLLBACK;
