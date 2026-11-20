-- Run after migrations 0001-0016 on PostgreSQL 16.
-- Signature verification remains the host adapter's responsibility. This
-- exercises the database half of exact-key, dual-consent telemetry admission.
BEGIN;
SELECT pg_catalog.set_config('ujani.tenant_id','telemetry-v3-test',true);

INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('telemetry-v3-test','Authenticated Telemetry V3 Test')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('telemetry-v3-test','telemetry-admin','administrator',true,'ci','telemetry-admin'),
 ('telemetry-v3-test','telemetry-owner','operator',true,'ci','telemetry-owner'),
 ('telemetry-v3-test','telemetry-owner-2','operator',true,'ci','telemetry-owner-2')
ON CONFLICT (tenant_id,subject_id) DO UPDATE
 SET role=EXCLUDED.role,enabled=true;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES
 ('telemetry-v3-test','telemetry-device','Telemetry V3 Device','linux','enrolled','unknown',
  'approved','telemetry-key',1,0,0,0,NULL,0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='telemetry-key',key_generation=1,consent_generation=0,
 telemetry_generation=0,telemetry_sequence=0,last_seen_at=NULL,reservation_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES
 ('telemetry-v3-test','telemetry-device','telemetry-key',decode(repeat('a1',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE
 SET state='active',revoked_at=NULL,valid_from=clock_timestamp();
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES
 ('telemetry-v3-test','telemetry-device','telemetry-owner','telemetry-admin',1,true,
  decode(repeat('a2',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,
 bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('a3',32),'hex');
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('telemetry-v3-test','telemetry-device',1,'granted','telemetry-owner',decode(repeat('a4',32),'hex'))
ON CONFLICT DO NOTHING;

SET LOCAL ROLE ujani_runtime;
DO $test$
DECLARE accepted boolean;
DECLARE sample_count integer;
DECLARE replay_count integer;
DECLARE current_generation bigint;
DECLARE current_sequence bigint;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,1,0,
  decode(repeat('01',16),'hex'),clock_timestamp(),decode(repeat('b1',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001601');
 IF accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'fresh authenticated telemetry with both consents should be accepted';
 END IF;

 -- Same request ID with a newer sequence is still a replay.
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,2,0,
  decode(repeat('01',16),'hex'),clock_timestamp(),decode(repeat('b2',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001602');
 IF accepted THEN RAISE EXCEPTION 'replayed request ID was accepted'; END IF;

 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,1,0,
  decode(repeat('02',16),'hex'),clock_timestamp(),decode(repeat('b3',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001603');
 IF accepted THEN RAISE EXCEPTION 'duplicate generation/sequence was accepted'; END IF;

 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,2,0,
  decode(repeat('03',16),'hex'),clock_timestamp()-interval '6 minutes',decode(repeat('b4',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001604');
 IF accepted THEN RAISE EXCEPTION 'stale observation was accepted'; END IF;

 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,2,0,
  decode(repeat('04',16),'hex'),clock_timestamp()+interval '2 minutes',decode(repeat('b5',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001605');
 IF accepted THEN RAISE EXCEPTION 'future observation was accepted'; END IF;

 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,2,1,
  decode(repeat('05',16),'hex'),clock_timestamp(),decode(repeat('b6',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001606');
 IF accepted THEN RAISE EXCEPTION 'future reservation watermark was accepted'; END IF;

 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','other-key',1,1,2,0,
  decode(repeat('06',16),'hex'),clock_timestamp(),decode(repeat('b7',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001607');
 IF accepted THEN RAISE EXCEPTION 'mismatched active key identifier was accepted'; END IF;

 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',2,1,2,0,
  decode(repeat('07',16),'hex'),clock_timestamp(),decode(repeat('b8',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001608');
 IF accepted THEN RAISE EXCEPTION 'stale key generation was accepted'; END IF;

 SELECT count(*) INTO sample_count FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
 SELECT telemetry_generation,telemetry_sequence INTO current_generation,current_sequence
 FROM ujani_control.devices
 WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
 IF sample_count <> 1 OR replay_count <> 1 OR current_generation <> 1 OR current_sequence <> 1 THEN
  RAISE EXCEPTION 'rejected telemetry mutated state: samples %, replays %, watermark %/%',
   sample_count,replay_count,current_generation,current_sequence;
 END IF;
END;
$test$;
RESET ROLE;

-- A pause revokes the current grant. The old grant cannot admit telemetry.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('telemetry-v3-test','telemetry-device',2,'paused','telemetry-owner',decode(repeat('a5',32),'hex'));
SET LOCAL ROLE ujani_runtime;
DO $paused$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,2,0,
  decode(repeat('08',16),'hex'),clock_timestamp(),decode(repeat('b9',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001609');
 IF accepted THEN RAISE EXCEPTION 'paused owner consent did not block telemetry'; END IF;
END;
$paused$;
RESET ROLE;

-- A fresh explicit grant restores admission only for the current owner.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('telemetry-v3-test','telemetry-device',3,'granted','telemetry-owner',decode(repeat('a6',32),'hex'));
SET LOCAL ROLE ujani_runtime;
DO $regranted$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,2,0,
  decode(repeat('09',16),'hex'),clock_timestamp(),decode(repeat('ba',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001610');
 IF accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'fresh owner re-consent should restore telemetry admission';
 END IF;
END;
$regranted$;
RESET ROLE;

-- Replacing the owner invalidates the prior owner's grant even though the
-- device key remains enrolled. The new owner must explicitly opt in.
UPDATE ujani_control.device_owner_bindings
SET owner_subject_id='telemetry-owner-2',
    binding_revision=binding_revision+1,
    binding_digest=decode(repeat('a7',32),'hex')
WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
SET LOCAL ROLE ujani_runtime;
DO $replaced$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,3,0,
  decode(repeat('0a',16),'hex'),clock_timestamp(),decode(repeat('bb',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001611');
 IF accepted THEN RAISE EXCEPTION 'previous owner consent survived owner replacement'; END IF;
END;
$replaced$;
RESET ROLE;
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('telemetry-v3-test','telemetry-device',4,'granted','telemetry-owner-2',decode(repeat('a8',32),'hex'));
SET LOCAL ROLE ujani_runtime;
DO $new_owner$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,3,0,
  decode(repeat('0b',16),'hex'),clock_timestamp(),decode(repeat('bc',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001612');
 IF accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'new owner explicit consent should restore admission';
 END IF;
END;
$new_owner$;
RESET ROLE;

UPDATE ujani_control.devices
SET admin_approval_state='rejected'
WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
SET LOCAL ROLE ujani_runtime;
DO $admin_denial$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,4,0,
  decode(repeat('0c',16),'hex'),clock_timestamp(),decode(repeat('bd',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001613');
 IF accepted THEN RAISE EXCEPTION 'organisation denial did not block telemetry'; END IF;
END;
$admin_denial$;
RESET ROLE;
UPDATE ujani_control.devices
SET admin_approval_state='approved',trust_state='revoked'
WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
SET LOCAL ROLE ujani_runtime;
DO $revoked$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,4,0,
  decode(repeat('0d',16),'hex'),clock_timestamp(),decode(repeat('be',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001614');
 IF accepted THEN RAISE EXCEPTION 'revoked device was admitted'; END IF;
END;
$revoked$;
RESET ROLE;
UPDATE ujani_control.devices
SET trust_state='enrolled'
WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';

SET LOCAL ROLE ujani_runtime;
SAVEPOINT telemetry_v3_rollback;
DO $rollback$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v3(
  'telemetry-v3-test','telemetry-device','telemetry-key',1,1,4,0,
  decode(repeat('0e',16),'hex'),clock_timestamp(),decode(repeat('bf',32),'hex'),
  1200,4096,'cool','ac','idle','00000000-0000-4000-8000-000000001615');
 IF accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'fresh telemetry should be accepted before caller rollback';
 END IF;
END;
$rollback$;
ROLLBACK TO SAVEPOINT telemetry_v3_rollback;
DO $verify_rollback$
DECLARE sample_count integer;
DECLARE replay_count integer;
DECLARE audit_count integer;
DECLARE current_sequence bigint;
BEGIN
 SELECT count(*) INTO sample_count FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device'
   AND request_id=decode(repeat('0e',16),'hex');
 SELECT count(*) INTO audit_count FROM ujani_control.audit_events
 WHERE tenant_id='telemetry-v3-test'
   AND event_id='00000000-0000-4000-8000-000000001615';
 SELECT telemetry_sequence INTO current_sequence FROM ujani_control.devices
 WHERE tenant_id='telemetry-v3-test' AND device_id='telemetry-device';
 IF sample_count <> 3 OR replay_count <> 0 OR audit_count <> 0 OR current_sequence <> 3 THEN
  RAISE EXCEPTION 'caller rollback did not restore telemetry, replay, watermark and audit atomically';
 END IF;
END;
$verify_rollback$;
RESET ROLE;
ROLLBACK;
