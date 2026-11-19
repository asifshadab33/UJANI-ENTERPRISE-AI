-- Run after migrations 0001-0014 and migration 0016_authenticated_device_telemetry_v2.sql.
-- Uses a dedicated tenant/device so these tests do not mutate the lease lifecycle fixtures.
-- Cryptographic signature verification is performed by the Rust service preflight;
-- this test proves the database's second, transactional authority/replay boundary.

SELECT pg_catalog.set_config('ujani.tenant_id','authenticated-telemetry-test',false);

INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('authenticated-telemetry-test','Authenticated Telemetry Test')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('authenticated-telemetry-test','telemetry-admin','administrator',true,'https://test.invalid','telemetry-admin'),
 ('authenticated-telemetry-test','telemetry-owner','operator',true,'https://test.invalid','telemetry-owner')
ON CONFLICT (tenant_id,subject_id) DO UPDATE SET enabled=true;

INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES
 ('authenticated-telemetry-test','telemetry-device','Telemetry Test Device','linux',
  'enrolled','unknown','approved','telemetry-key-v1',1,0,0,0,NULL,0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='telemetry-key-v1',key_generation=1,consent_generation=0,
 telemetry_generation=0,telemetry_sequence=0,last_seen_at=NULL,reservation_revision=0;

INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES
 ('authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  decode(repeat('31',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET
 generation=1,state='active',revoked_at=NULL;

INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES
 ('authenticated-telemetry-test','telemetry-device','telemetry-owner','telemetry-admin',1,true,
  decode(repeat('32',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id='telemetry-owner',bound_by_subject_id='telemetry-admin',
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('33',32),'hex');

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('authenticated-telemetry-test','telemetry-device',1,'granted','telemetry-owner',
  decode(repeat('34',32),'hex'))
ON CONFLICT (tenant_id,device_id,consent_generation) DO NOTHING;

-- Positive admission, replay, ordering, generation, freshness and watermark tests.
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='authenticated-telemetry-test';
DO $block$
DECLARE
 v_consent_generation bigint;
 v_key_generation bigint;
 v_expiry bigint;
 v_accepted boolean;
BEGIN
 SELECT consent_generation,key_generation
 INTO v_consent_generation,v_key_generation
 FROM ujani_control.devices
 WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device';
 IF v_consent_generation <> 1 OR v_key_generation <> 1 THEN
  RAISE EXCEPTION 'fixture did not establish the expected active consent/key generations';
 END IF;

 v_expiry := pg_catalog.floor(pg_catalog.date_part('epoch',pg_catalog.clock_timestamp())*1000)::bigint + 20000;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,1,0,
  decode(repeat('a1',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('a2',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'fresh telemetry with current dual consent should be accepted';
 END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,2,0,
  decode(repeat('a1',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('a3',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'replayed request ID was accepted';
 END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,1,0,
  decode(repeat('a4',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('a5',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'duplicate telemetry sequence was accepted';
 END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation+1,v_consent_generation,1,2,0,
  decode(repeat('a6',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('a7',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'wrong key generation was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation+1,1,2,0,
  decode(repeat('a8',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('a9',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'wrong consent generation was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','other-key',
  v_key_generation,v_consent_generation,1,2,0,
  decode(repeat('aa',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('ab',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'wrong active key ID was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,2,1,
  decode(repeat('ac',16),'hex'),v_expiry,pg_catalog.clock_timestamp(),
  decode(repeat('ad',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'future reservation watermark was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,2,0,
  decode(repeat('ae',16),'hex'),v_expiry,pg_catalog.clock_timestamp()-interval '6 minutes',
  decode(repeat('af',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'stale telemetry observation was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,2,0,
  decode(repeat('b0',16),'hex'),v_expiry,pg_catalog.clock_timestamp()+interval '2 minutes',
  decode(repeat('b1',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'future telemetry observation was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,2,0,
  decode(repeat('b2',16),'hex'),
  pg_catalog.floor(pg_catalog.date_part('epoch',pg_catalog.clock_timestamp())*1000)::bigint-1,
  pg_catalog.clock_timestamp(),decode(repeat('b3',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'expired signed request was accepted'; END IF;

 v_accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  v_key_generation,v_consent_generation,1,2,0,
  decode(repeat('b4',16),'hex'),
  pg_catalog.floor(pg_catalog.date_part('epoch',pg_catalog.clock_timestamp())*1000)::bigint+60000,
  pg_catalog.clock_timestamp(),decode(repeat('b5',32),'hex'),4000,8192,'cool','ac','idle');
 IF v_accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'overlong signed request was accepted'; END IF;
END;
$block$;
COMMIT;
RESET ROLE;

-- A real owner pause/re-consent advances the server-issued consent generation.
-- A report with the paused generation is rejected; the new grant requires generation 3.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('authenticated-telemetry-test','telemetry-device',2,'paused','telemetry-owner',
  decode(repeat('b6',32),'hex'));

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='authenticated-telemetry-test';
DO $block$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  1,2,1,2,0,decode(repeat('b7',16),'hex'),
  pg_catalog.floor(pg_catalog.date_part('epoch',pg_catalog.clock_timestamp())*1000)::bigint+20000,
  pg_catalog.clock_timestamp(),decode(repeat('b8',32),'hex'),4000,8192,'cool','ac','idle');
 IF accepted IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'owner pause did not block telemetry at the current consent generation';
 END IF;
END;
$block$;
COMMIT;
RESET ROLE;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('authenticated-telemetry-test','telemetry-device',3,'granted','telemetry-owner',
  decode(repeat('b9',32),'hex'));

UPDATE ujani_control.devices SET admin_approval_state='rejected'
WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device';
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='authenticated-telemetry-test';
DO $block$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_authenticated_device_telemetry_v2(
  'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
  1,3,1,2,0,decode(repeat('ba',16),'hex'),
  pg_catalog.floor(pg_catalog.date_part('epoch',pg_catalog.clock_timestamp())*1000)::bigint+20000,
  pg_catalog.clock_timestamp(),decode(repeat('bb',32),'hex'),4000,8192,'cool','ac','idle');
 IF accepted IS DISTINCT FROM false THEN RAISE EXCEPTION 'organisation denial did not block telemetry'; END IF;
END;
$block$;
COMMIT;
RESET ROLE;
UPDATE ujani_control.devices SET admin_approval_state='approved'
WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device';

-- Inject an audit failure after replay/sample/watermark writes. The function
-- must abort the whole statement transaction rather than leave partial telemetry.
CREATE OR REPLACE FUNCTION ujani_control.reject_test_telemetry_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
 IF NEW.event_type = 'device.telemetry.accepted' THEN
  RAISE EXCEPTION 'injected telemetry audit failure';
 END IF;
 RETURN NEW;
END;
$function$;
CREATE TRIGGER reject_test_telemetry_audit
 BEFORE INSERT ON ujani_control.audit_events
 FOR EACH ROW EXECUTE FUNCTION ujani_control.reject_test_telemetry_audit();

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='authenticated-telemetry-test';
DO $block$
DECLARE
 v_failed boolean := false;
BEGIN
 BEGIN
  PERFORM ujani_control.accept_authenticated_device_telemetry_v2(
   'authenticated-telemetry-test','telemetry-device','telemetry-key-v1',
   1,3,1,2,0,decode(repeat('bc',16),'hex'),
   pg_catalog.floor(pg_catalog.date_part('epoch',pg_catalog.clock_timestamp())*1000)::bigint+20000,
   pg_catalog.clock_timestamp(),decode(repeat('bd',32),'hex'),
   4000,8192,'cool','ac','idle');
 EXCEPTION WHEN OTHERS THEN
  v_failed := true;
 END;
 IF NOT v_failed THEN
  RAISE EXCEPTION 'injected audit failure did not abort telemetry admission';
 END IF;
END;
$block$;
COMMIT;
RESET ROLE;

DROP TRIGGER reject_test_telemetry_audit ON ujani_control.audit_events;
DROP FUNCTION ujani_control.reject_test_telemetry_audit();

DO $block$
DECLARE
 v_generation bigint;
 v_sequence bigint;
 v_samples integer;
 v_replays integer;
 v_audits integer;
BEGIN
 SELECT telemetry_generation,telemetry_sequence INTO v_generation,v_sequence
 FROM ujani_control.devices
 WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device';
 SELECT count(*) INTO v_samples FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device'
   AND consent_generation=1;
 SELECT count(*) INTO v_replays FROM ujani_control.request_replays
 WHERE tenant_id='authenticated-telemetry-test' AND device_id='telemetry-device'
   AND request_id=decode(repeat('bc',16),'hex');
 SELECT count(*) INTO v_audits FROM ujani_control.audit_events
 WHERE tenant_id='authenticated-telemetry-test'
   AND event_type='device.telemetry.accepted'
   AND object_ref='telemetry-device';
 IF v_generation <> 1 OR v_sequence <> 1 OR v_samples <> 1 OR v_replays <> 0 OR v_audits <> 1 THEN
  RAISE EXCEPTION 'audit rollback left partial telemetry: generation %, sequence %, samples %, replay %, audit %',
   v_generation,v_sequence,v_samples,v_replays,v_audits;
 END IF;
END;
$block$;

SELECT 'Authenticated telemetry v2 admission and rollback passed.' AS result;
