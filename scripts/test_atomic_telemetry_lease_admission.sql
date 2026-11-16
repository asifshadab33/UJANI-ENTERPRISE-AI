-- Run after migrations 0001-0010 and scripts/test_atomic_device_lease_admission.sql.
-- Cryptographic device/admin signature verification remains the trusted
-- adapter's responsibility. This verifies SQL transaction composition/rollback.
SELECT pg_catalog.set_config('ujani.tenant_id','admission-test',false);

INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation,
  telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision)
VALUES ('admission-test','admission-atomic-device','Atomic Admission Device','linux',
 'enrolled','unknown','approved','atomic-device-key',1,0,0,0,NULL,0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='atomic-device-key',key_generation=1,consent_generation=0,
 telemetry_generation=0,telemetry_sequence=0,last_seen_at=NULL,reservation_revision=0;

INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES ('admission-test','admission-atomic-device','atomic-device-key',
 decode(repeat('c1',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active';

INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES ('admission-test','admission-atomic-device','admission-owner','admission-admin',1,true,
 decode(repeat('c2',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,
 bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('c3',32),'hex'),bound_at=clock_timestamp();

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','admission-atomic-device',1,'granted','admission-owner',
 decode(repeat('c4',32),'hex'))
ON CONFLICT DO NOTHING;

DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease_with_telemetry(
  'admission-test','admission-atomic-device',
  1,1,                 -- signed device-key and owner-consent generations
  1,1,0,               -- telemetry generation, sequence and reservation watermark
  decode(repeat('d1',16),'hex'),clock_timestamp(),decode(repeat('d2',32),'hex'),
  4000,8192,'cool','ac','idle',
  'admission-workload','admission-approval','admission-atomic-lease',
  decode(repeat('d3',16),'hex'),decode(repeat('d4',32),'hex'),
  decode(repeat('44',32),'hex'),500,512,decode(repeat('d5',32),'hex'),
  clock_timestamp()+interval '4 minutes',
  '00000000-0000-4000-8000-000000000201');
 IF admitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'atomic telemetry-plus-lease admission was rejected';
 END IF;
END;
$block$;

DO $block$
DECLARE
 telemetry_generation bigint;
 telemetry_sequence bigint;
 reservation_revision bigint;
 telemetry_replays integer;
 lease_replays integer;
 sample_count integer;
 lease_count integer;
 approval_ref text;
 stored_request_digest bytea;
 audit_count integer;
BEGIN
 SELECT d.telemetry_generation,d.telemetry_sequence,d.reservation_revision
 INTO telemetry_generation,telemetry_sequence,reservation_revision
 FROM ujani_control.devices d
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 SELECT count(*) INTO telemetry_replays FROM ujani_control.request_replays
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
   AND request_id=decode(repeat('d1',16),'hex');
 SELECT count(*) INTO lease_replays FROM ujani_control.request_replays
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
   AND request_id=decode(repeat('d3',16),'hex');
 SELECT count(*) INTO sample_count FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
   AND generation=1 AND sequence=1;
 SELECT count(*) INTO lease_count FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-atomic-lease';
 SELECT l.approval_id,l.request_digest INTO approval_ref,stored_request_digest
 FROM ujani_control.leases l
 WHERE l.tenant_id='admission-test' AND l.lease_id='admission-atomic-lease';
 SELECT count(*) INTO audit_count FROM ujani_control.audit_events
 WHERE tenant_id='admission-test'
   AND event_id='00000000-0000-4000-8000-000000000201';
 IF telemetry_generation <> 1 OR telemetry_sequence <> 1 OR reservation_revision <> 1
    OR telemetry_replays <> 1 OR lease_replays <> 1
    OR sample_count <> 1 OR lease_count <> 1
    OR approval_ref IS DISTINCT FROM 'admission-approval'
    OR stored_request_digest IS DISTINCT FROM decode(repeat('d4',32),'hex')
    OR audit_count <> 1 THEN
  RAISE EXCEPTION 'atomic success was incomplete: telemetry %, sequence %, revision %, replay %, %, sample %, lease %, audit %',
   telemetry_generation,telemetry_sequence,reservation_revision,
   telemetry_replays,lease_replays,sample_count,lease_count,audit_count;
 END IF;
END;
$block$;

-- The operator evidence function must expose the durable request digest and
-- approval reference while still evaluating tenant RLS as the caller.
GRANT USAGE ON SCHEMA ujani_control TO ujani_runtime;
GRANT SELECT ON ujani_control.audit_events,ujani_control.leases,ujani_control.approvals TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.list_device_lease_audit_evidence(bigint,integer) TO ujani_runtime;
DO $block$
BEGIN
 IF (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname='ujani_runtime') IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'runtime role must not bypass row-level security';
 END IF;
END;
$block$;
SET ROLE ujani_runtime;
SELECT pg_catalog.set_config('ujani.tenant_id','admission-test',false);
DO $block$
DECLARE evidence_count integer;
BEGIN
 SELECT count(*) INTO evidence_count FROM ujani_control.list_device_lease_audit_evidence(NULL,10)
 WHERE lease_id='admission-atomic-lease'
   AND approval_id='admission-approval'
   AND request_digest=decode(repeat('d4',32),'hex');
 IF evidence_count <> 1 THEN
  RAISE EXCEPTION 'tenant-scoped audit evidence function omitted the admitted lease';
 END IF;
END;
$block$;
SELECT pg_catalog.set_config('ujani.tenant_id','another-tenant',false);
DO $block$
BEGIN
 IF EXISTS (SELECT 1 FROM ujani_control.list_device_lease_audit_evidence(NULL,10)
            WHERE lease_id='admission-atomic-lease') THEN
  RAISE EXCEPTION 'audit evidence function leaked a lease across tenant context';
 END IF;
END;
$block$;
RESET ROLE;
SELECT pg_catalog.set_config('ujani.tenant_id','admission-test',false);

-- Lease evidence fields are immutable even though lifecycle state/expiry/revision
-- remain mutable for future renewal/release workflows.
DO $block$
BEGIN
 BEGIN
  UPDATE ujani_control.leases
  SET request_digest=decode(repeat('aa',32),'hex')
  WHERE tenant_id='admission-test' AND lease_id='admission-atomic-lease';
  RAISE EXCEPTION 'lease request digest mutation was not rejected';
 EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
 END;
 BEGIN
  UPDATE ujani_control.leases
  SET approval_id='different-approval'
  WHERE tenant_id='admission-test' AND lease_id='admission-atomic-lease';
  RAISE EXCEPTION 'lease approval reference mutation was not rejected';
 EXCEPTION WHEN SQLSTATE '42501' THEN
  NULL;
 END;
END;
$block$;

-- A policy denial after telemetry validation must roll back the sample,
-- telemetry replay claim and watermarks rather than leave an unpaired sample.
DO $block$
DECLARE admitted boolean;
 telemetry_generation bigint;
 telemetry_sequence bigint;
 reservation_revision bigint;
BEGIN
 admitted := ujani_control.admit_device_lease_with_telemetry(
  'admission-test','admission-atomic-device',
  1,1,2,2,1,
  decode(repeat('e1',16),'hex'),clock_timestamp(),decode(repeat('e2',32),'hex'),
  4000,8192,'cool','ac','interactive',
  'admission-workload','admission-approval','admission-atomic-denied-lease',
  decode(repeat('e3',16),'hex'),decode(repeat('e4',32),'hex'),
  decode(repeat('44',32),'hex'),500,512,decode(repeat('e5',32),'hex'),
  clock_timestamp()+interval '4 minutes',
  '00000000-0000-4000-8000-000000000202');
 IF admitted IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'interactive telemetry must deny lease admission';
 END IF;
 SELECT d.telemetry_generation,d.telemetry_sequence,d.reservation_revision
 INTO telemetry_generation,telemetry_sequence,reservation_revision
 FROM ujani_control.devices d
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 IF telemetry_generation <> 1 OR telemetry_sequence <> 1 OR reservation_revision <> 1
    OR EXISTS (SELECT 1 FROM ujani_control.request_replays
               WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
                 AND request_id IN (decode(repeat('e1',16),'hex'),decode(repeat('e3',16),'hex')))
    OR EXISTS (SELECT 1 FROM ujani_control.device_telemetry_samples
               WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
                 AND generation=2 AND sequence=2)
    OR EXISTS (SELECT 1 FROM ujani_control.leases
               WHERE tenant_id='admission-test' AND lease_id='admission-atomic-denied-lease') THEN
  RAISE EXCEPTION 'expected denial left partial telemetry or lease state';
 END IF;
END;
$block$;

-- A late audit uniqueness failure must abort both the telemetry write and the
-- lease-side replay/reservation/revision writes.
DO $block$
DECLARE
 telemetry_generation bigint;
 telemetry_sequence bigint;
 reservation_revision bigint;
BEGIN
 BEGIN
  PERFORM ujani_control.admit_device_lease_with_telemetry(
   'admission-test','admission-atomic-device',
   1,1,2,2,1,
   decode(repeat('f1',16),'hex'),clock_timestamp(),decode(repeat('f2',32),'hex'),
   4000,8192,'cool','ac','idle',
   'admission-workload','admission-approval','admission-atomic-rollback-lease',
   decode(repeat('f3',16),'hex'),decode(repeat('f4',32),'hex'),
   decode(repeat('44',32),'hex'),500,512,decode(repeat('f5',32),'hex'),
   clock_timestamp()+interval '4 minutes',
   '00000000-0000-4000-8000-000000000201');
  RAISE EXCEPTION 'duplicate audit event did not abort atomic admission';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;

 SELECT d.telemetry_generation,d.telemetry_sequence,d.reservation_revision
 INTO telemetry_generation,telemetry_sequence,reservation_revision
 FROM ujani_control.devices d
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 IF telemetry_generation <> 1 OR telemetry_sequence <> 1 OR reservation_revision <> 1
    OR EXISTS (SELECT 1 FROM ujani_control.request_replays
               WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
                 AND request_id IN (decode(repeat('f1',16),'hex'),decode(repeat('f3',16),'hex')))
    OR EXISTS (SELECT 1 FROM ujani_control.device_telemetry_samples
               WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
                 AND generation=2 AND sequence=2)
    OR EXISTS (SELECT 1 FROM ujani_control.leases
               WHERE tenant_id='admission-test' AND lease_id='admission-atomic-rollback-lease') THEN
  RAISE EXCEPTION 'late audit failure left partial telemetry or lease state';
 END IF;
END;
$block$;

-- A request verified under an obsolete device key generation cannot update
-- telemetry or reserve a lease after key rotation has linearized in SQL.
DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease_with_telemetry(
  'admission-test','admission-atomic-device',
  2,1,2,2,1,
  decode(repeat('a1',16),'hex'),clock_timestamp(),decode(repeat('a2',32),'hex'),
  4000,8192,'cool','ac','idle',
  'admission-workload','admission-approval','admission-atomic-stale-key-lease',
  decode(repeat('a3',16),'hex'),decode(repeat('a4',32),'hex'),
  decode(repeat('44',32),'hex'),500,512,decode(repeat('a5',32),'hex'),
  clock_timestamp()+interval '4 minutes',
  '00000000-0000-4000-8000-000000000203');
 IF admitted IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'stale device key generation was accepted';
 END IF;
 IF EXISTS (SELECT 1 FROM ujani_control.request_replays
            WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
              AND request_id IN (decode(repeat('a1',16),'hex'),decode(repeat('a3',16),'hex'))) THEN
  RAISE EXCEPTION 'stale key generation consumed a replay identifier';
 END IF;
END;
$block$;


-- Owner consent withdrawal revokes outstanding leases and records one audit
-- event per lease in the same transaction as the monotonic consent revision.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','admission-atomic-device',2,'withdrawn','admission-owner',
 decode(repeat('b1',32),'hex'));

DO $block$
DECLARE
 device_consent_generation bigint;
 device_consent_state text;
 lease_state text;
 lease_revision bigint;
 revocation_events integer;
 evidence_rows integer;
BEGIN
 SELECT consent_generation,owner_consent_state
 INTO device_consent_generation,device_consent_state
 FROM ujani_control.devices
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 SELECT state,revision INTO lease_state,lease_revision
 FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-atomic-lease';
 SELECT count(*) INTO revocation_events FROM ujani_control.audit_events
 WHERE tenant_id='admission-test'
   AND event_type='device.lease.revoked'
   AND outcome='owner_consent_withdrawn'
   AND object_ref='admission-atomic-lease';
 SELECT count(*) INTO evidence_rows
 FROM ujani_control.list_device_lease_audit_evidence(NULL,10)
 WHERE lease_id='admission-atomic-lease'
   AND event_type='device.lease.revoked'
   AND outcome='owner_consent_withdrawn';
 IF device_consent_generation <> 2 OR device_consent_state <> 'withdrawn'
    OR lease_state <> 'revoked' OR lease_revision <> 2
    OR revocation_events <> 1 OR evidence_rows <> 1
    OR EXISTS (SELECT 1 FROM ujani_control.leases
               WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
                 AND state IN ('reserved','active')) THEN
  RAISE EXCEPTION 'owner consent withdrawal did not atomically revoke outstanding leases';
 END IF;
END;
$block$;

DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease_with_telemetry(
  'admission-test','admission-atomic-device',
  1,2,2,2,2,
  decode(repeat('b2',16),'hex'),clock_timestamp(),decode(repeat('b3',32),'hex'),
  4000,8192,'cool','ac','idle',
  'admission-workload','admission-approval','admission-after-withdrawal-lease',
  decode(repeat('b4',16),'hex'),decode(repeat('b5',32),'hex'),
  decode(repeat('44',32),'hex'),500,512,decode(repeat('b6',32),'hex'),
  clock_timestamp()+interval '4 minutes',
  '00000000-0000-4000-8000-000000000204');
 IF admitted IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'withdrawn owner consent must block new lease admission';
 END IF;
 IF EXISTS (SELECT 1 FROM ujani_control.request_replays
            WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
              AND request_id IN (decode(repeat('b2',16),'hex'),decode(repeat('b4',16),'hex'))) THEN
  RAISE EXCEPTION 'withdrawn owner consent consumed telemetry or lease replay identifiers';
 END IF;
END;
$block$;
 
-- A fresh grant permits a new reservation; pausing that consent must revoke
-- the reservation, and a later grant must not silently reactivate the old lease.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','admission-atomic-device',3,'granted','admission-owner',
 decode(repeat('c1',32),'hex'));

DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease_with_telemetry(
  'admission-test','admission-atomic-device',
  1,3,2,2,1,
  decode(repeat('c2',16),'hex'),clock_timestamp(),decode(repeat('c3',32),'hex'),
  4000,8192,'cool','ac','idle',
  'admission-workload','admission-approval','admission-after-grant-lease',
  decode(repeat('c4',16),'hex'),decode(repeat('c5',32),'hex'),
  decode(repeat('44',32),'hex'),500,512,decode(repeat('c6',32),'hex'),
  clock_timestamp()+interval '4 minutes',
  '00000000-0000-4000-8000-000000000205');
 IF admitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'fresh owner consent grant did not permit a new lease';
 END IF;
END;
$block$;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','admission-atomic-device',4,'paused','admission-owner',
 decode(repeat('c7',32),'hex'));

DO $block$
DECLARE
 device_consent_generation bigint;
 device_consent_state text;
 lease_state text;
 lease_revision bigint;
 pause_events integer;
BEGIN
 SELECT consent_generation,owner_consent_state
 INTO device_consent_generation,device_consent_state
 FROM ujani_control.devices
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 SELECT state,revision INTO lease_state,lease_revision
 FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-after-grant-lease';
 SELECT count(*) INTO pause_events FROM ujani_control.audit_events
 WHERE tenant_id='admission-test'
   AND event_type='device.lease.revoked'
   AND outcome='owner_consent_paused'
   AND object_ref='admission-after-grant-lease';
 IF device_consent_generation <> 4 OR device_consent_state <> 'paused'
    OR lease_state <> 'revoked' OR lease_revision <> 3 OR pause_events <> 1 THEN
  RAISE EXCEPTION 'owner consent pause did not atomically revoke the active reservation';
 END IF;
END;
$block$;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES ('admission-test','admission-atomic-device',5,'granted','admission-owner',
 decode(repeat('c8',32),'hex'));

DO $block$
BEGIN
 IF NOT EXISTS (
   SELECT 1 FROM ujani_control.leases
   WHERE tenant_id='admission-test' AND lease_id='admission-after-grant-lease'
     AND state='revoked' AND revision=3
 ) OR EXISTS (
   SELECT 1 FROM ujani_control.leases
   WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
     AND state IN ('reserved','active')
 ) THEN
  RAISE EXCEPTION 'a later owner consent grant reactivated a revoked lease';
 END IF;
END;
$block$;

