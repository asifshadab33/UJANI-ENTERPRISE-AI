-- Run after migrations 0001 and 0002 against a disposable PostgreSQL 16 database.
-- This exercises the SECURITY INVOKER admission function as the restricted runtime role.
GRANT SELECT, INSERT, UPDATE, DELETE ON ujani_control.devices,
 ujani_control.request_replays, ujani_control.device_telemetry_samples TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.accept_device_telemetry(text,text,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text) TO ujani_runtime;

INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('telemetry-test','Telemetry Test Tenant')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.devices
 (tenant_id, device_id, display_name, platform, trust_state, owner_consent_state, admin_approval_state)
VALUES
 ('telemetry-test','telemetry-device','Telemetry Device','linux','enrolled','granted','approved')
ON CONFLICT (tenant_id, device_id) DO UPDATE
 SET trust_state='enrolled', owner_consent_state='granted', admin_approval_state='approved',
     telemetry_generation=0, telemetry_sequence=0;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'telemetry-test';
DO $$
DECLARE accepted boolean;
DECLARE sample_count integer;
DECLARE current_generation bigint;
DECLARE current_sequence bigint;
BEGIN
 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,1,decode(repeat('01',16),'hex'),
  clock_timestamp(),decode(repeat('aa',32),'hex'),1500,4096,'cool','ac','idle');
 IF NOT accepted THEN RAISE EXCEPTION 'first fresh sample should be accepted'; END IF;

 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,1,decode(repeat('01',16),'hex'),
  clock_timestamp(),decode(repeat('aa',32),'hex'),1500,4096,'cool','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'replayed request id should be rejected'; END IF;

 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,1,decode(repeat('02',16),'hex'),
  clock_timestamp(),decode(repeat('bb',32),'hex'),1500,4096,'cool','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'duplicate generation/sequence should be rejected'; END IF;

 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,2,decode(repeat('03',16),'hex'),
  clock_timestamp(),decode(repeat('cc',32),'hex'),1200,3072,'warm','ac','idle');
 IF NOT accepted THEN RAISE EXCEPTION 'strictly newer sequence should be accepted'; END IF;

 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,3,decode(repeat('04',16),'hex'),
  clock_timestamp() - interval '6 minutes',decode(repeat('dd',32),'hex'),1200,3072,'warm','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'stale telemetry timestamp should be rejected'; END IF;

 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,3,decode(repeat('05',16),'hex'),
  clock_timestamp() + interval '2 minutes',decode(repeat('ee',32),'hex'),1200,3072,'warm','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'future telemetry timestamp should be rejected'; END IF;

 UPDATE ujani_control.devices SET owner_consent_state='paused'
 WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,3,decode(repeat('06',16),'hex'),
  clock_timestamp(),decode(repeat('ff',32),'hex'),1200,3072,'warm','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'owner opt-out should reject admission'; END IF;

 UPDATE ujani_control.devices SET owner_consent_state='granted', admin_approval_state='rejected'
 WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,3,decode(repeat('07',16),'hex'),
  clock_timestamp(),decode(repeat('11',32),'hex'),1200,3072,'warm','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'organization denial should reject admission'; END IF;

 UPDATE ujani_control.devices SET admin_approval_state='approved', trust_state='revoked'
 WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,3,decode(repeat('08',16),'hex'),
  clock_timestamp(),decode(repeat('22',32),'hex'),1200,3072,'warm','ac','idle');
 IF accepted THEN RAISE EXCEPTION 'revoked device should reject admission'; END IF;

 SELECT count(*) INTO sample_count FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 SELECT telemetry_generation, telemetry_sequence INTO current_generation, current_sequence
 FROM ujani_control.devices WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 IF sample_count <> 2 OR current_generation <> 1 OR current_sequence <> 2 THEN
  RAISE EXCEPTION 'unexpected accepted sample/checkpoint state: count %, generation %, sequence %',
   sample_count, current_generation, current_sequence;
 END IF;
END $$;

-- The admission operation participates in the caller's transaction. A caller
-- rollback must undo both the monotonic checkpoint and the sample insert.
SAVEPOINT telemetry_rollback_test;
DO $
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_device_telemetry(
  'telemetry-test','telemetry-device',1,3,decode(repeat('09',16),'hex'),
  clock_timestamp(),decode(repeat('33',32),'hex'),1000,2048,'cool','ac','idle');
 IF NOT accepted THEN RAISE EXCEPTION 'fresh telemetry sample should be accepted before rollback'; END IF;
END $;
ROLLBACK TO SAVEPOINT telemetry_rollback_test;
DO $
DECLARE sample_count integer;
DECLARE current_generation bigint;
DECLARE current_sequence bigint;
BEGIN
 SELECT count(*) INTO sample_count FROM ujani_control.device_telemetry_samples
 WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 SELECT telemetry_generation, telemetry_sequence INTO current_generation, current_sequence
 FROM ujani_control.devices WHERE tenant_id='telemetry-test' AND device_id='telemetry-device';
 IF sample_count <> 2 OR current_generation <> 1 OR current_sequence <> 2 THEN
  RAISE EXCEPTION 'caller rollback did not atomically restore telemetry state';
 END IF;
END $;

ROLLBACK;
RESET ROLE;
