-- Run after migrations 0001-0018 on PostgreSQL 16.
-- The database persists verified consent claims; Ed25519 verification and
-- trusted-key binding remain mandatory in the authenticated service adapter.
BEGIN;
SELECT pg_catalog.set_config('ujani.tenant_id','collective-consent-test',true);

INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('collective-consent-test','Collective Consent Test')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,admin_approval_state)
VALUES ('collective-consent-test','device-01','Consent Test Device','linux','pending','unknown','pending')
ON CONFLICT (tenant_id,device_id) DO NOTHING;

SET LOCAL ROLE ujani_runtime;

DO $test$
DECLARE
 tenant_result record;
 retry_result record;
 individual_result record;
 v_count bigint;
 v_current boolean;
 v_bad_digest boolean := false;
 v_bad_generation boolean := false;
 v_cross_tenant boolean := false;
 v_expired_tenant boolean := false;
 v_expired_individual boolean := false;
 v_wrong_policy_generation boolean := false;
 v_direct_select_denied boolean := false;
 v_direct_write_denied boolean := false;
 v_now timestamptz := clock_timestamp();
BEGIN
 -- The runtime role can execute only the audited routines, not read or mutate
 -- consent tables directly.
 BEGIN
  PERFORM 1 FROM ujani_control.collective_defence_tenant_consent;
 EXCEPTION WHEN insufficient_privilege THEN
  v_direct_select_denied := true;
 END;
 IF NOT v_direct_select_denied THEN
  RAISE EXCEPTION 'runtime role unexpectedly has direct consent-table read access';
 END IF;
 BEGIN
  INSERT INTO ujani_control.collective_defence_tenant_consent
   (tenant_id,enabled,generation,purpose,event_schema_version,retention_seconds,
    notice_version,notice_sha256,actor_key_id,issued_at,expires_at)
  VALUES ('collective-consent-test',false,99,'collective-defence.read-only.v1','1.0',
   0,'blocked',decode(repeat('51',32),'hex'),'blocked-key',v_now,v_now+interval '1 hour');
 EXCEPTION WHEN insufficient_privilege THEN
  v_direct_write_denied := true;
 END;
 IF NOT v_direct_write_denied THEN
  RAISE EXCEPTION 'runtime role unexpectedly has direct consent-table write access';
 END IF;

 -- No records means default-off, including for an otherwise valid device.
 IF ujani_control.collective_defence_consent_is_current(
   'collective-consent-test','user-01','device-01',v_now) THEN
  RAISE EXCEPTION 'missing consent unexpectedly authorized participation';
 END IF;

 SELECT * INTO tenant_result
 FROM ujani_control.record_collective_defence_tenant_consent(
  'collective-consent-test',true,NULL,'collective-defence.read-only.v1','1.0',
  86400,'notice-v1',decode(repeat('11',32),'hex'),'admin-key-1',
  v_now,v_now+interval '1 hour','tenant-enable-1',decode(repeat('21',32),'hex'));
 IF tenant_result.generation <> 1 OR tenant_result.sequence_id <> 1 THEN
  RAISE EXCEPTION 'initial tenant consent generation/audit sequence incorrect';
 END IF;

 SELECT * INTO retry_result
 FROM ujani_control.record_collective_defence_tenant_consent(
  'collective-consent-test',true,NULL,'collective-defence.read-only.v1','1.0',
  86400,'notice-v1',decode(repeat('11',32),'hex'),'admin-key-1',
  v_now,v_now+interval '1 hour','tenant-enable-1',decode(repeat('21',32),'hex'));
 IF retry_result.event_id <> tenant_result.event_id
    OR retry_result.sequence_id <> tenant_result.sequence_id THEN
  RAISE EXCEPTION 'idempotent tenant retry did not return the original audit event';
 END IF;

 BEGIN
  PERFORM * FROM ujani_control.record_collective_defence_tenant_consent(
   'collective-consent-test',true,NULL,'collective-defence.read-only.v1','1.0',
   86400,'notice-v1',decode(repeat('11',32),'hex'),'admin-key-1',
   v_now,v_now+interval '1 hour','tenant-enable-1',decode(repeat('22',32),'hex'));
 EXCEPTION WHEN unique_violation THEN
  v_bad_digest := true;
 END;
 IF NOT v_bad_digest THEN
  RAISE EXCEPTION 'idempotency key reuse with a different digest was accepted';
 END IF;

 SELECT * INTO individual_result
 FROM ujani_control.record_collective_defence_individual_consent(
  'collective-consent-test','user-01','device-01',true,1,NULL,
  'collective-defence.read-only.v1','notice-v1',decode(repeat('31',32),'hex'),
  'user-key-1',v_now,v_now+interval '1 hour','individual-enable-1',
  decode(repeat('41',32),'hex'));
 IF individual_result.generation <> 1 THEN
  RAISE EXCEPTION 'initial individual consent generation incorrect';
 END IF;
 IF NOT ujani_control.collective_defence_consent_is_current(
   'collective-consent-test','user-01','device-01',v_now) THEN
  RAISE EXCEPTION 'both current opt-ins did not authorize the exact principal/device';
 END IF;

 -- A stale expected generation cannot overwrite a newer decision.
 BEGIN
  PERFORM * FROM ujani_control.record_collective_defence_individual_consent(
   'collective-consent-test','user-01','device-01',false,1,NULL,
   'collective-defence.read-only.v1','notice-v1',decode(repeat('31',32),'hex'),
   'user-key-1',v_now,v_now+interval '1 hour','individual-stale-1',
   decode(repeat('42',32),'hex'));
 EXCEPTION WHEN serialization_failure THEN
  v_bad_generation := true;
 END;
 IF NOT v_bad_generation THEN
  RAISE EXCEPTION 'stale individual generation unexpectedly succeeded';
 END IF;

 -- Individual withdrawal increments its generation and immediately denies.
 SELECT * INTO individual_result
 FROM ujani_control.record_collective_defence_individual_consent(
  'collective-consent-test','user-01','device-01',false,1,1,
  'collective-defence.read-only.v1','notice-v1',decode(repeat('31',32),'hex'),
  'user-key-1',v_now,v_now+interval '1 hour','individual-withdraw-1',
  decode(repeat('43',32),'hex'));
 IF individual_result.generation <> 2 THEN
  RAISE EXCEPTION 'individual withdrawal did not advance generation';
 END IF;
 IF ujani_control.collective_defence_consent_is_current(
   'collective-consent-test','user-01','device-01',v_now) THEN
  RAISE EXCEPTION 'individual withdrawal did not revoke participation';
 END IF;

 -- Tenant disable advances its generation and invalidates every individual grant.
 SELECT * INTO tenant_result
 FROM ujani_control.record_collective_defence_tenant_consent(
  'collective-consent-test',false,1,'collective-defence.read-only.v1','1.0',
  0,'notice-v1',decode(repeat('11',32),'hex'),'admin-key-1',
  v_now,v_now+interval '1 hour','tenant-disable-1',decode(repeat('23',32),'hex'));
 IF tenant_result.generation <> 2 THEN
  RAISE EXCEPTION 'tenant disable did not advance generation';
 END IF;
 IF ujani_control.collective_defence_consent_is_current(
   'collective-consent-test','user-01','device-01',v_now) THEN
  RAISE EXCEPTION 'tenant disable did not revoke participation';
 END IF;

 -- Re-enabling the tenant does not revive the old individual consent.
 SELECT * INTO tenant_result
 FROM ujani_control.record_collective_defence_tenant_consent(
  'collective-consent-test',true,2,'collective-defence.read-only.v1','1.0',
  86400,'notice-v2',decode(repeat('12',32),'hex'),'admin-key-1',
  v_now,v_now+interval '1 hour','tenant-enable-2',decode(repeat('24',32),'hex'));
 IF tenant_result.generation <> 3 THEN
  RAISE EXCEPTION 'tenant re-enable did not advance generation';
 END IF;
 IF ujani_control.collective_defence_consent_is_current(
   'collective-consent-test','user-01','device-01',v_now) THEN
  RAISE EXCEPTION 'stale individual consent was revived by tenant re-enable';
 END IF;

 -- A fresh individual opt-in must bind to the new tenant generation.
 SELECT * INTO individual_result
 FROM ujani_control.record_collective_defence_individual_consent(
  'collective-consent-test','user-01','device-01',true,3,2,
  'collective-defence.read-only.v1','notice-v2',decode(repeat('32',32),'hex'),
  'user-key-1',v_now,v_now+interval '1 hour','individual-enable-2',
  decode(repeat('44',32),'hex'));
 IF individual_result.generation <> 3
    OR NOT ujani_control.collective_defence_consent_is_current(
      'collective-consent-test','user-01','device-01',v_now) THEN
  RAISE EXCEPTION 'fresh individual re-opt-in did not bind to current tenant generation';
 END IF;

 -- A different principal or device cannot borrow this consent record.
 IF ujani_control.collective_defence_consent_is_current(
     'collective-consent-test','other-user','device-01',v_now)
    OR ujani_control.collective_defence_consent_is_current(
     'collective-consent-test','user-01','other-device',v_now) THEN
  RAISE EXCEPTION 'consent was not bound to the exact principal/device tuple';
 END IF;

 -- A stale tenant policy generation cannot be used for a new individual grant.
 BEGIN
  PERFORM * FROM ujani_control.record_collective_defence_individual_consent(
   'collective-consent-test','user-01','device-01',true,2,3,
   'collective-defence.read-only.v1','notice-v2',decode(repeat('32',32),'hex'),
   'user-key-1',v_now,v_now+interval '1 hour','individual-old-policy',
   decode(repeat('45',32),'hex'));
 EXCEPTION WHEN insufficient_privilege THEN
  v_wrong_policy_generation := true;
 END;
 IF NOT v_wrong_policy_generation THEN
  RAISE EXCEPTION 'individual consent using an old tenant policy generation was accepted';
 END IF;

 -- Expired tenant and individual claims cannot replace current consent.
 BEGIN
  PERFORM * FROM ujani_control.record_collective_defence_tenant_consent(
   'collective-consent-test',true,3,'collective-defence.read-only.v1','1.0',
   86400,'notice-v3',decode(repeat('13',32),'hex'),'admin-key-1',
   v_now-interval '2 hours',v_now-interval '1 hour','tenant-expired',
   decode(repeat('26',32),'hex'));
 EXCEPTION WHEN invalid_parameter_value THEN
  v_expired_tenant := true;
 END;
 IF NOT v_expired_tenant THEN
  RAISE EXCEPTION 'expired tenant consent was accepted';
 END IF;

 BEGIN
  PERFORM * FROM ujani_control.record_collective_defence_individual_consent(
   'collective-consent-test','user-01','device-01',true,3,3,
   'collective-defence.read-only.v1','notice-v2',decode(repeat('32',32),'hex'),
   'user-key-1',v_now-interval '2 hours',v_now-interval '1 hour','individual-expired',
   decode(repeat('46',32),'hex'));
 EXCEPTION WHEN invalid_parameter_value THEN
  v_expired_individual := true;
 END;
 IF NOT v_expired_individual THEN
  RAISE EXCEPTION 'expired individual consent was accepted';
 END IF;

 -- Caller-supplied tenant identity cannot cross the authenticated DB context.
 BEGIN
  PERFORM * FROM ujani_control.record_collective_defence_tenant_consent(
   'another-tenant',true,NULL,'collective-defence.read-only.v1','1.0',
   86400,'notice-v1',decode(repeat('11',32),'hex'),'admin-key-1',
   v_now,v_now+interval '1 hour','cross-tenant',decode(repeat('25',32),'hex'));
 EXCEPTION WHEN insufficient_privilege THEN
  v_cross_tenant := true;
 END;
 IF NOT v_cross_tenant THEN
  RAISE EXCEPTION 'cross-tenant consent write was accepted';
 END IF;


END;
$test$;
RESET ROLE;

DO $audit$
BEGIN
 IF (SELECT count(*) FROM ujani_control.collective_defence_consent_audit
     WHERE tenant_id='collective-consent-test') <> 6 THEN
  RAISE EXCEPTION 'expected six committed consent audit events';
 END IF;

 IF EXISTS (
  SELECT 1
  FROM (
   SELECT a.*,
    lag(record_hash,1,decode(repeat('00',32),'hex'))
      OVER (PARTITION BY tenant_id ORDER BY sequence_id) AS expected_previous,
    row_number() OVER (PARTITION BY tenant_id ORDER BY sequence_id) AS expected_sequence
   FROM ujani_control.collective_defence_consent_audit a
   WHERE tenant_id='collective-consent-test'
  ) chain
  WHERE sequence_id <> expected_sequence
     OR previous_hash <> expected_previous
     OR record_hash <> sha256(previous_hash || convert_to(jsonb_build_object(
       'schema_version',1,'tenant_id',tenant_id,'sequence_id',sequence_id,
       'event_id',event_id,'scope',scope,'principal_id',principal_id,
       'device_id',device_id,'action',action,
       'previous_generation',previous_generation,'next_generation',next_generation,
       'actor_key_id',actor_key_id,'idempotency_key',idempotency_key,
       'request_digest',encode(request_digest,'hex'),
       'committed_at_utc',to_char(committed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
     )::text,'UTF8'))
 ) THEN
  RAISE EXCEPTION 'consent audit chain sequence, predecessor or canonical digest is invalid';
 END IF;

 BEGIN
  UPDATE ujani_control.collective_defence_consent_audit
   SET action='tampered'
   WHERE tenant_id='collective-consent-test' AND sequence_id=1;
  RAISE EXCEPTION 'consent audit update unexpectedly succeeded';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM = 'consent audit update unexpectedly succeeded' THEN RAISE; END IF;
 END;
END;
$audit$;
ROLLBACK;
