-- Generation-bound authenticated telemetry admission.
--
-- The host verifies the exact raw body with DurableDeviceRegistry first, then
-- calls this SECURITY INVOKER function in the same PostgreSQL transaction used
-- for replay, watermark, sample and audit persistence. The database rechecks
-- the current device key, organisation approval and the currently bound owner's
-- explicit consent under the tenant-audit -> device-row lock order.
--
-- Schema v2 carries reservation_revision inside the signed body. It is never
-- inferred from a later database read: capacity evidence must identify the
-- reservation snapshot against which it was measured.

CREATE OR REPLACE FUNCTION ujani_control.accept_authenticated_device_telemetry_v3(
 p_tenant_id text,
 p_device_id text,
 p_device_key_id text,
 p_device_key_generation bigint,
 p_generation bigint,
 p_sequence bigint,
 p_reservation_revision bigint,
 p_request_id bytea,
 p_observed_at timestamptz,
 p_payload_digest bytea,
 p_cpu_available_millis integer,
 p_memory_available_mb bigint,
 p_thermal_state text,
 p_power_state text,
 p_participation_state text,
 p_event_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_owner_subject_id text;
 v_previous_reservation_revision bigint;
 v_now timestamptz;
 v_inserted_request_id bytea;
 v_updated_rows integer;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_id IS NULL OR p_device_key_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_generation IS NULL OR p_generation <= 0
    OR p_sequence IS NULL OR p_sequence <= 0
    OR p_reservation_revision IS NULL OR p_reservation_revision < 0
    OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
    OR p_observed_at IS NULL
    OR p_payload_digest IS NULL OR pg_catalog.octet_length(p_payload_digest) <> 32
    OR p_event_id IS NULL
    OR (p_cpu_available_millis IS NOT NULL AND p_cpu_available_millis NOT BETWEEN 0 AND 65535000)
    OR (p_memory_available_mb IS NOT NULL AND p_memory_available_mb NOT BETWEEN 0 AND 16777216)
    OR p_thermal_state IS NULL OR p_thermal_state NOT IN ('cool','warm','hot','critical','unknown')
    OR p_power_state IS NULL OR p_power_state NOT IN ('ac','battery','low_battery','unknown')
    OR p_participation_state IS NULL OR p_participation_state NOT IN ('idle','interactive','paused','disabled','unknown') THEN
  RETURN false;
 END IF;

 -- Every admission/consent/key-change/audit writer takes the tenant audit lock
 -- before the device row. Holding both locks prevents a consent withdrawal,
 -- owner replacement or key rotation from interleaving after these checks.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND
    OR v_device.trust_state <> 'enrolled'
    OR v_device.admin_approval_state <> 'approved'
    OR v_device.owner_consent_state <> 'granted'
    OR v_device.active_key_id IS DISTINCT FROM p_device_key_id
    OR v_device.key_generation IS DISTINCT FROM p_device_key_generation
    OR v_device.consent_generation <= 0
    OR p_reservation_revision > v_device.reservation_revision THEN
  RETURN false;
 END IF;

 -- Bind the signed key identifier and generation to the currently active
 -- database key record. The HTTP adapter still performs Ed25519 verification;
 -- this check prevents a stale or mismatched verified principal reaching SQL.
 PERFORM 1
 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND key_id = p_device_key_id
   AND generation = p_device_key_generation
   AND state = 'active'
   AND valid_from <= pg_catalog.clock_timestamp()
   AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN
  RETURN false;
 END IF;

 -- Organisation approval alone is insufficient. The active binding must
 -- resolve to an enabled owner, and the current consent generation must be a
 -- grant recorded by that exact owner.
 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND active IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN
  RETURN false;
 END IF;

 PERFORM 1
 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id
   AND subject_id = v_owner_subject_id
   AND enabled IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN
  RETURN false;
 END IF;

 PERFORM 1
 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND consent_generation = v_device.consent_generation
   AND state = 'granted'
   AND actor_ref = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND THEN
  RETURN false;
 END IF;

 -- Recheck freshness after acquiring the device lock. The watermark must be
 -- strictly newer and non-decreasing, and capacity evidence cannot claim a
 -- reservation snapshot older than the latest accepted sample or newer than
 -- the server's current reservation revision.
 v_now := pg_catalog.clock_timestamp();
 IF p_observed_at < v_now - interval '5 minutes'
    OR p_observed_at > v_now + interval '60 seconds'
    OR (v_device.last_seen_at IS NOT NULL AND p_observed_at < v_device.last_seen_at)
    OR NOT (
      p_generation > v_device.telemetry_generation
      OR (p_generation = v_device.telemetry_generation AND p_sequence > v_device.telemetry_sequence)
    ) THEN
  RETURN false;
 END IF;

 SELECT max(reservation_revision) INTO v_previous_reservation_revision
 FROM ujani_control.device_telemetry_samples
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;
 IF v_previous_reservation_revision IS NOT NULL
    AND p_reservation_revision < v_previous_reservation_revision THEN
  RETURN false;
 END IF;

 -- Claim replay only after all authority, freshness and ordering checks. There
 -- is no compensating DELETE privilege: every later failure raises and rolls
 -- back this claim, sample, watermark and audit as one SQL statement.
 INSERT INTO ujani_control.request_replays
  (tenant_id,device_id,request_id,expires_at,operation_digest)
 VALUES
  (p_tenant_id,p_device_id,p_request_id,v_now + interval '10 minutes',p_payload_digest)
 ON CONFLICT (tenant_id,device_id,request_id) DO NOTHING
 RETURNING request_id INTO v_inserted_request_id;
 IF v_inserted_request_id IS NULL THEN
  RETURN false;
 END IF;

 UPDATE ujani_control.devices
 SET telemetry_generation = p_generation,
     telemetry_sequence = p_sequence,
     last_seen_at = p_observed_at,
     updated_at = pg_catalog.clock_timestamp()
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;
 GET DIAGNOSTICS v_updated_rows = ROW_COUNT;
 IF v_updated_rows <> 1 THEN
  RAISE EXCEPTION 'authenticated telemetry device checkpoint update failed';
 END IF;

 INSERT INTO ujani_control.device_telemetry_samples
  (tenant_id,device_id,generation,sequence,request_id,observed_at,
   payload_digest,reservation_revision,cpu_available_millis,memory_available_mb,
   thermal_state,power_state,participation_state)
 VALUES
  (p_tenant_id,p_device_id,p_generation,p_sequence,p_request_id,p_observed_at,
   p_payload_digest,p_reservation_revision,p_cpu_available_millis,p_memory_available_mb,
   p_thermal_state,p_power_state,p_participation_state);

 -- Audit contains identifiers, sequence/watermark and a short digest prefix
 -- only; never persist raw telemetry, prompts, process data or file paths.
 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (p_tenant_id,p_event_id,p_device_id,'device','device.telemetry.accepted','accepted',
   'device=' || p_device_id
   || ';generation=' || p_generation::text
   || ';sequence=' || p_sequence::text
   || ';reservation_revision=' || p_reservation_revision::text
   || ';digest=' || pg_catalog.left(pg_catalog.encode(p_payload_digest,'hex'),8));

 RETURN true;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.accept_authenticated_device_telemetry_v3(
 text,text,text,bigint,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text,uuid
) FROM PUBLIC;

DO $grant$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ujani_runtime'
 ) THEN
  RAISE EXCEPTION 'ujani_runtime must be provisioned before migration 0016';
 END IF;
 EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.accept_authenticated_device_telemetry_v3(text,text,text,bigint,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text,uuid) TO ujani_runtime';
END;
$grant$;

COMMENT ON FUNCTION ujani_control.accept_authenticated_device_telemetry_v3(
 text,text,text,bigint,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text,uuid
) IS
 'SECURITY INVOKER authenticated telemetry v3 admission. The host verifies exact raw bytes and derives tenant/device/key/request identity from the enrolled-device signature. The function locks tenant audit then device, rechecks active key generation, organisation approval, active owner binding, enabled owner and current explicit consent, then enforces replay, monotonic sequence/time and reservation-watermark rules before atomically committing the sample and audit. No workload is admitted or dispatched.';
