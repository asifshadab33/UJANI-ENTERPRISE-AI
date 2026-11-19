ALTER TABLE ujani_control.device_telemetry_samples
 ADD COLUMN IF NOT EXISTS consent_generation bigint;

DO $block$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_constraint
  WHERE conrelid = 'ujani_control.device_telemetry_samples'::regclass
    AND conname = 'device_telemetry_samples_consent_generation_safe'
 ) THEN
  ALTER TABLE ujani_control.device_telemetry_samples
   ADD CONSTRAINT device_telemetry_samples_consent_generation_safe
   CHECK (consent_generation IS NULL OR consent_generation BETWEEN 1 AND 9007199254740991);
 END IF;
END;
$block$;

-- Consent-bound, authenticated device telemetry v2 admission.
-- Apply after migrations 0001-0014 (requires the trust, owner-binding and
-- reservation-watermark columns introduced by 0008 and the consent trigger in 0013).
-- The hosting adapter verifies the exact signed raw body first. This function
-- then rechecks the active key and exact owner-consent generation under the
-- tenant/device locks and commits replay, telemetry, watermark and audit together.
-- It does not create leases or dispatch work.

CREATE OR REPLACE FUNCTION ujani_control.accept_authenticated_device_telemetry_v2(
 p_tenant_id text,
 p_device_id text,
 p_device_key_id text,
 p_device_key_generation bigint,
 p_consent_generation bigint,
 p_generation bigint,
 p_sequence bigint,
 p_reservation_revision bigint,
 p_request_id bytea,
 p_request_expires_at_unix_ms bigint,
 p_observed_at timestamptz,
 p_payload_digest bytea,
 p_cpu_available_millis integer,
 p_memory_available_mb bigint,
 p_thermal_state text,
 p_power_state text,
 p_participation_state text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_owner_subject_id text;
 v_previous_reservation_revision bigint;
 v_inserted_request_id bytea;
 v_updated_rows integer;
 v_now timestamptz;
 v_now_unix_ms bigint;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_id IS NULL OR p_device_key_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_generation IS NULL OR p_device_key_generation NOT BETWEEN 1 AND 9007199254740991
    OR p_consent_generation IS NULL OR p_consent_generation NOT BETWEEN 1 AND 9007199254740991
    OR p_generation IS NULL OR p_generation NOT BETWEEN 1 AND 9007199254740991
    OR p_sequence IS NULL OR p_sequence NOT BETWEEN 1 AND 9007199254740991
    OR p_reservation_revision IS NULL OR p_reservation_revision NOT BETWEEN 0 AND 9007199254740991
    OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
    OR p_request_expires_at_unix_ms IS NULL
    OR p_request_expires_at_unix_ms NOT BETWEEN 1 AND 9007199254740991
    OR p_observed_at IS NULL
    OR p_payload_digest IS NULL OR pg_catalog.octet_length(p_payload_digest) <> 32
    OR (p_cpu_available_millis IS NOT NULL AND p_cpu_available_millis NOT BETWEEN 0 AND 65535000)
    OR (p_memory_available_mb IS NOT NULL AND p_memory_available_mb NOT BETWEEN 0 AND 16777216)
    OR p_thermal_state IS NULL OR p_thermal_state NOT IN ('cool','warm','hot','critical','unknown')
    OR p_power_state IS NULL OR p_power_state NOT IN ('ac','battery','low_battery','unknown')
    OR p_participation_state IS NULL OR p_participation_state NOT IN ('idle','interactive','paused','disabled','unknown') THEN
  RETURN false;
 END IF;

 -- Match the audit/consent writer lock order: tenant first, then device, then
 -- active key, owner binding, owner subject and consent evidence. This prevents
 -- owner pause/re-consent, key rotation or revocation from interleaving between
 -- the authority check and the telemetry commit.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;

 v_now := pg_catalog.clock_timestamp();
 v_now_unix_ms := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) * 1000)::bigint;
 IF v_device.trust_state <> 'enrolled'
    OR v_device.owner_consent_state <> 'granted'
    OR v_device.admin_approval_state <> 'approved'
    OR v_device.active_key_id IS DISTINCT FROM p_device_key_id
    OR v_device.key_generation IS DISTINCT FROM p_device_key_generation
    OR v_device.consent_generation IS DISTINCT FROM p_consent_generation
    OR p_request_expires_at_unix_ms <= v_now_unix_ms
    OR p_request_expires_at_unix_ms > v_now_unix_ms + 30000
    OR p_observed_at < v_now - interval '5 minutes'
    OR p_observed_at > v_now + interval '60 seconds'
    OR (v_device.last_seen_at IS NOT NULL AND p_observed_at < v_device.last_seen_at)
    OR NOT (
      p_generation > v_device.telemetry_generation
      OR (p_generation = v_device.telemetry_generation AND p_sequence > v_device.telemetry_sequence)
    )
    OR p_reservation_revision > v_device.reservation_revision THEN
  RETURN false;
 END IF;

 SELECT pg_catalog.max(reservation_revision)
 INTO v_previous_reservation_revision
 FROM ujani_control.device_telemetry_samples
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;
 IF v_previous_reservation_revision IS NOT NULL
    AND p_reservation_revision < v_previous_reservation_revision THEN
  RETURN false;
 END IF;

 PERFORM 1 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND key_id = p_device_key_id
   AND generation = p_device_key_generation
   AND state = 'active'
   AND valid_from <= v_now
   AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND active IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 PERFORM 1 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id AND subject_id = v_owner_subject_id AND enabled IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 PERFORM 1 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND consent_generation = p_consent_generation
   AND state = 'granted'
   AND actor_ref = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- Recheck time after all authority locks. The signed request has a 30-second
 -- maximum lifetime; a lock wait must not make an expired request admissible.
 v_now := pg_catalog.clock_timestamp();
 v_now_unix_ms := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) * 1000)::bigint;
 IF p_request_expires_at_unix_ms <= v_now_unix_ms
    OR p_observed_at < v_now - interval '5 minutes'
    OR p_observed_at > v_now + interval '60 seconds' THEN
  RETURN false;
 END IF;

 -- Claim replay only after all policy/order checks. Any subsequent exception
 -- aborts this statement transaction, including the replay claim and watermark.
 INSERT INTO ujani_control.request_replays
  (tenant_id, device_id, request_id, expires_at, operation_digest)
 VALUES
  (p_tenant_id, p_device_id, p_request_id,
   v_now + interval '10 minutes', p_payload_digest)
 ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING
 RETURNING request_id INTO v_inserted_request_id;
 IF v_inserted_request_id IS NULL THEN RETURN false; END IF;

 UPDATE ujani_control.devices
 SET telemetry_generation = p_generation,
     telemetry_sequence = p_sequence,
     last_seen_at = p_observed_at,
     updated_at = pg_catalog.clock_timestamp()
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND trust_state = 'enrolled'
   AND owner_consent_state = 'granted'
   AND admin_approval_state = 'approved'
   AND active_key_id = p_device_key_id
   AND key_generation = p_device_key_generation
   AND consent_generation = p_consent_generation
   AND (last_seen_at IS NULL OR p_observed_at >= last_seen_at)
   AND (p_generation > telemetry_generation
        OR (p_generation = telemetry_generation AND p_sequence > telemetry_sequence))
   AND p_reservation_revision <= reservation_revision;
 GET DIAGNOSTICS v_updated_rows = ROW_COUNT;
 IF v_updated_rows <> 1 THEN
  RAISE EXCEPTION 'device telemetry authority or watermark changed during admission'
   USING ERRCODE = '40001';
 END IF;

 INSERT INTO ujani_control.device_telemetry_samples
  (tenant_id, device_id, generation, sequence, request_id, observed_at,
   payload_digest, reservation_revision, consent_generation, cpu_available_millis, memory_available_mb,
   thermal_state, power_state, participation_state)
 VALUES
  (p_tenant_id, p_device_id, p_generation, p_sequence, p_request_id, p_observed_at,
   p_payload_digest, p_reservation_revision, p_consent_generation, p_cpu_available_millis, p_memory_available_mb,
   p_thermal_state, p_power_state, p_participation_state);

 INSERT INTO ujani_control.audit_events
  (tenant_id, event_id, actor_ref, actor_role, event_type, outcome, object_ref)
 VALUES
  (p_tenant_id, pg_catalog.gen_random_uuid(), p_device_id, 'device',
   'device.telemetry.accepted', 'accepted', p_device_id);

 -- Audit append can be slow. Do not commit a sample whose request or observation
 -- expired while the durable receipt was being recorded.
 v_now := pg_catalog.clock_timestamp();
 v_now_unix_ms := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) * 1000)::bigint;
 IF p_request_expires_at_unix_ms <= v_now_unix_ms
    OR p_observed_at < v_now - interval '5 minutes'
    OR p_observed_at > v_now + interval '60 seconds' THEN
  RAISE EXCEPTION 'device telemetry request or sample expired during audit commit'
   USING ERRCODE = '40001';
 END IF;

 RETURN true;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.accept_authenticated_device_telemetry_v2(
 text,text,text,bigint,bigint,bigint,bigint,bigint,bytea,bigint,timestamptz,bytea,integer,bigint,text,text,text
) FROM PUBLIC;

DO $block$
DECLARE
 v_runtime_role_oid oid;
BEGIN
 SELECT oid INTO v_runtime_role_oid
 FROM pg_catalog.pg_roles
 WHERE rolname = 'ujani_runtime';
 IF v_runtime_role_oid IS NULL THEN
  RAISE EXCEPTION 'ujani_runtime must be provisioned before migration 0016'
   USING ERRCODE = '42704';
 END IF;
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles
  WHERE oid = v_runtime_role_oid AND (rolsuper IS TRUE OR rolbypassrls IS TRUE)
 ) THEN
  RAISE EXCEPTION 'ujani_runtime must not be superuser or BYPASSRLS'
   USING ERRCODE = '42501';
 END IF;
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_namespace
  WHERE nspname = 'ujani_control' AND nspowner = v_runtime_role_oid
 ) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'ujani_control' AND c.relowner = v_runtime_role_oid
 ) THEN
  RAISE EXCEPTION 'ujani_runtime must not own the control schema or its objects'
   USING ERRCODE = '42501';
 END IF;

 GRANT USAGE ON SCHEMA ujani_control TO ujani_runtime;
 GRANT SELECT ON ujani_control.devices,ujani_control.device_keys,
  ujani_control.device_owner_bindings,ujani_control.owner_consents,
  ujani_control.operator_subjects,ujani_control.device_telemetry_samples,
  ujani_control.request_replays,ujani_control.audit_events TO ujani_runtime;
 GRANT UPDATE (admission_lock_marker) ON ujani_control.device_keys,
  ujani_control.device_owner_bindings,ujani_control.owner_consents,
  ujani_control.operator_subjects TO ujani_runtime;
 GRANT UPDATE (telemetry_generation,telemetry_sequence,last_seen_at,updated_at)
  ON ujani_control.devices TO ujani_runtime;
 GRANT INSERT ON ujani_control.device_telemetry_samples,
  ujani_control.request_replays,ujani_control.audit_events TO ujani_runtime;
 GRANT USAGE,SELECT ON SEQUENCE ujani_control.audit_events_sequence_id_seq TO ujani_runtime;
 GRANT EXECUTE ON FUNCTION ujani_control.accept_authenticated_device_telemetry_v2(
  text,text,text,bigint,bigint,bigint,bigint,bigint,bytea,bigint,timestamptz,bytea,integer,bigint,text,text,text
 ) TO ujani_runtime;
END;
$block$;

COMMENT ON FUNCTION ujani_control.accept_authenticated_device_telemetry_v2(
 text,text,text,bigint,bigint,bigint,bigint,bigint,bytea,bigint,timestamptz,bytea,integer,bigint,text,text,text
) IS
 'SECURITY INVOKER authenticated telemetry v2 admission. The host verifies the exact signed body and passes the authenticated key/request claims. The function rechecks active key, owner binding, enabled owner, exact consent generation, organisation approval, replay, freshness, monotonic generation/sequence and reservation watermark under tenant/device locks, then commits the sample and audit receipt atomically. No raw body is stored and no workload is dispatched.';

COMMENT ON COLUMN ujani_control.device_telemetry_samples.consent_generation IS
 'Server-issued owner-consent generation captured in authenticated telemetry v2. NULL denotes a legacy sample admitted before consent-generation binding.';
