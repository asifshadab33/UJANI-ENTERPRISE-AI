-- Preserve the tenant-audit -> device-row lock order for combined telemetry
-- and lease admission. Migration 0010 locked the device first, then called
-- admit_device_lease(), which takes the tenant audit advisory lock. A concurrent
-- owner-consent trigger takes that advisory lock before the device row, creating
-- a lock-order inversion and a possible deadlock under admission/withdrawal races.
--
-- This forward migration replaces the function without changing its contract.
-- The host must still authenticate the exact signed device/admin evidence before
-- invoking this SECURITY INVOKER function. No work is dispatched or executed.

CREATE OR REPLACE FUNCTION ujani_control.admit_device_lease_with_telemetry(
 p_tenant_id text,
 p_device_id text,
 p_device_key_generation bigint,
 p_consent_generation bigint,
 p_telemetry_generation bigint,
 p_telemetry_sequence bigint,
 p_reservation_revision bigint,
 p_telemetry_request_id bytea,
 p_observed_at timestamptz,
 p_payload_digest bytea,
 p_cpu_available_millis integer,
 p_memory_available_mb bigint,
 p_thermal_state text,
 p_power_state text,
 p_participation_state text,
 p_workload_id text,
 p_approval_id text,
 p_lease_id text,
 p_lease_request_id bytea,
 p_operation_digest bytea,
 p_manifest_digest bytea,
 p_cpu_millis integer,
 p_memory_mb bigint,
 p_capability_digest bytea,
 p_expires_at timestamptz,
 p_event_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_key_generation bigint;
 v_consent_generation bigint;
 v_telemetry_accepted boolean;
 v_lease_admitted boolean;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true)
    OR p_device_id IS NULL OR p_device_id = ''
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_consent_generation IS NULL OR p_consent_generation <= 0
    OR p_telemetry_request_id IS NULL
    OR p_lease_request_id IS NULL
    OR p_telemetry_request_id = p_lease_request_id THEN
  RETURN false;
 END IF;

 -- All admission, consent, key-change and audit paths acquire the tenant audit
 -- lock before the device row. This outer lock must precede the initial device
 -- SELECT because the nested lease admission takes the same lock reentrantly.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 -- Lock the device before comparing the generations covered by the signed
 -- request. Key rotation, revocation and owner-consent changes serialize on
 -- this same row, so none can interleave between this check and lease commit.
 SELECT key_generation, consent_generation
 INTO v_key_generation, v_consent_generation
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND trust_state = 'enrolled'
   AND owner_consent_state = 'granted'
   AND admin_approval_state = 'approved'
 FOR UPDATE;
 IF NOT FOUND
    OR v_key_generation IS DISTINCT FROM p_device_key_generation
    OR v_consent_generation IS DISTINCT FROM p_consent_generation THEN
  RETURN false;
 END IF;

 -- A nested exception block provides a PostgreSQL subtransaction. Expected
 -- policy denials roll back the telemetry replay claim, sample and watermarks
 -- if the following lease admission cannot commit. Unexpected storage/audit
 -- exceptions propagate and abort the caller's transaction.
 BEGIN
  v_telemetry_accepted := ujani_control.accept_device_telemetry_v2(
   p_tenant_id,
   p_device_id,
   p_telemetry_generation,
   p_telemetry_sequence,
   p_reservation_revision,
   p_telemetry_request_id,
   p_observed_at,
   p_payload_digest,
   p_cpu_available_millis,
   p_memory_available_mb,
   p_thermal_state,
   p_power_state,
   p_participation_state
  );
  IF v_telemetry_accepted IS DISTINCT FROM true THEN
   RAISE EXCEPTION USING ERRCODE = 'UJ001', MESSAGE = 'telemetry admission rejected';
  END IF;

  v_lease_admitted := ujani_control.admit_device_lease(
   p_tenant_id,
   p_device_id,
   p_workload_id,
   p_approval_id,
   p_lease_id,
   p_lease_request_id,
   p_operation_digest,
   p_manifest_digest,
   p_device_key_generation,
   p_consent_generation,
   p_cpu_millis,
   p_memory_mb,
   p_capability_digest,
   p_expires_at,
   p_event_id
  );
  IF v_lease_admitted IS DISTINCT FROM true THEN
   RAISE EXCEPTION USING ERRCODE = 'UJ001', MESSAGE = 'lease admission rejected';
  END IF;

  RETURN true;
 EXCEPTION WHEN SQLSTATE 'UJ001' THEN
  RETURN false;
 END;
END;
$function$;

COMMENT ON FUNCTION ujani_control.admit_device_lease_with_telemetry(
 text,text,bigint,bigint,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text,
 text,text,text,bytea,bytea,bytea,integer,bigint,bytea,timestamptz,uuid
) IS
 'SECURITY INVOKER atomic telemetry-plus-lease transaction. Acquires the tenant audit-chain advisory lock before the device row, preserving the common audit -> device -> child-row lock order against owner-consent/key changes. The adapter verifies signed device/admin evidence first. Rechecks key and consent generations, then commits telemetry replay/sample/watermarks, lease replay/reservation/revision and audit together. Expected policy denial rolls back the telemetry subtransaction; unexpected persistence/audit errors propagate. No work is dispatched or executed.';
