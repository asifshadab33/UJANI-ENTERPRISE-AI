-- Privacy-minimised monotonic telemetry persistence.
-- Apply after 0001_customer_hosted_control_plane.sql and 0002_task_contract_replay_storage.sql with the migration owner.
-- The authenticated service adapter MUST verify the signed device request and
-- bind ujani.tenant_id from authenticated identity before calling this function.
-- This SECURITY INVOKER function is an admission/transaction boundary, not a
-- cryptographic signature verifier.
ALTER TABLE ujani_control.devices
 ADD COLUMN IF NOT EXISTS telemetry_generation bigint NOT NULL DEFAULT 0 CHECK (telemetry_generation >= 0),
 ADD COLUMN IF NOT EXISTS telemetry_sequence bigint NOT NULL DEFAULT 0 CHECK (telemetry_sequence >= 0);

CREATE TABLE IF NOT EXISTS ujani_control.device_telemetry_samples (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 generation bigint NOT NULL CHECK (generation > 0),
 sequence bigint NOT NULL CHECK (sequence > 0),
 request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
 observed_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
 cpu_available_millis integer CHECK (cpu_available_millis IS NULL OR cpu_available_millis BETWEEN 0 AND 65535000),
 memory_available_mb bigint CHECK (memory_available_mb IS NULL OR memory_available_mb BETWEEN 0 AND 16777216),
 thermal_state text NOT NULL CHECK (thermal_state IN ('cool','warm','hot','critical','unknown')),
 power_state text NOT NULL CHECK (power_state IN ('ac','battery','low_battery','unknown')),
 participation_state text NOT NULL CHECK (participation_state IN ('idle','interactive','paused','disabled','unknown')),
 PRIMARY KEY (tenant_id, device_id, generation, sequence),
 UNIQUE (tenant_id, device_id, request_id),
 FOREIGN KEY (tenant_id, device_id) REFERENCES ujani_control.devices(tenant_id, device_id)
);
CREATE INDEX IF NOT EXISTS device_telemetry_recent_idx
 ON ujani_control.device_telemetry_samples (tenant_id, device_id, received_at DESC);

ALTER TABLE ujani_control.device_telemetry_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.device_telemetry_samples FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.device_telemetry_samples;
CREATE POLICY tenant_isolation ON ujani_control.device_telemetry_samples
 USING (tenant_id = current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = current_setting('ujani.tenant_id', true));

CREATE OR REPLACE FUNCTION ujani_control.accept_device_telemetry(
 p_tenant_id text,
 p_device_id text,
 p_generation bigint,
 p_sequence bigint,
 p_request_id bytea,
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
AS $$
DECLARE
 inserted_request_id bytea;
 updated_rows integer;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM current_setting('ujani.tenant_id', true)
    OR p_device_id IS NULL OR p_device_id = ''
    OR p_generation IS NULL OR p_generation <= 0
    OR p_sequence IS NULL OR p_sequence <= 0
    OR p_request_id IS NULL OR octet_length(p_request_id) <> 16
    OR p_payload_digest IS NULL OR octet_length(p_payload_digest) <> 32
    OR p_observed_at IS NULL
    OR p_observed_at < clock_timestamp() - interval '5 minutes'
    OR p_observed_at > clock_timestamp() + interval '60 seconds'
    OR (p_cpu_available_millis IS NOT NULL AND p_cpu_available_millis NOT BETWEEN 0 AND 65535000)
    OR (p_memory_available_mb IS NOT NULL AND p_memory_available_mb NOT BETWEEN 0 AND 16777216)
    OR p_thermal_state IS NULL OR p_thermal_state NOT IN ('cool','warm','hot','critical','unknown')
    OR p_power_state IS NULL OR p_power_state NOT IN ('ac','battery','low_battery','unknown')
    OR p_participation_state IS NULL OR p_participation_state NOT IN ('idle','interactive','paused','disabled','unknown') THEN
  RETURN false;
 END IF;

 INSERT INTO ujani_control.request_replays
  (tenant_id, device_id, request_id, expires_at, operation_digest)
 VALUES
  (p_tenant_id, p_device_id, p_request_id, clock_timestamp() + interval '10 minutes', p_payload_digest)
 ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING
 RETURNING request_id INTO inserted_request_id;
 IF inserted_request_id IS NULL THEN
  RETURN false;
 END IF;

 -- The device row update serializes concurrent samples. A strictly newer
 -- generation/sequence AND non-decreasing observation time are required.
 UPDATE ujani_control.devices
 SET telemetry_generation = p_generation,
     telemetry_sequence = p_sequence,
     last_seen_at = p_observed_at,
     updated_at = clock_timestamp()
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND trust_state = 'enrolled'
   AND owner_consent_state = 'granted'
   AND admin_approval_state = 'approved'
   AND (last_seen_at IS NULL OR p_observed_at >= last_seen_at)
   AND (p_generation > telemetry_generation
        OR (p_generation = telemetry_generation AND p_sequence > telemetry_sequence));
 GET DIAGNOSTICS updated_rows = ROW_COUNT;
 IF updated_rows <> 1 THEN
  DELETE FROM ujani_control.request_replays
   WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND request_id = p_request_id;
  RETURN false;
 END IF;

 INSERT INTO ujani_control.device_telemetry_samples
  (tenant_id, device_id, generation, sequence, request_id, observed_at,
   payload_digest, cpu_available_millis, memory_available_mb,
   thermal_state, power_state, participation_state)
 VALUES
  (p_tenant_id, p_device_id, p_generation, p_sequence, p_request_id, p_observed_at,
   p_payload_digest, p_cpu_available_millis, p_memory_available_mb,
   p_thermal_state, p_power_state, p_participation_state);
 RETURN true;
END;
$$;

COMMENT ON FUNCTION ujani_control.accept_device_telemetry(text,text,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text)
 IS 'SECURITY INVOKER monotonic telemetry admission. Caller must verify the signed device request and set tenant context from authenticated identity. Enforces fresh/non-decreasing timestamps, enrolled trust, both consent states, replay uniqueness and monotonic generation/sequence. Checkpoint and sample insert participate in the caller transaction.';
COMMENT ON TABLE ujani_control.device_telemetry_samples
 IS 'Tenant-scoped privacy-minimised device capacity and participation samples. Never store prompts, personal files, process command lines, local paths or raw model content.';
