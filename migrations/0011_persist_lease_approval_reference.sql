-- Persist the exact administrator approval reference on each new lease.
-- Legacy leases remain readable with NULL approval_id; all new admissions
-- through admit_device_lease write a tenant-scoped FK to the approval row.
ALTER TABLE ujani_control.leases
 ADD COLUMN IF NOT EXISTS approval_id text;

DO $block$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_constraint
  WHERE conname = 'leases_approval_id_fk'
    AND conrelid = 'ujani_control.leases'::regclass
 ) THEN
  ALTER TABLE ujani_control.leases
   ADD CONSTRAINT leases_approval_id_fk
   FOREIGN KEY (tenant_id, approval_id)
   REFERENCES ujani_control.approvals(tenant_id, approval_id);
 END IF;
END;
$block$;

ALTER TABLE ujani_control.leases
 DROP CONSTRAINT IF EXISTS leases_approval_id_format;
ALTER TABLE ujani_control.leases
 ADD CONSTRAINT leases_approval_id_format
 CHECK (approval_id IS NULL OR approval_id ~ '^[A-Za-z0-9._:-]{1,128}$');

CREATE INDEX IF NOT EXISTS leases_approval_id_idx
 ON ujani_control.leases (tenant_id, approval_id)
 WHERE approval_id IS NOT NULL;

CREATE OR REPLACE FUNCTION ujani_control.admit_device_lease(
 p_tenant_id text,
 p_device_id text,
 p_workload_id text,
 p_approval_id text,
 p_lease_id text,
 p_request_id bytea,
 p_operation_digest bytea,
 p_manifest_digest bytea,
 p_device_key_generation bigint,
 p_consent_generation bigint,
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
 v_device ujani_control.devices%ROWTYPE;
 v_sample ujani_control.device_telemetry_samples%ROWTYPE;
 v_reserved_cpu bigint;
 v_reserved_memory bigint;
 v_now timestamptz;
 v_revision bigint;
 v_inserted bytea;
 v_owner_subject_id text;
 v_approval_expires_at timestamptz;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_workload_id IS NULL OR p_workload_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_approval_id IS NULL OR p_approval_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_lease_id IS NULL OR p_lease_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
    OR p_operation_digest IS NULL OR pg_catalog.octet_length(p_operation_digest) <> 32
    OR p_manifest_digest IS NULL OR pg_catalog.octet_length(p_manifest_digest) <> 32
    OR p_capability_digest IS NULL OR pg_catalog.octet_length(p_capability_digest) <> 32
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_consent_generation IS NULL OR p_consent_generation <= 0
    OR p_cpu_millis IS NULL OR p_cpu_millis NOT BETWEEN 1 AND 65535000
    OR p_memory_mb IS NULL OR p_memory_mb NOT BETWEEN 1 AND 16777216
    OR p_expires_at IS NULL OR p_event_id IS NULL THEN
  RAISE EXCEPTION 'invalid device admission parameters' USING ERRCODE = '22023';
 END IF;

 -- Serialize tenant audit writers before taking the device row lock. Consent
 -- and owner-binding writers use the same audit-lock-first order.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 -- Serialize all admissions for this device. Consent changes, key rotation and
 -- revocation must lock this same device row before updating their state.
 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;

 v_now := pg_catalog.clock_timestamp();
 IF v_device.trust_state <> 'enrolled'
    OR v_device.owner_consent_state <> 'granted'
    OR v_device.admin_approval_state <> 'approved'
    OR v_device.active_key_id IS NULL
    OR v_device.key_generation <> p_device_key_generation
    OR v_device.consent_generation <> p_consent_generation
    OR v_device.reservation_revision >= 9007199254740991
    OR p_expires_at <= v_now
    OR p_expires_at > v_now + interval '5 minutes' THEN
  RETURN false;
 END IF;

 -- Confirm the currently active key generation is represented by an active key.
 PERFORM 1 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND key_id = v_device.active_key_id
   AND generation = p_device_key_generation AND state = 'active'
   AND valid_from <= v_now AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- The device must have an active, administrator-established owner binding.
 -- Read the binding without a row lock. Device-row serialization makes
 -- admission linearize before/after a binding writer; taking a binding-row
 -- lock here would deadlock with UPDATE, which locks that row before its trigger.
 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND active IS TRUE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id AND subject_id = v_owner_subject_id AND enabled IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- The latest consent event must be from that exact bound owner and agree with
 -- the device's monotonic consent revision.
 PERFORM 1 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND consent_generation = p_consent_generation AND state = 'granted'
   AND actor_ref = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- Workload and signed administrator approval are checked against trusted rows.
 PERFORM 1 FROM ujani_control.workloads
 WHERE tenant_id = p_tenant_id AND workload_id = p_workload_id
   AND state = 'approved' AND manifest_digest = p_manifest_digest
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT a.expires_at INTO v_approval_expires_at
 FROM ujani_control.approvals a
 JOIN ujani_control.operator_subjects s
   ON s.tenant_id = a.tenant_id
  AND s.subject_id = a.approver_subject_id
 WHERE a.tenant_id = p_tenant_id AND a.workload_id = p_workload_id
   AND a.approval_id = p_approval_id AND a.decision = 'approved'
   AND a.manifest_digest = p_manifest_digest AND a.expires_at > v_now
   AND s.enabled IS TRUE AND s.role = 'administrator'
 FOR SHARE OF a, s;
 IF NOT FOUND THEN RETURN false; END IF;

 -- Fresh capacity evidence only; never admit from missing, stale, hot,
 -- low-battery or interactive telemetry.
 SELECT * INTO v_sample
 FROM ujani_control.device_telemetry_samples
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 ORDER BY received_at DESC LIMIT 1;
 -- Re-sample time after all eligibility locks and telemetry have been read;
 -- a lock wait must not extend request, approval or telemetry freshness.
 v_now := pg_catalog.clock_timestamp();
 IF p_expires_at <= v_now OR v_approval_expires_at <= v_now THEN
  RETURN false;
 END IF;
 IF NOT FOUND
    OR v_sample.observed_at < v_now - interval '2 minutes'
    OR v_sample.received_at < v_now - interval '2 minutes'
    OR v_sample.reservation_revision IS NULL
    OR v_sample.reservation_revision > v_device.reservation_revision
    OR v_sample.generation <> v_device.telemetry_generation
    OR v_sample.sequence <> v_device.telemetry_sequence
    OR v_sample.cpu_available_millis IS NULL
    OR v_sample.memory_available_mb IS NULL
    OR v_sample.thermal_state NOT IN ('cool','warm')
    OR v_sample.power_state NOT IN ('ac','battery')
    OR v_sample.participation_state <> 'idle' THEN
  RETURN false;
 END IF;

 SELECT COALESCE(sum(requested_cpu_millis),0),
        COALESCE(sum(requested_memory_mb),0)
 INTO v_reserved_cpu, v_reserved_memory
 FROM ujani_control.leases
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND state IN ('reserved','active') AND expires_at > v_now
   AND revision > v_sample.reservation_revision;

 IF v_reserved_cpu + p_cpu_millis > v_sample.cpu_available_millis
    OR v_reserved_memory + p_memory_mb > v_sample.memory_available_mb THEN
  RETURN false;
 END IF;

 -- Nonce, lease, revision and audit receipt are one transaction. Any later
 -- exception/rollback removes every write, including this replay claim.
 INSERT INTO ujani_control.request_replays
  (tenant_id, device_id, request_id, expires_at, operation_digest)
 VALUES (p_tenant_id, p_device_id, p_request_id,
         v_now + interval '10 minutes', p_operation_digest)
 ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING
 RETURNING request_id INTO v_inserted;
 IF v_inserted IS NULL THEN RETURN false; END IF;

 v_revision := v_device.reservation_revision + 1;
 INSERT INTO ujani_control.leases
  (tenant_id, lease_id, device_id, workload_id, approval_id, manifest_digest,
   device_key_generation, state, expires_at, revision,
   requested_cpu_millis, requested_memory_mb, capability_digest,
   consent_generation, request_id)
 VALUES
  (p_tenant_id, p_lease_id, p_device_id, p_workload_id, p_approval_id, p_manifest_digest,
   p_device_key_generation, 'reserved', p_expires_at, v_revision,
   p_cpu_millis, p_memory_mb, p_capability_digest,
   p_consent_generation, p_request_id);

 UPDATE ujani_control.devices
 SET reservation_revision = v_revision, updated_at = v_now
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;

 INSERT INTO ujani_control.audit_events
  (tenant_id, event_id, actor_ref, actor_role, event_type, outcome, object_ref)
 VALUES
  (p_tenant_id, p_event_id, p_device_id, 'device',
   'device.lease.admitted', 'reserved', p_lease_id);

 -- Audit insertion may wait on tenant-scoped serialization. Abort the SQL
 -- statement (rolling back replay, lease and revision writes) if authorization
 -- or telemetry expires while the audit receipt is being recorded.
 v_now := pg_catalog.clock_timestamp();
 IF p_expires_at <= v_now OR v_approval_expires_at <= v_now
    OR v_sample.observed_at < v_now - interval '2 minutes'
    OR v_sample.received_at < v_now - interval '2 minutes' THEN
  RAISE EXCEPTION 'device admission authorization or telemetry expired while recording the audit receipt'
   USING ERRCODE = '40001';
 END IF;

 RETURN true;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.admit_device_lease(
 text,text,text,text,text,bytea,bytea,bytea,bigint,bigint,integer,bigint,bytea,timestamptz,uuid
) FROM PUBLIC;

COMMENT ON COLUMN ujani_control.leases.approval_id IS
 'Exact tenant-scoped administrator approval referenced by a newly admitted lease; NULL only for legacy leases predating migration 0011.';
COMMENT ON FUNCTION ujani_control.admit_device_lease(
 text,text,text,text,text,bytea,bytea,bytea,bigint,bigint,integer,bigint,bytea,timestamptz,uuid
) IS
 'Atomic post-authentication admission transaction. New lease rows persist the exact tenant-scoped approval_id as well as manifest, key/consent generations and request_id, allowing the audit event object_ref to resolve to the durable approval evidence. Caller verifies signatures first. This function does not dispatch or execute work.';
