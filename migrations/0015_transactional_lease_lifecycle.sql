-- Transactional PostgreSQL lease lifecycle operations.
--
-- The trusted host must authenticate the exact signed device request and derive
-- tenant/device identity before calling renew_device_lease or
-- release_device_lease. These SECURITY INVOKER functions recheck mutable SQL
-- authority and commit replay, lease state, reservation revision and audit in
-- the same transaction. They never dispatch or execute work.
--
-- Expiry is an idempotent per-tenant/per-device reconciliation operation. The
-- host must enumerate devices from authenticated tenant scope and call it with
-- a bounded batch size. It does not accept caller-supplied time or lease state.

CREATE OR REPLACE FUNCTION ujani_control.renew_device_lease(
 p_tenant_id text,
 p_device_id text,
 p_workload_id text,
 p_lease_id text,
 p_device_key_generation bigint,
 p_consent_generation bigint,
 p_request_id bytea,
 p_operation_digest bytea,
 p_manifest_digest bytea,
 p_new_expires_at timestamptz,
 p_event_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_lease ujani_control.leases%ROWTYPE;
 v_sample ujani_control.device_telemetry_samples%ROWTYPE;
 v_owner_subject_id text;
 v_approval_expires_at timestamptz;
 v_reserved_cpu bigint;
 v_reserved_memory bigint;
 v_now timestamptz;
 v_inserted bytea;
 v_sample_found boolean;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_workload_id IS NULL OR p_workload_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_lease_id IS NULL OR p_lease_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_consent_generation IS NULL OR p_consent_generation <= 0
    OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
    OR p_operation_digest IS NULL OR pg_catalog.octet_length(p_operation_digest) <> 32
    OR p_manifest_digest IS NULL OR pg_catalog.octet_length(p_manifest_digest) <> 32
    OR p_new_expires_at IS NULL OR p_event_id IS NULL THEN
  RAISE EXCEPTION 'invalid lease renewal parameters' USING ERRCODE = '22023';
 END IF;

 -- All lease lifecycle and consent paths take the tenant audit lock before the
 -- device row lock. This preserves the existing audit -> device -> child-row
 -- lock order and serializes renewal against owner-consent withdrawal.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- Read the immutable lease identity only after the device lock. The row is
 -- locked again after authority checks, following the admission lock order.
 SELECT * INTO v_lease
 FROM ujani_control.leases
 WHERE tenant_id = p_tenant_id AND lease_id = p_lease_id;
 IF NOT FOUND
    OR v_lease.device_id IS DISTINCT FROM p_device_id
    OR v_lease.workload_id IS DISTINCT FROM p_workload_id
    OR v_lease.manifest_digest IS DISTINCT FROM p_manifest_digest
    OR v_lease.device_key_generation <> p_device_key_generation
    OR v_lease.consent_generation <> p_consent_generation
    OR v_lease.state NOT IN ('reserved','active') THEN
  RETURN false;
 END IF;

 v_now := pg_catalog.clock_timestamp();
 IF v_device.trust_state <> 'enrolled'
    OR v_device.owner_consent_state <> 'granted'
    OR v_device.admin_approval_state <> 'approved'
    OR v_device.active_key_id IS NULL
    OR v_device.key_generation <> p_device_key_generation
    OR v_device.consent_generation <> p_consent_generation
    OR v_lease.expires_at <= v_now
    OR p_new_expires_at <= v_lease.expires_at
    OR p_new_expires_at > v_now + interval '5 minutes' THEN
  RETURN false;
 END IF;

 PERFORM 1 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND key_id = v_device.active_key_id
   AND generation = p_device_key_generation AND state = 'active'
   AND valid_from <= v_now AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND active IS TRUE;
 IF NOT FOUND THEN RETURN false; END IF;

 PERFORM 1 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id AND subject_id = v_owner_subject_id AND enabled IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 PERFORM 1 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND consent_generation = p_consent_generation
   AND state = 'granted' AND actor_ref = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 PERFORM 1 FROM ujani_control.workloads
 WHERE tenant_id = p_tenant_id AND workload_id = p_workload_id
   AND state = 'approved' AND manifest_digest = p_manifest_digest
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 SELECT a.expires_at INTO v_approval_expires_at
 FROM ujani_control.approvals a
 JOIN ujani_control.operator_subjects s
   ON s.tenant_id = a.tenant_id AND s.subject_id = a.approver_subject_id
 WHERE a.tenant_id = p_tenant_id
   AND a.approval_id = v_lease.approval_id
   AND a.workload_id = p_workload_id
   AND a.decision = 'approved'
   AND a.manifest_digest = p_manifest_digest
   AND a.expires_at > v_now
   AND s.enabled IS TRUE AND s.role = 'administrator'
 FOR SHARE OF a, s;
 IF NOT FOUND OR p_new_expires_at > v_approval_expires_at THEN
  RETURN false;
 END IF;

 -- Renewal authorizes continued participation, so it must not outlive the
 -- device's current safety evidence. The latest sample must match the device
 -- watermark, be fresh, and report safe thermal/power/participation state.
 SELECT * INTO v_sample
 FROM ujani_control.device_telemetry_samples
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 ORDER BY received_at DESC
 LIMIT 1;
 v_sample_found := FOUND;
 v_now := pg_catalog.clock_timestamp();
 IF NOT v_sample_found
    OR v_sample.observed_at < v_now - interval '2 minutes'
    OR v_sample.observed_at > v_now + interval '60 seconds'
    OR v_sample.received_at < v_now - interval '2 minutes'
    OR v_sample.reservation_revision IS NULL
    OR v_sample.reservation_revision > v_device.reservation_revision
    OR v_sample.generation <> v_device.telemetry_generation
    OR v_sample.sequence <> v_device.telemetry_sequence
    OR v_sample.cpu_available_millis IS NULL
    OR v_sample.memory_available_mb IS NULL
    OR v_sample.thermal_state NOT IN ('cool','warm')
    OR v_sample.power_state NOT IN ('ac','battery')
    OR v_sample.participation_state <> 'idle'
    OR v_lease.expires_at <= v_now
    OR v_approval_expires_at <= v_now
    OR p_new_expires_at <= v_now
    OR p_new_expires_at > v_now + interval '5 minutes' THEN
  RETURN false;
 END IF;

 -- A telemetry sample may predate one or more reservations. Count every
 -- still-active lease newer than the sample's reservation watermark, including
 -- the lease being renewed when that lease was not yet reflected in the sample.
 SELECT COALESCE(pg_catalog.sum(requested_cpu_millis), 0),
        COALESCE(pg_catalog.sum(requested_memory_mb), 0)
 INTO v_reserved_cpu, v_reserved_memory
 FROM ujani_control.leases
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND state IN ('reserved','active')
   AND expires_at > v_now
   AND revision > v_sample.reservation_revision;
 IF v_reserved_cpu > v_sample.cpu_available_millis
    OR v_reserved_memory > v_sample.memory_available_mb THEN
  RETURN false;
 END IF;

 -- Authority and telemetry reads are protected by the device row lock. Lock
 -- the target lease last, then recheck its expiry and the evidence deadline.
 SELECT * INTO v_lease
 FROM ujani_control.leases
 WHERE tenant_id = p_tenant_id AND lease_id = p_lease_id
 FOR UPDATE;
 v_now := pg_catalog.clock_timestamp();
 IF NOT FOUND OR v_lease.device_id IS DISTINCT FROM p_device_id
    OR v_lease.workload_id IS DISTINCT FROM p_workload_id
    OR v_lease.manifest_digest IS DISTINCT FROM p_manifest_digest
    OR v_lease.device_key_generation <> p_device_key_generation
    OR v_lease.consent_generation <> p_consent_generation
    OR v_lease.state NOT IN ('reserved','active')
    OR v_lease.expires_at <= v_now
    OR v_approval_expires_at <= v_now
    OR p_new_expires_at <= v_now
    OR p_new_expires_at > v_now + interval '5 minutes'
    OR p_new_expires_at <= v_lease.expires_at THEN
  RETURN false;
 END IF;

 -- Claim the authenticated request only after all policy checks. Any later
 -- failure rolls back the replay row, lease update and audit receipt together.
 INSERT INTO ujani_control.request_replays
  (tenant_id, device_id, request_id, expires_at, operation_digest)
 VALUES
  (p_tenant_id, p_device_id, p_request_id,
   v_now + interval '10 minutes', p_operation_digest)
 ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING
 RETURNING request_id INTO v_inserted;
 IF v_inserted IS NULL THEN RETURN false; END IF;

 -- Renewal does not change reserved CPU/RAM, so it deliberately does not
 -- advance devices.reservation_revision. That watermark represents capacity
 -- changes only; advancing it here would double-count a lease already reflected
 -- in a telemetry sample taken before the renewal.
 UPDATE ujani_control.leases
 SET expires_at = p_new_expires_at
 WHERE tenant_id = p_tenant_id AND lease_id = p_lease_id;

 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (p_tenant_id,p_event_id,p_device_id,'device',
   'device.lease.renewed','renewed',p_lease_id);

 v_now := pg_catalog.clock_timestamp();
 IF p_new_expires_at <= v_now
    OR v_approval_expires_at <= v_now
    OR v_sample.observed_at < v_now - interval '2 minutes'
    OR v_sample.received_at < v_now - interval '2 minutes' THEN
  RAISE EXCEPTION 'lease renewal authorization or telemetry expired while recording the audit receipt'
   USING ERRCODE = '40001';
 END IF;
 RETURN true;
END;
$function$;

CREATE OR REPLACE FUNCTION ujani_control.release_device_lease(
 p_tenant_id text,
 p_device_id text,
 p_workload_id text,
 p_lease_id text,
 p_device_key_generation bigint,
 p_request_id bytea,
 p_operation_digest bytea,
 p_manifest_digest bytea,
 p_event_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_lease ujani_control.leases%ROWTYPE;
 v_now timestamptz;
 v_inserted bytea;
 v_new_revision bigint;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_workload_id IS NULL OR p_workload_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_lease_id IS NULL OR p_lease_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
    OR p_operation_digest IS NULL OR pg_catalog.octet_length(p_operation_digest) <> 32
    OR p_manifest_digest IS NULL OR pg_catalog.octet_length(p_manifest_digest) <> 32
    OR p_event_id IS NULL THEN
  RAISE EXCEPTION 'invalid lease release parameters' USING ERRCODE = '22023';
 END IF;

 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- Releasing a reservation is permitted after owner opt-out; consent withdrawal
 -- already revokes outstanding leases, and release never grants new capacity.
 IF v_device.trust_state <> 'enrolled'
    OR v_device.active_key_id IS NULL
    OR v_device.key_generation <> p_device_key_generation
    OR v_device.reservation_revision >= 9007199254740991 THEN
  RETURN false;
 END IF;

 PERFORM 1 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND key_id = v_device.active_key_id
   AND generation = p_device_key_generation AND state = 'active'
   AND valid_from <= pg_catalog.clock_timestamp() AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 SELECT * INTO v_lease
 FROM ujani_control.leases
 WHERE tenant_id = p_tenant_id AND lease_id = p_lease_id
 FOR UPDATE;
 IF NOT FOUND
    OR v_lease.device_id IS DISTINCT FROM p_device_id
    OR v_lease.workload_id IS DISTINCT FROM p_workload_id
    OR v_lease.manifest_digest IS DISTINCT FROM p_manifest_digest
    OR v_lease.device_key_generation <> p_device_key_generation
    OR v_lease.state NOT IN ('reserved','active') THEN
  RETURN false;
 END IF;

 v_now := pg_catalog.clock_timestamp();
 IF v_lease.expires_at <= v_now THEN
  RETURN false;
 END IF;

 INSERT INTO ujani_control.request_replays
  (tenant_id, device_id, request_id, expires_at, operation_digest)
 VALUES
  (p_tenant_id, p_device_id, p_request_id,
   v_now + interval '10 minutes', p_operation_digest)
 ON CONFLICT (tenant_id, device_id, request_id) DO NOTHING
 RETURNING request_id INTO v_inserted;
 IF v_inserted IS NULL THEN RETURN false; END IF;

 v_new_revision := v_device.reservation_revision + 1;
 UPDATE ujani_control.leases
 SET state = 'released', revision = v_new_revision
 WHERE tenant_id = p_tenant_id AND lease_id = p_lease_id;

 UPDATE ujani_control.devices
 SET reservation_revision = v_new_revision,
     updated_at = v_now
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;

 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (p_tenant_id,p_event_id,p_device_id,'device',
   'device.lease.released','released',p_lease_id);

 RETURN true;
END;
$function$;

CREATE OR REPLACE FUNCTION ujani_control.expire_device_leases(
 p_tenant_id text,
 p_device_id text,
 p_limit integer DEFAULT 50
) RETURNS integer
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_now timestamptz;
 v_lease_ids text[];
 v_due_count integer;
 v_new_revision bigint;
 v_audit_count integer;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
  RAISE EXCEPTION 'invalid lease expiry reconciliation parameters' USING ERRCODE = '22023';
 END IF;

 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));

 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN RETURN 0; END IF;

 v_now := pg_catalog.clock_timestamp();
 SELECT COALESCE(
   pg_catalog.array_agg(due.lease_id ORDER BY due.expires_at, due.lease_id),
   ARRAY[]::text[]
 )
 INTO v_lease_ids
 FROM (
  SELECT lease_id, expires_at
  FROM ujani_control.leases
  WHERE tenant_id = p_tenant_id AND device_id = p_device_id
    AND state IN ('reserved','active') AND expires_at <= v_now
  ORDER BY expires_at, lease_id
  LIMIT p_limit
  FOR UPDATE
 ) AS due;

 v_due_count := COALESCE(pg_catalog.array_length(v_lease_ids, 1), 0);
 IF v_due_count = 0 THEN RETURN 0; END IF;
 IF v_device.reservation_revision > 9007199254740991 - v_due_count THEN
  RAISE EXCEPTION 'device reservation revision exhausted during lease expiry'
   USING ERRCODE = '22003';
 END IF;
 v_new_revision := v_device.reservation_revision + v_due_count;

 -- Assign one strictly increasing device reservation revision to each expired
 -- lease. The device row lock serializes this batch against admission, renewal,
 -- release and consent-driven revocation for the same device.
 WITH ordered AS (
  SELECT due.lease_id, due.ordinality::bigint AS ordinal
  FROM pg_catalog.unnest(v_lease_ids) WITH ORDINALITY AS due(lease_id, ordinality)
 ),
 expired AS (
  UPDATE ujani_control.leases AS lease
  SET state = 'expired',
      revision = v_device.reservation_revision + ordered.ordinal
  FROM ordered
  WHERE lease.tenant_id = p_tenant_id
    AND lease.device_id = p_device_id
    AND lease.lease_id = ordered.lease_id
    AND lease.state IN ('reserved','active')
    AND lease.expires_at <= v_now
  RETURNING lease.lease_id
 )
 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 SELECT p_tenant_id,pg_catalog.gen_random_uuid(),'lease-expiry-worker','system',
        'device.lease.expired','expired',expired.lease_id
 FROM expired;
 GET DIAGNOSTICS v_audit_count = ROW_COUNT;

 IF v_audit_count <> v_due_count THEN
  RAISE EXCEPTION 'lease expiry batch changed while holding the device lock'
   USING ERRCODE = '40001';
 END IF;

 UPDATE ujani_control.devices
 SET reservation_revision = v_new_revision,
     updated_at = v_now
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;

 RETURN v_due_count;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.renew_device_lease(
 text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION ujani_control.release_device_lease(
 text,text,text,text,bigint,bytea,bytea,bytea,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION ujani_control.expire_device_leases(text,text,integer) FROM PUBLIC;

-- Grant only when the customer has provisioned the documented runtime role.
-- Production deployments must keep that role non-owner and non-BYPASSRLS.
DO $block$
DECLARE
 v_runtime_role_oid oid;
BEGIN
 SELECT oid INTO v_runtime_role_oid
 FROM pg_catalog.pg_roles WHERE rolname = 'ujani_runtime';
 IF v_runtime_role_oid IS NULL THEN
  RAISE EXCEPTION 'ujani_runtime must be provisioned before migration 0015'
   USING ERRCODE = '42704';
 END IF;
 IF v_runtime_role_oid IS NOT NULL THEN
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
  EXECUTE 'GRANT USAGE ON SCHEMA ujani_control TO ujani_runtime';
  -- Remove broad table-level write access left by bootstrap fixtures and
  -- replace it with the exact columns needed by the admission/lifecycle
  -- functions. Owner consent, trust and admission evidence remain read-only.
  EXECUTE 'REVOKE UPDATE,DELETE ON ujani_control.devices,ujani_control.leases FROM PUBLIC,ujani_runtime';
  EXECUTE 'REVOKE UPDATE (owner_consent_state,admin_approval_state,trust_state,key_generation,consent_generation,active_key_id) ON ujani_control.devices FROM ujani_runtime';
  EXECUTE 'REVOKE UPDATE (manifest_digest) ON ujani_control.leases FROM ujani_runtime';
  EXECUTE 'GRANT SELECT ON ujani_control.devices,ujani_control.device_keys,ujani_control.device_owner_bindings,ujani_control.owner_consents,ujani_control.operator_subjects,ujani_control.workloads,ujani_control.approvals,ujani_control.leases,ujani_control.device_telemetry_samples,ujani_control.request_replays,ujani_control.audit_events,ujani_control.model_inventory_policies TO ujani_runtime';
  -- Row-lock privileges are column-scoped. The runtime can update telemetry,
  -- inventory and reservation watermarks, but not trust or owner-consent state.
  EXECUTE 'GRANT UPDATE (admission_lock_marker) ON ujani_control.device_keys,ujani_control.device_owner_bindings,ujani_control.owner_consents,ujani_control.operator_subjects,ujani_control.workloads,ujani_control.approvals TO ujani_runtime';
  EXECUTE 'GRANT UPDATE (telemetry_generation,telemetry_sequence,last_seen_at,reservation_revision,model_inventory_revision,updated_at) ON ujani_control.devices TO ujani_runtime';
  EXECUTE 'GRANT SELECT,INSERT ON ujani_control.device_telemetry_samples TO ujani_runtime';
  EXECUTE 'GRANT SELECT,INSERT ON ujani_control.leases TO ujani_runtime';
  EXECUTE 'GRANT UPDATE (state,expires_at,revision) ON ujani_control.leases TO ujani_runtime';
  EXECUTE 'GRANT SELECT,INSERT ON ujani_control.request_replays TO ujani_runtime';
  EXECUTE 'GRANT SELECT,INSERT ON ujani_control.audit_events TO ujani_runtime';
  EXECUTE 'GRANT SELECT,INSERT,UPDATE ON ujani_control.device_model_inventory TO ujani_runtime';
  EXECUTE 'GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA ujani_control TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.accept_device_telemetry_v2(text,text,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text) TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.admit_device_lease(text,text,text,text,text,bytea,bytea,bytea,bigint,bigint,integer,bigint,bytea,timestamptz,uuid) TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.admit_device_lease_with_telemetry(text,text,bigint,bigint,bigint,bigint,bigint,bytea,timestamptz,bytea,integer,bigint,text,text,text,text,text,text,bytea,bytea,bytea,integer,bigint,bytea,timestamptz,uuid) TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.accept_model_runtime_inventory_v2(text,text,text,bigint,bigint,bytea,timestamptz,bigint,text,bytea,jsonb,uuid) TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.renew_device_lease(text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz,uuid) TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.release_device_lease(text,text,text,text,bigint,bytea,bytea,bytea,uuid) TO ujani_runtime';
  EXECUTE 'GRANT EXECUTE ON FUNCTION ujani_control.expire_device_leases(text,text,integer) TO ujani_runtime';
 END IF;
END;
$block$;

COMMENT ON FUNCTION ujani_control.renew_device_lease(
 text,text,text,text,bigint,bigint,bytea,bytea,bytea,timestamptz,uuid
) IS
 'Atomic device-authenticated lease renewal. Rechecks enrolled trust, active key generation, current owner consent generation, enabled owner, approved workload, unexpired administrator approval and fresh safe telemetry. Capacity checks account for reservations newer than the measured reservation revision. Claims request replay, extends expiry and appends audit in one transaction. Resource quantity is unchanged, so reservation_revision is not advanced.';
COMMENT ON FUNCTION ujani_control.release_device_lease(
 text,text,text,text,bigint,bytea,bytea,bytea,uuid
) IS
 'Atomic device-authenticated lease release. Rechecks enrolled device and active key generation, claims request replay, marks the owned unexpired reservation released, advances the device reservation revision and appends audit in one transaction. It does not require owner consent because release cannot grant participation.';
COMMENT ON FUNCTION ujani_control.expire_device_leases(text,text,integer) IS
 'Idempotent tenant-scoped lease expiry reconciliation for one device. Locks the tenant audit chain and device row, expires at most 100 due reserved/active leases, advances the device reservation revision once per expired lease and appends one audit receipt per transition. It accepts no caller-supplied clock or lease state.';
