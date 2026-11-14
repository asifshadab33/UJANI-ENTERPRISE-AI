-- Atomic post-authentication device admission and lease reservation.
-- Apply after migrations 0001-0007. The HTTP adapter MUST verify the signed
-- request and administrator approval before calling this SECURITY INVOKER function.
-- This transaction rechecks mutable tenant/device/consent/approval/capacity facts.
-- It does not dispatch work or execute models.

ALTER TABLE ujani_control.devices
 ADD COLUMN IF NOT EXISTS consent_generation bigint NOT NULL DEFAULT 0 CHECK (consent_generation >= 0),
 ADD COLUMN IF NOT EXISTS reservation_revision bigint NOT NULL DEFAULT 0 CHECK (reservation_revision >= 0);

-- Bind each enrolled device to a tenant identity. The owner subject is assigned
-- by the authenticated administrator enrollment service; runtime lease admission
-- can only read this binding and cannot create or change it.
CREATE TABLE IF NOT EXISTS ujani_control.device_owner_bindings (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 owner_subject_id text NOT NULL,
 bound_by_subject_id text NOT NULL,
 binding_revision bigint NOT NULL CHECK (binding_revision > 0),
 active boolean NOT NULL DEFAULT true,
 binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
 bound_at timestamptz NOT NULL DEFAULT now(),
 admission_lock_marker boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id, device_id),
 FOREIGN KEY (tenant_id, device_id)
  REFERENCES ujani_control.devices(tenant_id, device_id),
 FOREIGN KEY (tenant_id, owner_subject_id)
  REFERENCES ujani_control.operator_subjects(tenant_id, subject_id),
 FOREIGN KEY (tenant_id, bound_by_subject_id)
  REFERENCES ujani_control.operator_subjects(tenant_id, subject_id)
);
ALTER TABLE ujani_control.device_owner_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.device_owner_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.device_owner_bindings;
CREATE POLICY tenant_isolation ON ujani_control.device_owner_bindings
 USING (tenant_id = current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = current_setting('ujani.tenant_id', true));

CREATE OR REPLACE FUNCTION ujani_control.validate_device_owner_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_owner_enabled boolean;
 v_admin_enabled boolean;
 v_admin_role text;
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 -- Use the same device-row lock order as consent changes and lease admission.
 PERFORM 1 FROM ujani_control.devices
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id
 FOR UPDATE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'device owner binding references an unknown device' USING ERRCODE = '23503';
 END IF;

 SELECT enabled INTO v_owner_enabled
 FROM ujani_control.operator_subjects
 WHERE tenant_id = NEW.tenant_id AND subject_id = NEW.owner_subject_id
 FOR SHARE;
 IF NOT FOUND OR v_owner_enabled IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'device owner must be an enabled tenant subject' USING ERRCODE = '23514';
 END IF;

 SELECT role, enabled INTO v_admin_role, v_admin_enabled
 FROM ujani_control.operator_subjects
 WHERE tenant_id = NEW.tenant_id AND subject_id = NEW.bound_by_subject_id
 FOR SHARE;
 IF NOT FOUND OR v_admin_enabled IS DISTINCT FROM true OR v_admin_role <> 'administrator' THEN
  RAISE EXCEPTION 'device owner binding requires an enabled administrator' USING ERRCODE = '42501';
 END IF;

 IF TG_OP = 'INSERT' THEN
  IF NEW.binding_revision <> 1 THEN
   RAISE EXCEPTION 'initial device owner binding revision must be one' USING ERRCODE = '23514';
  END IF;
 ELSE
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.device_id IS DISTINCT FROM OLD.device_id
     OR NEW.binding_revision <> OLD.binding_revision + 1 THEN
   RAISE EXCEPTION 'device owner binding revision must advance monotonically' USING ERRCODE = '23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS device_owner_binding_validate ON ujani_control.device_owner_bindings;
CREATE TRIGGER device_owner_binding_validate
 BEFORE INSERT OR UPDATE ON ujani_control.device_owner_bindings
 FOR EACH ROW EXECUTE FUNCTION ujani_control.validate_device_owner_binding();

-- PostgreSQL requires UPDATE privilege on at least one column of a relation
-- for SELECT ... FOR SHARE. Give the runtime role a column-only privilege on
-- this inert marker, then reject every attempted value change. This permits
-- row locks without granting UPDATE on trust, consent, workload or approval data.
ALTER TABLE ujani_control.device_keys
 ADD COLUMN IF NOT EXISTS admission_lock_marker boolean NOT NULL DEFAULT false;
ALTER TABLE ujani_control.owner_consents
 ADD COLUMN IF NOT EXISTS admission_lock_marker boolean NOT NULL DEFAULT false;
ALTER TABLE ujani_control.workloads
 ADD COLUMN IF NOT EXISTS admission_lock_marker boolean NOT NULL DEFAULT false;
ALTER TABLE ujani_control.approvals
 ADD COLUMN IF NOT EXISTS admission_lock_marker boolean NOT NULL DEFAULT false;
ALTER TABLE ujani_control.operator_subjects
 ADD COLUMN IF NOT EXISTS admission_lock_marker boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION ujani_control.reject_admission_lock_marker_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 IF NEW.admission_lock_marker IS DISTINCT FROM OLD.admission_lock_marker THEN
  RAISE EXCEPTION 'admission lock marker is immutable' USING ERRCODE = '42501';
 END IF;
 RETURN NEW;
END;
$function$;

DO $block$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY[
  'device_keys','owner_consents','workloads','approvals','operator_subjects'
 ] LOOP
  EXECUTE format(
   'DROP TRIGGER IF EXISTS admission_lock_marker_immutable ON ujani_control.%I',
   table_name
  );
  EXECUTE format(
   'CREATE TRIGGER admission_lock_marker_immutable BEFORE UPDATE OF admission_lock_marker ON ujani_control.%I FOR EACH ROW EXECUTE FUNCTION ujani_control.reject_admission_lock_marker_mutation()',
   table_name
  );
 END LOOP;
END;
$block$;

-- Preserve monotonic consent history for devices that already have a durable
-- owner-consent event. Devices without such evidence remain generation zero
-- and cannot be admitted until a fresh owner-consent event is recorded.
UPDATE ujani_control.devices d
SET consent_generation = consent.latest_generation
FROM (
 SELECT tenant_id, device_id, max(consent_generation) AS latest_generation
 FROM ujani_control.owner_consents
 GROUP BY tenant_id, device_id
) consent
WHERE d.tenant_id = consent.tenant_id
  AND d.device_id = consent.device_id
  AND d.consent_generation < consent.latest_generation;

ALTER TABLE ujani_control.leases
 ADD COLUMN IF NOT EXISTS requested_cpu_millis integer NOT NULL DEFAULT 0 CHECK (requested_cpu_millis >= 0),
 ADD COLUMN IF NOT EXISTS requested_memory_mb bigint NOT NULL DEFAULT 0 CHECK (requested_memory_mb >= 0),
 ADD COLUMN IF NOT EXISTS capability_digest bytea CHECK (capability_digest IS NULL OR octet_length(capability_digest) = 32),
 ADD COLUMN IF NOT EXISTS consent_generation bigint NOT NULL DEFAULT 0 CHECK (consent_generation >= 0),
 ADD COLUMN IF NOT EXISTS request_id bytea CHECK (request_id IS NULL OR octet_length(request_id) = 16);

CREATE INDEX IF NOT EXISTS leases_active_device_capacity_idx
 ON ujani_control.leases (tenant_id, device_id, expires_at)
 WHERE state IN ('reserved','active');

-- Owner consent revisions are monotonic and serialize with admission on the device row.
CREATE OR REPLACE FUNCTION ujani_control.apply_owner_consent_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE v_current bigint;
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 SELECT consent_generation INTO v_current
 FROM ujani_control.devices
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id
 FOR UPDATE;
 IF NOT FOUND OR NEW.consent_generation <> v_current + 1 THEN
  RAISE EXCEPTION 'owner consent revision is not the next generation' USING ERRCODE = '23514';
 END IF;
 UPDATE ujani_control.devices
 SET consent_generation = NEW.consent_generation,
     owner_consent_state = NEW.state,
     updated_at = pg_catalog.clock_timestamp()
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS owner_consent_revision_apply ON ujani_control.owner_consents;
CREATE TRIGGER owner_consent_revision_apply
 BEFORE INSERT ON ujani_control.owner_consents
 FOR EACH ROW EXECUTE FUNCTION ujani_control.apply_owner_consent_revision();

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

 -- The latest consent event must agree with the device's monotonic consent revision.
 PERFORM 1 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND consent_generation = p_consent_generation AND state = 'granted'
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;

 -- Workload and signed administrator approval are checked against trusted rows.
 PERFORM 1 FROM ujani_control.workloads
 WHERE tenant_id = p_tenant_id AND workload_id = p_workload_id
   AND state = 'approved' AND manifest_digest = p_manifest_digest
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1
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
 IF NOT FOUND
    OR v_sample.received_at < v_now - interval '2 minutes'
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
   AND state IN ('reserved','active') AND expires_at > v_now;

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
  (tenant_id, lease_id, device_id, workload_id, manifest_digest,
   device_key_generation, state, expires_at, revision,
   requested_cpu_millis, requested_memory_mb, capability_digest,
   consent_generation, request_id)
 VALUES
  (p_tenant_id, p_lease_id, p_device_id, p_workload_id, p_manifest_digest,
   p_device_key_generation, 'reserved', p_expires_at, v_revision,
   p_cpu_millis, p_memory_mb, p_capability_digest,
   p_consent_generation, p_request_id);

 UPDATE ujani_control.devices
 SET reservation_revision = v_revision, updated_at = v_now
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;

 INSERT INTO ujani_control.audit_events
  (tenant_id, event_id, actor_ref, actor_role, event_type, outcome, object_ref, event_digest)
 VALUES
  (p_tenant_id, p_event_id, p_device_id, 'device',
   'device.lease.admitted', 'reserved', p_lease_id,
   pg_catalog.decode(pg_catalog.repeat('00',32),'hex'));

 RETURN true;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.admit_device_lease(
 text,text,text,text,text,bytea,bytea,bytea,bigint,bigint,integer,bigint,bytea,timestamptz,uuid
) FROM PUBLIC;
COMMENT ON FUNCTION ujani_control.admit_device_lease(
 text,text,text,text,text,bytea,bytea,bytea,bigint,bigint,integer,bigint,bytea,timestamptz,uuid
) IS
 'Atomic post-authentication admission transaction. Caller verifies device and administrator signatures first. Rechecks tenant, trust, active key generation, owner consent generation, an unexpired approval from a currently enabled administrator, approved workload, fresh telemetry and capacity under a device row lock. Commits replay claim, reservation/lease, revision and append-only audit receipt together. It does not dispatch or execute work. Consent/key/revocation writers must lock the same device row.';
