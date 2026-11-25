-- Revoke outstanding leases whenever device admission authority changes.
-- Apply after migrations 0001-0018.
--
-- Admission/renewal already recheck trust, owner binding/consent, administrator
-- approval and the active device-key generation. This migration closes the
-- resource-accounting gap: a previously admitted reservation must not remain
-- live until expiry after one of those authorities is withdrawn or replaced.
--
-- All authority writers must set ujani.tenant_id and take the tenant audit
-- advisory lock before locking a device. Migration 0014 already installs the
-- statement-level lock for these device columns. The AFTER trigger is named
-- device_z_* so it runs after migration 0014's inventory invalidation trigger:
-- lock order remains tenant audit -> device -> inventory -> leases -> audit.

CREATE OR REPLACE FUNCTION ujani_control.reset_owner_consent_after_device_identity_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 IF NEW.trust_state IS DISTINCT FROM OLD.trust_state
    OR NEW.active_key_id IS DISTINCT FROM OLD.active_key_id
    OR NEW.key_generation IS DISTINCT FROM OLD.key_generation THEN
  -- A trust transition or device-key change invalidates the old owner's
  -- device-bound opt-in. The next owner consent event must advance the
  -- existing consent generation; this trigger never manufactures consent.
  NEW.owner_consent_state := 'unknown';
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS device_a_reset_owner_consent_after_identity_change
 ON ujani_control.devices;
CREATE TRIGGER device_a_reset_owner_consent_after_identity_change
 BEFORE UPDATE OF trust_state,active_key_id,key_generation
 ON ujani_control.devices
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.reset_owner_consent_after_device_identity_change();

CREATE OR REPLACE FUNCTION ujani_control.revoke_device_leases_after_authority_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_context text;
 v_authority_changed boolean;
 v_authority_valid boolean;
 v_reason text;
 v_revoked_count bigint;
BEGIN
 v_tenant_context := pg_catalog.current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = ''
    OR v_tenant_context IS DISTINCT FROM NEW.tenant_id THEN
  RAISE EXCEPTION 'authenticated tenant context is required for device authority changes'
   USING ERRCODE = '42501';
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id, 0));

 v_authority_changed :=
  NEW.trust_state IS DISTINCT FROM OLD.trust_state
  OR NEW.owner_consent_state IS DISTINCT FROM OLD.owner_consent_state
  OR NEW.admin_approval_state IS DISTINCT FROM OLD.admin_approval_state
  OR NEW.active_key_id IS DISTINCT FROM OLD.active_key_id
  OR NEW.key_generation IS DISTINCT FROM OLD.key_generation;

 -- Re-evaluate the complete dual-consent and device-identity envelope. This
 -- also makes the trigger safe for the one-time legacy reconciliation below,
 -- which deliberately issues a no-op trust_state update for invalid devices.
 v_authority_valid :=
  NEW.trust_state = 'enrolled'
  AND NEW.owner_consent_state = 'granted'
  AND NEW.admin_approval_state = 'approved'
  AND NEW.active_key_id IS NOT NULL
  AND EXISTS (
   SELECT 1
   FROM ujani_control.device_keys AS key_record
   WHERE key_record.tenant_id = NEW.tenant_id
     AND key_record.device_id = NEW.device_id
     AND key_record.key_id = NEW.active_key_id
     AND key_record.generation = NEW.key_generation
     AND key_record.state = 'active'
     AND key_record.valid_from <= pg_catalog.clock_timestamp()
     AND key_record.revoked_at IS NULL
  )
  AND EXISTS (
   SELECT 1
   FROM ujani_control.device_owner_bindings AS binding
   JOIN ujani_control.operator_subjects AS owner_subject
     ON owner_subject.tenant_id = binding.tenant_id
    AND owner_subject.subject_id = binding.owner_subject_id
   JOIN ujani_control.owner_consents AS consent
     ON consent.tenant_id = binding.tenant_id
    AND consent.device_id = binding.device_id
    AND consent.consent_generation = NEW.consent_generation
    AND consent.actor_ref = binding.owner_subject_id
    AND consent.state = 'granted'
   WHERE binding.tenant_id = NEW.tenant_id
     AND binding.device_id = NEW.device_id
     AND binding.active IS TRUE
     AND owner_subject.enabled IS TRUE
  );

 IF NOT v_authority_changed AND v_authority_valid THEN
  RETURN NEW;
 END IF;

 IF NEW.trust_state IS DISTINCT FROM OLD.trust_state THEN
  v_reason := 'device_trust_changed';
 ELSIF NEW.active_key_id IS DISTINCT FROM OLD.active_key_id
    OR NEW.key_generation IS DISTINCT FROM OLD.key_generation THEN
  v_reason := 'device_key_rotated';
 ELSIF NEW.admin_approval_state IS DISTINCT FROM OLD.admin_approval_state THEN
  v_reason := 'admin_approval_changed';
 ELSIF EXISTS (
   SELECT 1
   FROM ujani_control.device_owner_bindings AS binding
   JOIN ujani_control.operator_subjects AS owner_subject
     ON owner_subject.tenant_id = binding.tenant_id
    AND owner_subject.subject_id = binding.owner_subject_id
   WHERE binding.tenant_id = NEW.tenant_id
     AND binding.device_id = NEW.device_id
     AND binding.active IS TRUE
     AND owner_subject.enabled IS FALSE
  ) THEN
  v_reason := 'owner_subject_disabled';
 ELSIF NEW.owner_consent_state IS DISTINCT FROM OLD.owner_consent_state THEN
  v_reason := 'owner_consent_changed';
 ELSE
  v_reason := 'legacy_authority_invalid';
 END IF;

 -- Record that trust/key replacement invalidated the prior device-bound
 -- owner opt-in. The caller remains responsible for its actor-specific
 -- enrollment/approval audit event; this records only the derived consequence.
 IF (NEW.trust_state IS DISTINCT FROM OLD.trust_state
     OR NEW.active_key_id IS DISTINCT FROM OLD.active_key_id
     OR NEW.key_generation IS DISTINCT FROM OLD.key_generation)
    AND NEW.owner_consent_state = 'unknown'
    AND OLD.owner_consent_state IS DISTINCT FROM 'unknown' THEN
  INSERT INTO ujani_control.audit_events
   (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
  VALUES
   (NEW.tenant_id,pg_catalog.gen_random_uuid(),'system','system',
    'device.owner_consent.invalidated','device_identity_changed',NEW.device_id);
 END IF;

 -- State transition, per-lease audit receipt and capacity watermark advance
 -- are one transaction. An audit failure or revision overflow rolls back the
 -- original trust/approval/key/consent update as well as every lease mutation.
 WITH revoked_leases AS (
  UPDATE ujani_control.leases
  SET state = 'revoked', revision = revision + 1
  WHERE tenant_id = NEW.tenant_id
    AND device_id = NEW.device_id
    AND state IN ('reserved','active')
  RETURNING lease_id
 )
 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 SELECT
  NEW.tenant_id,pg_catalog.gen_random_uuid(),'system','system',
  'device.lease.revoked',v_reason,revoked_leases.lease_id
 FROM revoked_leases;
 GET DIAGNOSTICS v_revoked_count = ROW_COUNT;

 IF v_revoked_count > 0 THEN
  UPDATE ujani_control.devices
  SET reservation_revision = reservation_revision + v_revoked_count,
      updated_at = pg_catalog.clock_timestamp()
  WHERE tenant_id = NEW.tenant_id
    AND device_id = NEW.device_id
    AND reservation_revision <= 9007199254740991 - v_revoked_count;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'device reservation revision exhausted while revoking leases'
    USING ERRCODE = '22003';
  END IF;
 END IF;

 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS device_z_revoke_leases_after_authority_change
 ON ujani_control.devices;
CREATE TRIGGER device_z_revoke_leases_after_authority_change
 AFTER UPDATE OF trust_state,owner_consent_state,admin_approval_state,active_key_id,key_generation
 ON ujani_control.devices
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.revoke_device_leases_after_authority_change();

COMMENT ON FUNCTION ujani_control.revoke_device_leases_after_authority_change() IS
 'Atomically revokes every reserved/active lease when trust, owner consent, administrator approval, owner binding or active device-key authority changes. Rechecks the complete current authority envelope for legacy reconciliation, appends one audit event per revoked lease, and advances reservation_revision by the number of capacity changes. It never creates or dispatches work.';

CREATE OR REPLACE FUNCTION ujani_control.lock_operator_subject_authority_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_context text;
BEGIN
 v_tenant_context := pg_catalog.current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = '' THEN
  RAISE EXCEPTION 'authenticated tenant context is required for operator authority changes'
   USING ERRCODE = '42501';
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_tenant_context, 0));
 RETURN NULL;
END;
$function$;

DROP TRIGGER IF EXISTS operator_subjects_a_authority_lock ON ujani_control.operator_subjects;
CREATE TRIGGER operator_subjects_a_authority_lock
 BEFORE UPDATE OF enabled,role ON ujani_control.operator_subjects
 FOR EACH STATEMENT
 EXECUTE FUNCTION ujani_control.lock_operator_subject_authority_change();

CREATE OR REPLACE FUNCTION ujani_control.revoke_device_leases_for_disabled_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_context text;
BEGIN
 v_tenant_context := pg_catalog.current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = ''
    OR v_tenant_context IS DISTINCT FROM NEW.tenant_id THEN
  RAISE EXCEPTION 'authenticated tenant context is required for operator authority changes'
   USING ERRCODE = '42501';
 END IF;

 IF OLD.enabled IS DISTINCT FROM NEW.enabled AND NEW.enabled IS FALSE THEN
  -- The statement-level trigger already holds the tenant audit lock before the
  -- subject row lock. Invalidate every active owner's device grant; the device
  -- AFTER trigger revokes reservations and appends per-lease receipts atomically.
  UPDATE ujani_control.devices AS device
  SET owner_consent_state = 'unknown',
      updated_at = pg_catalog.clock_timestamp()
  FROM ujani_control.device_owner_bindings AS binding
  WHERE binding.tenant_id = NEW.tenant_id
    AND binding.owner_subject_id = NEW.subject_id
    AND binding.active IS TRUE
    AND device.tenant_id = binding.tenant_id
    AND device.device_id = binding.device_id
    AND device.owner_consent_state = 'granted';

  INSERT INTO ujani_control.audit_events
   (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
  VALUES
   (NEW.tenant_id,pg_catalog.gen_random_uuid(),NEW.subject_id,NEW.role,
    'operator.subject.disabled','disabled',
    'subject=' || pg_catalog.left(NEW.subject_id,64));
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS operator_subjects_z_revoke_device_leases ON ujani_control.operator_subjects;
CREATE TRIGGER operator_subjects_z_revoke_device_leases
 AFTER UPDATE OF enabled ON ujani_control.operator_subjects
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.revoke_device_leases_for_disabled_owner();

COMMENT ON FUNCTION ujani_control.revoke_device_leases_for_disabled_owner() IS
 'When an operator subject is disabled, invalidate every active device-owner grant for that subject. Device authority triggers revoke outstanding reservations, append per-lease audit receipts and advance capacity revisions in the same transaction. Re-enabling a subject never restores consent or leases.';

CREATE OR REPLACE FUNCTION ujani_control.revoke_device_leases_for_invalid_approver()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_context text;
 v_reason text;
 v_device_count bigint;
 v_updated_count bigint;
BEGIN
 v_tenant_context := pg_catalog.current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = ''
    OR v_tenant_context IS DISTINCT FROM NEW.tenant_id THEN
  RAISE EXCEPTION 'authenticated tenant context is required for approver authority changes'
   USING ERRCODE = '42501';
 END IF;

 IF OLD.role IS DISTINCT FROM NEW.role THEN
  INSERT INTO ujani_control.audit_events
   (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
  VALUES
   (NEW.tenant_id,pg_catalog.gen_random_uuid(),'system','system',
    'operator.subject.role_changed',OLD.role || '_to_' || NEW.role,
    'subject=' || pg_catalog.left(NEW.subject_id,64));
 END IF;

 IF NOT (
  (OLD.enabled IS TRUE AND NEW.enabled IS FALSE)
  OR (OLD.role = 'administrator' AND NEW.role IS DISTINCT FROM 'administrator')
 ) THEN
  RETURN NEW;
 END IF;

 IF NEW.enabled IS FALSE THEN
  v_reason := 'approver_subject_disabled';
 ELSE
  v_reason := 'approver_role_changed';
 END IF;

 -- The statement-level tenant lock is acquired before the subject row lock.
 -- Lock affected devices in stable order before touching lease rows, preserving
 -- the common tenant -> device -> lease -> audit order used by admission.
 PERFORM device.device_id
 FROM ujani_control.devices AS device
 JOIN ujani_control.leases AS lease
   ON lease.tenant_id = device.tenant_id
  AND lease.device_id = device.device_id
 JOIN ujani_control.approvals AS approval
   ON approval.tenant_id = lease.tenant_id
  AND approval.approval_id = lease.approval_id
 WHERE device.tenant_id = NEW.tenant_id
   AND approval.approver_subject_id = NEW.subject_id
   AND lease.state IN ('reserved','active')
 ORDER BY device.device_id
 FOR UPDATE OF device;

 WITH revoked_leases AS (
  UPDATE ujani_control.leases AS lease
  SET state = 'revoked', revision = revision + 1
  FROM ujani_control.approvals AS approval
  WHERE lease.tenant_id = NEW.tenant_id
    AND approval.tenant_id = lease.tenant_id
    AND approval.approval_id = lease.approval_id
    AND approval.approver_subject_id = NEW.subject_id
    AND lease.state IN ('reserved','active')
  RETURNING lease.tenant_id, lease.device_id, lease.lease_id
 ),
 revoked_counts AS (
  SELECT tenant_id, device_id, count(*)::bigint AS revoked_count
  FROM revoked_leases
  GROUP BY tenant_id, device_id
 ),
 updated_devices AS (
  UPDATE ujani_control.devices AS device
  SET reservation_revision = device.reservation_revision + revoked_counts.revoked_count,
      updated_at = pg_catalog.clock_timestamp()
  FROM revoked_counts
  WHERE device.tenant_id = revoked_counts.tenant_id
    AND device.device_id = revoked_counts.device_id
    AND device.reservation_revision <= 9007199254740991 - revoked_counts.revoked_count
  RETURNING device.tenant_id, device.device_id
 ),
 audit_receipts AS (
  INSERT INTO ujani_control.audit_events
   (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
  SELECT revoked.tenant_id,pg_catalog.gen_random_uuid(),'system','system',
   'device.lease.revoked',v_reason,revoked.lease_id
  FROM revoked_leases AS revoked
  RETURNING event_id
 )
 SELECT (SELECT count(*) FROM revoked_counts),
        (SELECT count(*) FROM updated_devices)
 INTO v_device_count, v_updated_count;

 IF v_device_count <> v_updated_count THEN
  RAISE EXCEPTION 'device reservation revision exhausted while revoking approver leases'
   USING ERRCODE = '22003';
 END IF;

 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS operator_subjects_y_revoke_approver_leases ON ujani_control.operator_subjects;
CREATE TRIGGER operator_subjects_y_revoke_approver_leases
 AFTER UPDATE OF enabled,role ON ujani_control.operator_subjects
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.revoke_device_leases_for_invalid_approver();

COMMENT ON FUNCTION ujani_control.revoke_device_leases_for_invalid_approver() IS
 'Disabling an approver or demoting an administrator invalidates leases backed by that approver. It locks affected devices before lease rows, appends one audit receipt per revoked lease, advances per-device capacity revisions, and never reactivates leases after re-enablement or re-promotion.';

-- Reconcile pre-existing rows before enabling normal operation under this
-- migration. The migration role must bypass RLS, as required by migration 0008;
-- tenant context is set for each pass so audit-chain triggers remain active.
DO $backfill$
DECLARE
 v_tenant_id text;
 v_can_bypass_rls boolean;
BEGIN
 SELECT (role_record.rolsuper OR role_record.rolbypassrls)
 INTO v_can_bypass_rls
 FROM pg_catalog.pg_roles AS role_record
 WHERE role_record.rolname = current_user;
 IF v_can_bypass_rls IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'migration 0019 must run as a superuser or BYPASSRLS migration role'
   USING ERRCODE = '42501';
 END IF;

 FOR v_tenant_id IN
  SELECT tenant_id FROM ujani_control.tenants ORDER BY tenant_id
 LOOP
  PERFORM pg_catalog.set_config('ujani.tenant_id',v_tenant_id,true);

  -- Do not preserve an old grant for a revoked/untrusted device, replaced or
  -- missing active key, or owner binding/consent that no longer matches.
  UPDATE ujani_control.devices AS device
  SET owner_consent_state = 'unknown',
      updated_at = pg_catalog.clock_timestamp()
  WHERE device.tenant_id = v_tenant_id
    AND device.owner_consent_state = 'granted'
    AND (
     device.trust_state <> 'enrolled'
     OR device.active_key_id IS NULL
     OR NOT EXISTS (
      SELECT 1
      FROM ujani_control.device_keys AS key_record
      WHERE key_record.tenant_id = device.tenant_id
        AND key_record.device_id = device.device_id
        AND key_record.key_id = device.active_key_id
        AND key_record.generation = device.key_generation
        AND key_record.state = 'active'
        AND key_record.valid_from <= pg_catalog.clock_timestamp()
        AND key_record.revoked_at IS NULL
     )
     OR NOT EXISTS (
      SELECT 1
      FROM ujani_control.device_owner_bindings AS binding
      JOIN ujani_control.operator_subjects AS owner_subject
        ON owner_subject.tenant_id = binding.tenant_id
       AND owner_subject.subject_id = binding.owner_subject_id
      JOIN ujani_control.owner_consents AS consent
        ON consent.tenant_id = binding.tenant_id
       AND consent.device_id = binding.device_id
       AND consent.consent_generation = device.consent_generation
       AND consent.actor_ref = binding.owner_subject_id
       AND consent.state = 'granted'
      WHERE binding.tenant_id = device.tenant_id
        AND binding.device_id = device.device_id
        AND binding.active IS TRUE
        AND owner_subject.enabled IS TRUE
     )
    );
  -- The no-op target column deliberately fires the AFTER row trigger. It
  -- reconciles active leases for legacy devices whose organisation approval,
  -- owner consent, trust or key evidence is invalid even if no row changed.
  UPDATE ujani_control.devices AS device
  SET trust_state = device.trust_state
  WHERE device.tenant_id = v_tenant_id
    AND EXISTS (
     SELECT 1
     FROM ujani_control.leases AS lease
     WHERE lease.tenant_id = device.tenant_id
       AND lease.device_id = device.device_id
       AND lease.state IN ('reserved','active')
    )
    AND (
     device.trust_state <> 'enrolled'
     OR device.owner_consent_state <> 'granted'
     OR device.admin_approval_state <> 'approved'
     OR device.active_key_id IS NULL
     OR NOT EXISTS (
      SELECT 1
      FROM ujani_control.device_keys AS key_record
      WHERE key_record.tenant_id = device.tenant_id
        AND key_record.device_id = device.device_id
        AND key_record.key_id = device.active_key_id
        AND key_record.generation = device.key_generation
        AND key_record.state = 'active'
        AND key_record.valid_from <= pg_catalog.clock_timestamp()
        AND key_record.revoked_at IS NULL
     )
     OR NOT EXISTS (
      SELECT 1
      FROM ujani_control.device_owner_bindings AS binding
      JOIN ujani_control.operator_subjects AS owner_subject
        ON owner_subject.tenant_id = binding.tenant_id
       AND owner_subject.subject_id = binding.owner_subject_id
      JOIN ujani_control.owner_consents AS consent
        ON consent.tenant_id = binding.tenant_id
       AND consent.device_id = binding.device_id
       AND consent.consent_generation = device.consent_generation
       AND consent.actor_ref = binding.owner_subject_id
       AND consent.state = 'granted'
      WHERE binding.tenant_id = device.tenant_id
        AND binding.device_id = device.device_id
        AND binding.active IS TRUE
        AND owner_subject.enabled IS TRUE
     )
    );
 END LOOP;
END;
$backfill$;
