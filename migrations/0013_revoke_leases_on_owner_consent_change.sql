-- Owner consent pause/withdrawal invalidates all outstanding leases atomically.
CREATE OR REPLACE FUNCTION ujani_control.apply_owner_consent_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_current bigint;
 v_owner_subject_id text;
 v_owner_role text;
 v_owner_enabled boolean;
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.tenant_id, 0));
 SELECT consent_generation INTO v_current
 FROM ujani_control.devices
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id
 FOR UPDATE;
 IF NOT FOUND OR NEW.consent_generation <> v_current + 1 THEN
  RAISE EXCEPTION 'owner consent revision is not the next generation' USING ERRCODE = '23514';
 END IF;
 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id AND active IS TRUE
 FOR SHARE;
 IF NOT FOUND OR NEW.actor_ref IS DISTINCT FROM v_owner_subject_id THEN
  RAISE EXCEPTION 'owner consent actor does not match the active device owner' USING ERRCODE = '42501';
 END IF;
 SELECT role, enabled INTO v_owner_role, v_owner_enabled
 FROM ujani_control.operator_subjects
 WHERE tenant_id = NEW.tenant_id AND subject_id = NEW.actor_ref
 FOR SHARE;
 IF NOT FOUND OR v_owner_enabled IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'device owner subject is not enabled' USING ERRCODE = '42501';
 END IF;
 UPDATE ujani_control.devices
 SET consent_generation = NEW.consent_generation,
     owner_consent_state = NEW.state,
     updated_at = pg_catalog.clock_timestamp()
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id;

 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (NEW.tenant_id,pg_catalog.gen_random_uuid(),NEW.actor_ref,v_owner_role,
   'device.owner_consent.recorded',NEW.state,
   'device=' || pg_catalog.left(NEW.device_id,64)
   || ';generation=' || NEW.consent_generation::text
   || ';evidence=' || pg_catalog.left(pg_catalog.encode(NEW.evidence_digest,'hex'),16));

 -- Pausing or withdrawing owner consent immediately revokes every outstanding
 -- reservation on this device in the same transaction. A later grant requires
 -- a fresh lease; revoked reservations are never silently reactivated.
 IF NEW.state <> 'granted' THEN
  WITH revoked_leases AS (
   UPDATE ujani_control.leases
   SET state = 'revoked', revision = revision + 1
   WHERE tenant_id = NEW.tenant_id
     AND device_id = NEW.device_id
     AND state IN ('reserved','active')
   RETURNING tenant_id, lease_id
  )
  INSERT INTO ujani_control.audit_events
   (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
  SELECT revoked_leases.tenant_id,pg_catalog.gen_random_uuid(),NEW.actor_ref,v_owner_role,
   'device.lease.revoked','owner_consent_' || NEW.state,revoked_leases.lease_id
  FROM revoked_leases;
 END IF;
 RETURN NEW;
END;
$function$;

COMMENT ON FUNCTION ujani_control.apply_owner_consent_revision() IS
 'Applies monotonic owner-consent revisions under the device row lock. A paused or withdrawn consent also revokes every reserved/active lease and appends a per-lease audit event in the same transaction. A later grant never reactivates old leases; a fresh admission is required.';
