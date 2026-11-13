-- Enforce a tenant-scoped, database-computed audit hash chain on every insert.
-- Apply after 0001_customer_hosted_control_plane.sql. This is a database boundary,
-- not an external rollback anchor: privileged database owners can still rewrite history.

ALTER TABLE ujani_control.audit_events
 ALTER COLUMN sequence_id DROP DEFAULT,
 ALTER COLUMN event_digest SET DEFAULT decode(repeat('00', 32), 'hex');

DO $
DECLARE
 sequence_name text;
BEGIN
 sequence_name := pg_get_serial_sequence('ujani_control.audit_events', 'sequence_id');
 IF sequence_name IS NULL THEN
  RAISE EXCEPTION 'audit sequence is not configured';
 END IF;
 EXECUTE format('GRANT USAGE ON SEQUENCE %s TO %I', sequence_name, 'ujani_runtime');
END;
$;

CREATE OR REPLACE FUNCTION ujani_control.enforce_audit_event_chain()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $$
DECLARE
 v_tenant_id text;
 v_previous_digest bytea;
 v_previous_sequence bigint;
 v_payload jsonb;
 v_sequence_name text;
BEGIN
 v_tenant_id := current_setting('ujani.tenant_id', true);
 IF v_tenant_id IS NULL OR v_tenant_id = '' OR NEW.tenant_id <> v_tenant_id THEN
  RAISE EXCEPTION 'audit tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 -- Serialize inserts per tenant so concurrent writers cannot fork the chain.
 PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant_id, 0));

 SELECT sequence_id, event_digest
  INTO v_previous_sequence, v_previous_digest
  FROM ujani_control.audit_events
  WHERE tenant_id = v_tenant_id
  ORDER BY sequence_id DESC
  LIMIT 1;

 v_sequence_name := pg_get_serial_sequence('ujani_control.audit_events', 'sequence_id');
 IF v_sequence_name IS NULL THEN
  RAISE EXCEPTION 'audit sequence is not configured';
 END IF;
 NEW.sequence_id := nextval(v_sequence_name);
 IF v_previous_sequence IS NOT NULL AND NEW.sequence_id <= v_previous_sequence THEN
  RAISE EXCEPTION 'audit sequence did not advance';
 END IF;

 NEW.previous_digest := v_previous_digest;
 v_payload := jsonb_build_object(
  'schema_version', 1,
  'tenant_id', NEW.tenant_id,
  'sequence_id', NEW.sequence_id,
  'event_id', NEW.event_id,
  'actor_ref', NEW.actor_ref,
  'actor_role', NEW.actor_role,
  'event_type', NEW.event_type,
  'outcome', NEW.outcome,
  'object_ref', NEW.object_ref,
  'occurred_at_utc', to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
 );
 NEW.event_digest := sha256(
  coalesce(v_previous_digest, decode(repeat('00', 32), 'hex'))
  || convert_to(v_payload::text, 'UTF8')
 );
 RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS audit_events_hash_chain_insert ON ujani_control.audit_events;
CREATE TRIGGER audit_events_hash_chain_insert
 BEFORE INSERT ON ujani_control.audit_events
 FOR EACH ROW EXECUTE FUNCTION ujani_control.enforce_audit_event_chain();

COMMENT ON FUNCTION ujani_control.enforce_audit_event_chain() IS
 'Computes a tenant-scoped SHA-256 append chain under a per-tenant transaction advisory lock. This is not external rollback protection.';
