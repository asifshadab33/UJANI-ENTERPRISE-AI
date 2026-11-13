-- Executed after 0004_audit_event_hash_chain.sql against PostgreSQL 16.
-- Existing tenant-a is created by scripts/test_customer_hosted_migration.sql.

BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';

DO $$
DECLARE
 first_id uuid := '00000000-0000-4000-8000-000000000101';
 second_id uuid := '00000000-0000-4000-8000-000000000102';
 first_sequence bigint;
 second_sequence bigint;
 first_digest bytea;
 first_occurred_at timestamptz;
 expected_first_digest bytea;
 second_previous bytea;
 second_digest bytea;
BEGIN
 INSERT INTO ujani_control.audit_events
  (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
 VALUES
  ('tenant-a', first_id, 'operator-a', 'administrator', 'control_plane.test', 'accepted')
 RETURNING sequence_id, event_digest, occurred_at INTO first_sequence, first_digest, first_occurred_at;

 IF first_sequence <= 0 OR octet_length(first_digest) <> 32 THEN
  RAISE EXCEPTION 'first audit event was not assigned a valid sequence and digest';
 END IF;
 expected_first_digest := sha256(
  decode(repeat('00', 32), 'hex')
  || convert_to(jsonb_build_object(
   'schema_version', 1,
   'tenant_id', 'tenant-a',
   'sequence_id', first_sequence,
   'event_id', first_id,
   'actor_ref', 'operator-a',
   'actor_role', 'administrator',
   'event_type', 'control_plane.test',
   'outcome', 'accepted',
   'object_ref', NULL,
   'occurred_at_utc', to_char(first_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  )::text, 'UTF8')
 );
 IF first_digest IS DISTINCT FROM expected_first_digest THEN
  RAISE EXCEPTION 'first event digest does not match canonical database payload';
 END IF;
 IF (SELECT previous_digest FROM ujani_control.audit_events
      WHERE tenant_id = 'tenant-a' AND event_id = first_id) IS NOT NULL THEN
  RAISE EXCEPTION 'first event unexpectedly has a previous digest';
 END IF;

 INSERT INTO ujani_control.audit_events
  (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
 VALUES
  ('tenant-a', second_id, 'operator-a', 'administrator', 'control_plane.test', 'accepted')
 RETURNING sequence_id, previous_digest, event_digest
 INTO second_sequence, second_previous, second_digest;

 IF second_sequence <= first_sequence THEN
  RAISE EXCEPTION 'audit sequence did not increase';
 END IF;
 IF second_previous IS DISTINCT FROM first_digest THEN
  RAISE EXCEPTION 'second event does not link to the prior event digest';
 END IF;
 IF second_digest IS NOT DISTINCT FROM first_digest THEN
  RAISE EXCEPTION 'distinct audit events produced the same digest';
 END IF;

 BEGIN
  INSERT INTO ujani_control.audit_events
   (tenant_id, event_id, actor_ref, actor_role, event_type, outcome)
  VALUES
   ('tenant-b', '00000000-0000-4000-8000-000000000103', 'operator-b',
    'administrator', 'control_plane.test', 'accepted');
  RAISE EXCEPTION 'cross-tenant audit insert unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
END $$;

-- UPDATE and DELETE remain prohibited by the original append-only trigger.
DO $$
BEGIN
 BEGIN
  UPDATE ujani_control.audit_events SET outcome = 'tampered'
   WHERE tenant_id = 'tenant-a'
    AND event_id = '00000000-0000-4000-8000-000000000101';
  RAISE EXCEPTION 'audit update unexpectedly succeeded';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM = 'audit update unexpectedly succeeded' THEN RAISE; END IF;
 END;
 BEGIN
  DELETE FROM ujani_control.audit_events
   WHERE tenant_id = 'tenant-a'
    AND event_id = '00000000-0000-4000-8000-000000000101';
  RAISE EXCEPTION 'audit delete unexpectedly succeeded';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM = 'audit delete unexpectedly succeeded' THEN RAISE; END IF;
 END;
END $$;
ROLLBACK;
