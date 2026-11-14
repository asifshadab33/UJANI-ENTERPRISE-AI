-- Atomic, tenant-bound consumption primitive for verified Self-Evolution approvals.
-- Apply after 0006_self_evolution_approval_replay.sql.
-- The caller must verify the signature and exact proposal/target binding first.
-- This SECURITY INVOKER function uses the caller's RLS identity and performs no
-- patch, repository, filesystem, signing or execution operation.

CREATE OR REPLACE FUNCTION ujani_control.consume_self_evolution_approval(
 p_tenant_id text,
 p_approval_id text,
 p_approver_subject_id text,
 p_approver_key_id text,
 p_nonce bytea,
 p_repository text,
 p_base_ref text,
 p_source_revision text,
 p_proposal_sha256 bytea,
 p_target_sha256 bytea,
 p_approved_scope_sha256 bytea,
 p_approved_scope_count integer,
 p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 approval_lock bigint;
 nonce_lock bigint;
 consumed_at_value timestamptz;
 inserted_approval_id text;
BEGIN
 IF p_tenant_id IS NULL
    OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch'
   USING ERRCODE = '42501';
 END IF;

 IF p_approval_id IS NULL
    OR p_approval_id !~ '^[A-Za-z0-9._-]{1,128}$'
    OR p_nonce IS NULL
    OR pg_catalog.octet_length(p_nonce) <> 16
    OR p_nonce = pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex')
    OR p_expires_at IS NULL THEN
  RAISE EXCEPTION 'invalid approval replay claim'
   USING ERRCODE = '22023';
 END IF;

 -- Lock both uniqueness dimensions in deterministic order. This serializes
 -- concurrent reuse of either the approval ID or nonce without deadlocks.
 approval_lock := pg_catalog.hashtextextended(
  p_tenant_id || ':approval:' || p_approval_id, 0
 );
 nonce_lock := pg_catalog.hashtextextended(
  p_tenant_id || ':nonce:' || pg_catalog.encode(p_nonce, 'hex'), 0
 );

 IF approval_lock < nonce_lock THEN
  PERFORM pg_catalog.pg_advisory_xact_lock(approval_lock);
  IF nonce_lock <> approval_lock THEN
   PERFORM pg_catalog.pg_advisory_xact_lock(nonce_lock);
  END IF;
 ELSE
  PERFORM pg_catalog.pg_advisory_xact_lock(nonce_lock);
  IF approval_lock <> nonce_lock THEN
   PERFORM pg_catalog.pg_advisory_xact_lock(approval_lock);
  END IF;
 END IF;

 -- Sample wall-clock time only after both transaction locks are held. A
 -- transaction that waited past expiry must not consume a stale approval.
 consumed_at_value := pg_catalog.clock_timestamp();
 IF p_expires_at <= consumed_at_value THEN
  RETURN false;
 END IF;

 INSERT INTO ujani_control.self_evolution_approval_replays (
  tenant_id, approval_id, approver_subject_id, approver_key_id, nonce,
  repository, base_ref, source_revision, proposal_sha256, target_sha256,
  approved_scope_sha256, approved_scope_count, expires_at, consumed_at
 )
 VALUES (
  p_tenant_id, p_approval_id, p_approver_subject_id, p_approver_key_id, p_nonce,
  p_repository, p_base_ref, p_source_revision, p_proposal_sha256, p_target_sha256,
  p_approved_scope_sha256, p_approved_scope_count, p_expires_at, consumed_at_value
 )
 ON CONFLICT DO NOTHING
 RETURNING approval_id INTO inserted_approval_id;

 RETURN inserted_approval_id IS NOT NULL;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.consume_self_evolution_approval(
 text, text, text, text, bytea, text, text, text, bytea, bytea, bytea, integer, timestamptz
) FROM PUBLIC;

COMMENT ON FUNCTION ujani_control.consume_self_evolution_approval(
 text, text, text, text, bytea, text, text, text, bytea, bytea, bytea, integer, timestamptz
) IS
 'SECURITY INVOKER single-use approval consumption. Requires authenticated transaction-local tenant context and INSERT privileges. Acquires tenant-scoped approval-ID and nonce locks in deterministic order, samples clock_timestamp after lock acquisition, and returns true only when a new tombstone is inserted. Caller must verify the signed approval before calling.';
