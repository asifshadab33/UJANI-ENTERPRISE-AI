-- Transaction-safe helper functions for the shared task-contract v1 replay tables.
-- Call only after the service has authenticated the sender and verified the
-- exact envelope/payload digests, signatures, tenant and device-key binding.
-- These functions claim replay state and advance sequence watermarks only;
-- they do not authorise, reserve or execute workloads.

CREATE OR REPLACE FUNCTION ujani_control.claim_task_contract_replay(
 p_tenant_id text,
 p_task_id text,
 p_sender_device_id text,
 p_nonce bytea,
 p_envelope_digest bytea,
 p_payload_digest bytea,
 p_expires_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_now timestamptz := pg_catalog.clock_timestamp();
 v_claimed_task_id text;
BEGIN
 IF p_tenant_id IS NULL
    OR p_tenant_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_task_id IS NULL OR p_task_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_sender_device_id IS NULL OR p_sender_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32
    OR p_envelope_digest IS NULL OR pg_catalog.octet_length(p_envelope_digest) <> 32
    OR p_payload_digest IS NULL OR pg_catalog.octet_length(p_payload_digest) <> 32
    OR p_expires_at IS NULL
    OR p_expires_at <= v_now
    OR p_expires_at > v_now + interval '5 minutes' THEN
  RAISE EXCEPTION 'invalid task-contract replay claim' USING ERRCODE = '22023';
 END IF;

 -- The primary key rejects task-ID reuse; the unique sender/nonce key rejects
 -- nonce reuse. The unique indexes are the concurrency primitive, not a
 -- preflight SELECT. A conflict is a replay rejection, never an idempotent task.
 INSERT INTO ujani_control.task_contract_replays
  (tenant_id, task_id, sender_device_id, nonce, envelope_digest,
   payload_digest, expires_at, state)
 VALUES
  (p_tenant_id, p_task_id, p_sender_device_id, p_nonce, p_envelope_digest,
   p_payload_digest, p_expires_at, 'received')
 ON CONFLICT DO NOTHING
 RETURNING task_id INTO v_claimed_task_id;

 RETURN v_claimed_task_id IS NOT NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION ujani_control.advance_task_contract_sequence(
 p_tenant_id text,
 p_task_id text,
 p_message_type text,
 p_sequence bigint,
 p_message_digest bytea
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_accepted_sequence bigint;
BEGIN
 IF p_tenant_id IS NULL
    OR p_tenant_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 IF p_task_id IS NULL OR p_task_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_message_type IS NULL OR p_message_type NOT IN ('task_status','execution_receipt')
    OR p_sequence IS NULL OR p_sequence NOT BETWEEN 1 AND 9007199254740991
    OR p_message_digest IS NULL OR pg_catalog.octet_length(p_message_digest) <> 32 THEN
  RAISE EXCEPTION 'invalid task-contract sequence update' USING ERRCODE = '22023';
 END IF;

 -- Status and receipt streams advance independently. A zero-row result is a
 -- repeated or stale message and must abort the caller's associated state
 -- transition in the same surrounding transaction.
 INSERT INTO ujani_control.task_contract_sequences
  (tenant_id, task_id, message_type, last_sequence, message_digest)
 VALUES
  (p_tenant_id, p_task_id, p_message_type, p_sequence, p_message_digest)
 ON CONFLICT (tenant_id, task_id, message_type) DO UPDATE
 SET last_sequence = EXCLUDED.last_sequence,
     message_digest = EXCLUDED.message_digest,
     updated_at = pg_catalog.clock_timestamp()
 WHERE ujani_control.task_contract_sequences.last_sequence < EXCLUDED.last_sequence
 RETURNING last_sequence INTO v_accepted_sequence;

 RETURN v_accepted_sequence IS NOT NULL;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.claim_task_contract_replay(
 text,text,text,bytea,bytea,bytea,timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION ujani_control.advance_task_contract_sequence(
 text,text,text,bigint,bytea
) FROM PUBLIC;

COMMENT ON FUNCTION ujani_control.claim_task_contract_replay(
 text,text,text,bytea,bytea,bytea,timestamptz
) IS
 'Atomically claim one tenant-scoped task ID and sender nonce after external signature/key authentication. Returns false on either replay conflict. Stores digests only; no payload, admission, dispatch or execution.';
COMMENT ON FUNCTION ujani_control.advance_task_contract_sequence(
 text,text,text,bigint,bytea
) IS
 'Atomically advance one task_status or execution_receipt sequence stream. Returns false for repeated/stale sequence values. The caller must verify signatures and commit the associated task transition in the same transaction.';
