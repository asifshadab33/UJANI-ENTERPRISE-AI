-- Run after migrations 0001, 0002 and 0009 on the disposable CI database.
-- The runtime role receives only the table/column privileges needed by the
-- replay functions. No payload bytes are stored in these tables.

REVOKE ALL ON ujani_control.task_contract_replays FROM ujani_runtime;
REVOKE ALL ON ujani_control.task_contract_sequences FROM ujani_runtime;
GRANT SELECT, INSERT ON ujani_control.task_contract_replays TO ujani_runtime;
GRANT SELECT, INSERT ON ujani_control.task_contract_sequences TO ujani_runtime;
GRANT UPDATE (last_sequence, message_digest, updated_at)
 ON ujani_control.task_contract_sequences TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.claim_task_contract_replay(
 text,text,text,bytea,bytea,bytea,timestamptz
) TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.advance_task_contract_sequence(
 text,text,text,bigint,bytea
) TO ujani_runtime;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';

DO $$
DECLARE
 accepted boolean;
 visible_rows integer;
BEGIN
 IF has_table_privilege(current_user,'ujani_control.task_contract_replays','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.task_contract_replays','DELETE')
    OR has_table_privilege(current_user,'ujani_control.task_contract_sequences','DELETE')
    OR has_column_privilege(current_user,'ujani_control.task_contract_sequences','task_id','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.task_contract_sequences','tenant_id','UPDATE')
    OR NOT has_column_privilege(current_user,'ujani_control.task_contract_sequences','last_sequence','UPDATE') THEN
  RAISE EXCEPTION 'task-contract runtime privileges are not least-privilege';
 END IF;

 SELECT ujani_control.claim_task_contract_replay(
  'tenant-a','task-a','device-a',decode(repeat('11',32),'hex'),
  decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
  clock_timestamp() + interval '4 minutes'
 ) INTO accepted;
 IF NOT accepted THEN
  RAISE EXCEPTION 'first task-contract replay claim was not accepted';
 END IF;

 -- Reusing a sender nonce for a different task is a replay, not idempotency.
 SELECT ujani_control.claim_task_contract_replay(
  'tenant-a','task-b','device-a',decode(repeat('11',32),'hex'),
  decode(repeat('44',32),'hex'),decode(repeat('55',32),'hex'),
  clock_timestamp() + interval '4 minutes'
 ) INTO accepted;
 IF accepted THEN
  RAISE EXCEPTION 'replayed sender nonce was accepted for a second task';
 END IF;

 -- Reusing a task ID with a different nonce is also rejected.
 SELECT ujani_control.claim_task_contract_replay(
  'tenant-a','task-a','device-a',decode(repeat('66',32),'hex'),
  decode(repeat('77',32),'hex'),decode(repeat('88',32),'hex'),
  clock_timestamp() + interval '4 minutes'
 ) INTO accepted;
 IF accepted THEN
  RAISE EXCEPTION 'replayed task ID was accepted with a different nonce';
 END IF;

 -- Task status and execution receipt are independent monotonic streams.
 SELECT ujani_control.advance_task_contract_sequence(
  'tenant-a','task-a','task_status',1,decode(repeat('91',32),'hex')
 ) INTO accepted;
 IF NOT accepted THEN RAISE EXCEPTION 'initial task-status sequence was rejected'; END IF;

 SELECT ujani_control.advance_task_contract_sequence(
  'tenant-a','task-a','execution_receipt',1,decode(repeat('92',32),'hex')
 ) INTO accepted;
 IF NOT accepted THEN RAISE EXCEPTION 'initial execution-receipt sequence was rejected'; END IF;

 SELECT ujani_control.advance_task_contract_sequence(
  'tenant-a','task-a','task_status',2,decode(repeat('93',32),'hex')
 ) INTO accepted;
 IF NOT accepted THEN RAISE EXCEPTION 'newer task-status sequence did not advance'; END IF;

 SELECT ujani_control.advance_task_contract_sequence(
  'tenant-a','task-a','task_status',2,decode(repeat('94',32),'hex')
 ) INTO accepted;
 IF accepted THEN RAISE EXCEPTION 'replayed task-status sequence unexpectedly advanced'; END IF;

 SELECT ujani_control.advance_task_contract_sequence(
  'tenant-a','task-a','task_status',1,decode(repeat('95',32),'hex')
 ) INTO accepted;
 IF accepted THEN RAISE EXCEPTION 'stale task-status sequence unexpectedly advanced'; END IF;

 SELECT count(*) INTO visible_rows
  FROM ujani_control.task_contract_sequences
  WHERE tenant_id = 'tenant-a' AND task_id = 'task-a'
    AND message_type = 'task_status'
    AND last_sequence = 2 AND message_digest = decode(repeat('93',32),'hex');
 IF visible_rows <> 1 THEN
  RAISE EXCEPTION 'stale/replayed status changed the accepted sequence digest';
 END IF;

 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_replays;
 IF visible_rows <> 1 THEN
  RAISE EXCEPTION 'tenant-a should see one replay claim, got %', visible_rows;
 END IF;
 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_sequences;
 IF visible_rows <> 2 THEN
  RAISE EXCEPTION 'tenant-a should see two independent sequence streams, got %', visible_rows;
 END IF;

 -- Missing tenant context fails closed for both reads and writes.
 PERFORM set_config('ujani.tenant_id','',true);
 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_replays;
 IF visible_rows <> 0 THEN RAISE EXCEPTION 'missing tenant context exposed replay rows'; END IF;
 BEGIN
  PERFORM ujani_control.claim_task_contract_replay(
   'tenant-a','no-context','device-a',decode(repeat('a1',32),'hex'),
   decode(repeat('a2',32),'hex'),decode(repeat('a3',32),'hex'),
   clock_timestamp() + interval '4 minutes'
  );
  RAISE EXCEPTION 'replay claim without tenant context unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;

 -- A tenant-A session cannot claim or insert tenant-B replay state.
 PERFORM set_config('ujani.tenant_id','tenant-a',true);
 BEGIN
  PERFORM ujani_control.claim_task_contract_replay(
   'tenant-b','forged-task','device-b',decode(repeat('b1',32),'hex'),
   decode(repeat('b2',32),'hex'),decode(repeat('b3',32),'hex'),
   clock_timestamp() + interval '4 minutes'
  );
  RAISE EXCEPTION 'cross-tenant replay claim unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
  INSERT INTO ujani_control.task_contract_replays
   (tenant_id, task_id, sender_device_id, nonce, envelope_digest, payload_digest, expires_at, state)
  VALUES
   ('tenant-b','direct-forged-task','device-b',decode(repeat('c1',32),'hex'),
    decode(repeat('c2',32),'hex'),decode(repeat('c3',32),'hex'),
    clock_timestamp() + interval '4 minutes','received');
  RAISE EXCEPTION 'cross-tenant direct replay insert unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;

 -- The helper rejects oversized expiry windows and malformed digests.
 BEGIN
  PERFORM ujani_control.claim_task_contract_replay(
   'tenant-a','too-long','device-a',decode(repeat('d1',32),'hex'),
   decode(repeat('d2',32),'hex'),decode(repeat('d3',32),'hex'),
   clock_timestamp() + interval '6 minutes'
  );
  RAISE EXCEPTION 'oversized task expiry was accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
 BEGIN
  PERFORM ujani_control.advance_task_contract_sequence(
   'tenant-a','task-a','task_status',3,decode(repeat('e1',31),'hex')
  );
  RAISE EXCEPTION 'short sequence digest was accepted';
 EXCEPTION WHEN invalid_parameter_value THEN NULL;
 END;
END $$;

ROLLBACK;
RESET ROLE;
