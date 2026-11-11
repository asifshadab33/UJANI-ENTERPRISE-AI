-- Executed after migrations 0001 and 0002 on a disposable PostgreSQL database.
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('tenant-a','Tenant A'), ('tenant-b','Tenant B')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO ujani_control.devices
 (tenant_id, device_id, display_name, platform, trust_state, owner_consent_state, admin_approval_state)
VALUES
 ('tenant-a','device-a','Device A','linux','enrolled','granted','approved'),
 ('tenant-b','device-b','Device B','linux','enrolled','granted','approved')
ON CONFLICT (tenant_id, device_id) DO NOTHING;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';

DO $$
DECLARE
 visible_rows integer;
 affected_rows integer;
BEGIN
 INSERT INTO ujani_control.task_contract_replays
  (tenant_id, task_id, sender_device_id, nonce, envelope_digest, payload_digest, expires_at, state)
 VALUES
  ('tenant-a','task-a','device-a',decode(repeat('11',32),'hex'),
   decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),now() + interval '5 minutes','received');

 -- The same sender/nonce cannot be claimed for another task, even concurrently:
 -- the unique constraint is the database-level atomic replay gate.
 BEGIN
  INSERT INTO ujani_control.task_contract_replays
   (tenant_id, task_id, sender_device_id, nonce, envelope_digest, payload_digest, expires_at, state)
  VALUES
   ('tenant-a','task-b','device-a',decode(repeat('11',32),'hex'),
    decode(repeat('44',32),'hex'),decode(repeat('55',32),'hex'),now() + interval '5 minutes','received');
  RAISE EXCEPTION 'duplicate task nonce unexpectedly accepted';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;

 -- Status and receipt counters are independent streams, each beginning at 1.
 INSERT INTO ujani_control.task_contract_sequences
  (tenant_id, task_id, message_type, last_sequence, message_digest)
 VALUES ('tenant-a','task-a','task_status',1,decode(repeat('66',32),'hex'));

 INSERT INTO ujani_control.task_contract_sequences
  (tenant_id, task_id, message_type, last_sequence, message_digest)
 VALUES ('tenant-a','task-a','execution_receipt',1,decode(repeat('77',32),'hex'));

 -- A strictly greater status sequence advances exactly one row.
 INSERT INTO ujani_control.task_contract_sequences
  (tenant_id, task_id, message_type, last_sequence, message_digest)
 VALUES ('tenant-a','task-a','task_status',2,decode(repeat('88',32),'hex'))
 ON CONFLICT (tenant_id, task_id, message_type) DO UPDATE
 SET last_sequence = EXCLUDED.last_sequence,
     message_digest = EXCLUDED.message_digest,
     updated_at = now()
 WHERE ujani_control.task_contract_sequences.last_sequence < EXCLUDED.last_sequence;
 GET DIAGNOSTICS affected_rows = ROW_COUNT;
 IF affected_rows <> 1 THEN
  RAISE EXCEPTION 'newer status sequence did not advance exactly once';
 END IF;

 -- Replaying the same sequence is a no-op; callers must reject the message.
 INSERT INTO ujani_control.task_contract_sequences
  (tenant_id, task_id, message_type, last_sequence, message_digest)
 VALUES ('tenant-a','task-a','task_status',2,decode(repeat('99',32))
 )
 ON CONFLICT (tenant_id, task_id, message_type) DO UPDATE
 SET last_sequence = EXCLUDED.last_sequence,
     message_digest = EXCLUDED.message_digest,
     updated_at = now()
 WHERE ujani_control.task_contract_sequences.last_sequence < EXCLUDED.last_sequence;
 GET DIAGNOSTICS affected_rows = ROW_COUNT;
 IF affected_rows <> 0 THEN
  RAISE EXCEPTION 'replayed status sequence unexpectedly advanced';
 END IF;

 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_replays;
 IF visible_rows <> 1 THEN
  RAISE EXCEPTION 'tenant-a should see one task replay row, got %', visible_rows;
 END IF;
 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_sequences;
 IF visible_rows <> 2 THEN
  RAISE EXCEPTION 'tenant-a should see two independent sequence rows, got %', visible_rows;
 END IF;

 PERFORM set_config('ujani.tenant_id','tenant-b',true);
 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_replays;
 IF visible_rows <> 0 THEN
  RAISE EXCEPTION 'tenant-b can see tenant-a replay rows';
 END IF;

 PERFORM set_config('ujani.tenant_id','',true);
 SELECT count(*) INTO visible_rows FROM ujani_control.task_contract_sequences;
 IF visible_rows <> 0 THEN
  RAISE EXCEPTION 'missing tenant context did not fail closed for sequence rows';
 END IF;

 PERFORM set_config('ujani.tenant_id','tenant-a',true);
 BEGIN
  INSERT INTO ujani_control.task_contract_replays
   (tenant_id, task_id, sender_device_id, nonce, envelope_digest, payload_digest, expires_at, state)
  VALUES
   ('tenant-b','forged-task','device-b',decode(repeat('aa',32),'hex'),
    decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),now() + interval '5 minutes','received');
  RAISE EXCEPTION 'cross-tenant replay insert unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
END $$;

ROLLBACK;
RESET ROLE;
