-- Executed after migrations 0001, 0006 and 0007 on a disposable PostgreSQL DB.
-- Requires tenant-a/admin-a and the ujani_runtime role from earlier migration tests.
GRANT SELECT, INSERT ON ujani_control.self_evolution_approval_replays TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.consume_self_evolution_approval(
 text, text, text, text, bytea, text, text, text, bytea, bytea, bytea, integer, timestamptz
) TO ujani_runtime;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';

DO $$
DECLARE
 consumed boolean;
 visible_rows integer;
BEGIN
 SELECT ujani_control.consume_self_evolution_approval(
  'tenant-a','approval-function-a','admin-a','admin-key-a',decode(repeat('11',16),'hex'),
  'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
  decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
  decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '5 minutes'
 ) INTO consumed;
 IF consumed IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'first verified approval was not consumed';
 END IF;

 -- Same approval ID with a different nonce is still a replay.
 SELECT ujani_control.consume_self_evolution_approval(
  'tenant-a','approval-function-a','admin-a','admin-key-a',decode(repeat('55',16),'hex'),
  'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
  decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
  decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '5 minutes'
 ) INTO consumed;
 IF consumed IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'duplicate approval ID was consumed twice';
 END IF;

 -- Same nonce with a different approval ID is also a replay.
 SELECT ujani_control.consume_self_evolution_approval(
  'tenant-a','approval-function-b','admin-a','admin-key-a',decode(repeat('11',16),'hex'),
  'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
  decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
  decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '5 minutes'
 ) INTO consumed;
 IF consumed IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'duplicate approval nonce was consumed twice';
 END IF;

 -- Expiry is evaluated by the database after acquiring both advisory locks.
 SELECT ujani_control.consume_self_evolution_approval(
  'tenant-a','approval-function-expired','admin-a','admin-key-a',decode(repeat('66',16),'hex'),
  'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
  decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
  decode(repeat('44',32),'hex'),1,clock_timestamp() - interval '1 second'
 ) INTO consumed;
 IF consumed IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'expired approval was consumed';
 END IF;

 SELECT count(*) INTO visible_rows
  FROM ujani_control.self_evolution_approval_replays
  WHERE tenant_id = 'tenant-a';
 IF visible_rows <> 1 THEN
  RAISE EXCEPTION 'expected exactly one consumed approval, got %', visible_rows;
 END IF;

 -- Tenant context is checked before any replay row can be written.
 PERFORM set_config('ujani.tenant_id','tenant-b',true);
 BEGIN
  PERFORM ujani_control.consume_self_evolution_approval(
   'tenant-a','cross-tenant-approval','admin-a','admin-key-a',decode(repeat('77',16),'hex'),
   'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
   decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
   decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '5 minutes'
  );
  RAISE EXCEPTION 'cross-tenant approval consumption unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;

 PERFORM set_config('ujani.tenant_id','',true);
 BEGIN
  PERFORM ujani_control.consume_self_evolution_approval(
   'tenant-a','missing-context-approval','admin-a','admin-key-a',decode(repeat('88',16),'hex'),
   'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
   decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
   decode(repeat('44',32),'hex'),1,clock_timestamp() + interval '5 minutes'
  );
  RAISE EXCEPTION 'approval consumption without tenant context unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
END $$;

ROLLBACK;
RESET ROLE;
