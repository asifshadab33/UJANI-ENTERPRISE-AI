-- Run after migrations 0001-0014 and scripts/test_atomic_telemetry_lease_admission.sql.
-- The Rust service adapter verifies the exact device signature and JSON Schema.
-- This test proves SQL-side trust/dual-consent rechecks, replay protection,
-- monotonic server revision, tenant RLS, privacy rejection and consent purge.

GRANT SELECT, INSERT, UPDATE, DELETE
 ON ujani_control.device_model_runtime_inventories TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.accept_device_model_runtime_inventory(
 text,text,bigint,bytea,bytea,timestamptz,jsonb
) TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.list_device_model_runtime_inventory(text,integer)
 TO ujani_runtime;

BEGIN;
SET LOCAL ROLE ujani_runtime;
SET LOCAL ujani.tenant_id = 'admission-test';

DO $block$
DECLARE
 v_generated_at timestamptz;
 v_generated_at_ms bigint;
 v_inventory jsonb;
 v_revision bigint;
 v_rows integer;
 v_audit_rows integer;
 v_replay_rows integer;
 v_digest bytea := decode(repeat('a1',32),'hex');
 v_request_id bytea := decode(repeat('b1',16),'hex');
 v_other_request bytea;
BEGIN
 v_generated_at := clock_timestamp();
 v_generated_at_ms := floor(extract(epoch FROM v_generated_at) * 1000)::bigint;
 v_generated_at := to_timestamp(v_generated_at_ms::double precision / 1000.0);
 v_inventory := jsonb_build_object(
  'schema_version',1,
  'generated_at_unix_ms',v_generated_at_ms,
  'device_ref','admission-atomic-device',
  'platform',jsonb_build_object('os','linux','architecture','x86_64'),
  'hardware',jsonb_build_object(
   'cpu_logical_cores',8,
   'memory_total_mb',16384,
   'memory_available_mb',8192,
   'accelerators',jsonb_build_array()
  ),
  'runtimes',jsonb_build_array(jsonb_build_object(
   'runtime_id','ollama-local',
   'provider','ollama',
   'version','0.5.12',
   'availability','available',
   'network_scope','loopback_only',
   'evidence',jsonb_build_object(
    'source','runtime_api',
    'confidence','reported',
    'observed_at_unix_ms',v_generated_at_ms
   )
  )),
  'models',jsonb_build_array(jsonb_build_object(
   'model_ref','qwen2.5:3b',
   'runtime_id','ollama-local',
   'display_name','Qwen 2.5 3B',
   'availability','installed',
   'size_bytes',1500000000,
   'capabilities',jsonb_build_array('chat','coding'),
   'evidence',jsonb_build_object(
    'source','runtime_metadata',
    'confidence','reported',
    'observed_at_unix_ms',v_generated_at_ms
   )
  )),
  'privacy',jsonb_build_object(
   'contains_prompts',false,
   'contains_user_files',false,
   'contains_local_paths',false,
   'contains_credentials',false
  )
 );

 v_revision := ujani_control.accept_device_model_runtime_inventory(
  'admission-test','admission-atomic-device',1,v_request_id,v_digest,
  v_generated_at,v_inventory
 );
 IF v_revision IS DISTINCT FROM 1 THEN
  RAISE EXCEPTION 'first model inventory report was not accepted at revision 1';
 END IF;

 SELECT count(*) INTO v_rows
 FROM ujani_control.list_device_model_runtime_inventory(NULL,10)
 WHERE device_id='admission-atomic-device'
   AND inventory_revision=1
   AND device_key_generation=1
   AND consent_generation=5
   AND jsonb_array_length(inventory->'runtimes')=1
   AND jsonb_array_length(inventory->'models')=1;
 SELECT count(*) INTO v_audit_rows
 FROM ujani_control.audit_events
 WHERE tenant_id='admission-test'
   AND event_type='device.model_runtime_inventory.updated'
   AND object_ref='admission-atomic-device'
   AND outcome='accepted:' || left(encode(v_digest,'hex'),16);
 SELECT count(*) INTO v_replay_rows
 FROM ujani_control.request_replays
 WHERE tenant_id='admission-test'
   AND device_id='admission-atomic-device'
   AND request_id=v_request_id;
 IF v_rows <> 1 OR v_audit_rows <> 1 OR v_replay_rows <> 1 THEN
  RAISE EXCEPTION 'accepted inventory, audit or replay receipt is incomplete';
 END IF;

 -- A duplicate request cannot create another revision or audit receipt.
 v_other_request := decode(repeat('b1',16),'hex');
 IF ujani_control.accept_device_model_runtime_inventory(
   'admission-test','admission-atomic-device',1,v_other_request,
   decode(repeat('a2',32),'hex'),v_generated_at + interval '1 second',
   jsonb_set(v_inventory,'{generated_at_unix_ms}',to_jsonb(v_generated_at_ms + 1000))
 ) IS NOT NULL THEN
  RAISE EXCEPTION 'duplicate inventory request ID was accepted';
 END IF;

 -- A fresh but older snapshot cannot replace the last accepted inventory.
 v_other_request := decode(repeat('b2',16),'hex');
 IF ujani_control.accept_device_model_runtime_inventory(
   'admission-test','admission-atomic-device',1,v_other_request,
   decode(repeat('a3',32),'hex'),v_generated_at - interval '1 second',
   jsonb_set(
    jsonb_set(
     jsonb_set(v_inventory,'{generated_at_unix_ms}',to_jsonb(v_generated_at_ms - 1000)),
     '{runtimes,0,evidence,observed_at_unix_ms}',to_jsonb(v_generated_at_ms - 1000)
    ),
    '{models,0,evidence,observed_at_unix_ms}',to_jsonb(v_generated_at_ms - 1000)
   )
 ) IS NOT NULL THEN
  RAISE EXCEPTION 'older inventory timestamp replaced a newer snapshot';
 END IF;

 -- Stale key generation and privacy-violating content fail closed.
 v_other_request := decode(repeat('b3',16),'hex');
 IF ujani_control.accept_device_model_runtime_inventory(
   'admission-test','admission-atomic-device',2,v_other_request,
   decode(repeat('a4',32),'hex'),v_generated_at + interval '2 seconds',
   jsonb_set(v_inventory,'{generated_at_unix_ms}',to_jsonb(v_generated_at_ms + 2000))
 ) IS NOT NULL THEN
  RAISE EXCEPTION 'stale device key generation was accepted';
 END IF;

 v_other_request := decode(repeat('b4',16),'hex');
 IF ujani_control.accept_device_model_runtime_inventory(
   'admission-test','admission-atomic-device',1,v_other_request,
   decode(repeat('a5',32),'hex'),v_generated_at + interval '3 seconds',
   jsonb_set(
    jsonb_set(v_inventory,'{generated_at_unix_ms}',to_jsonb(v_generated_at_ms + 3000)),
    '{privacy,contains_prompts}','true'::jsonb
   )
 ) IS NOT NULL THEN
  RAISE EXCEPTION 'prompt-bearing inventory was accepted';
 END IF;

 IF EXISTS (
  SELECT 1 FROM ujani_control.request_replays
  WHERE tenant_id='admission-test'
    AND device_id='admission-atomic-device'
    AND request_id IN (
     decode(repeat('b2',16),'hex'),
     decode(repeat('b3',16),'hex'),
     decode(repeat('b4',16),'hex')
    )
 ) THEN
  RAISE EXCEPTION 'rejected inventory consumed a replay identifier';
 END IF;

 -- Owner pause purges the previously shared snapshot in the same transaction.
 INSERT INTO ujani_control.owner_consents
  (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
 VALUES
  ('admission-test','admission-atomic-device',6,'paused','admission-owner',
   decode(repeat('a6',32),'hex'));

 SELECT count(*) INTO v_rows
 FROM ujani_control.device_model_runtime_inventories
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 IF v_rows <> 0 THEN
  RAISE EXCEPTION 'owner pause did not purge previously shared model inventory';
 END IF;

 v_generated_at := clock_timestamp();
 v_generated_at_ms := floor(extract(epoch FROM v_generated_at) * 1000)::bigint;
 v_generated_at := to_timestamp(v_generated_at_ms::double precision / 1000.0);
 v_inventory := jsonb_set(v_inventory,'{generated_at_unix_ms}',to_jsonb(v_generated_at_ms));
 v_inventory := jsonb_set(
  v_inventory,'{runtimes,0,evidence,observed_at_unix_ms}',to_jsonb(v_generated_at_ms)
 );
 v_inventory := jsonb_set(
  v_inventory,'{models,0,evidence,observed_at_unix_ms}',to_jsonb(v_generated_at_ms)
 );

 v_other_request := decode(repeat('b5',16),'hex');
 IF ujani_control.accept_device_model_runtime_inventory(
   'admission-test','admission-atomic-device',1,v_other_request,
   decode(repeat('a7',32),'hex'),v_generated_at,v_inventory
 ) IS NOT NULL THEN
  RAISE EXCEPTION 'inventory upload was accepted after owner pause';
 END IF;

 -- A later owner grant requires a fresh report. The server revision remains
 -- monotonic across the privacy purge and the old snapshot is not restored.
 INSERT INTO ujani_control.owner_consents
  (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
 VALUES
  ('admission-test','admission-atomic-device',7,'granted','admission-owner',
   decode(repeat('a8',32),'hex'));

 v_generated_at := clock_timestamp();
 v_generated_at_ms := floor(extract(epoch FROM v_generated_at) * 1000)::bigint;
 v_generated_at := to_timestamp(v_generated_at_ms::double precision / 1000.0);
 v_inventory := jsonb_set(v_inventory,'{generated_at_unix_ms}',to_jsonb(v_generated_at_ms));
 v_inventory := jsonb_set(
  v_inventory,'{runtimes,0,evidence,observed_at_unix_ms}',to_jsonb(v_generated_at_ms)
 );
 v_inventory := jsonb_set(
  v_inventory,'{models,0,evidence,observed_at_unix_ms}',to_jsonb(v_generated_at_ms)
 );
 v_revision := ujani_control.accept_device_model_runtime_inventory(
  'admission-test','admission-atomic-device',1,
  decode(repeat('b6',16),'hex'),decode(repeat('a9',32),'hex'),
  v_generated_at,v_inventory
 );
 IF v_revision IS DISTINCT FROM 2 THEN
  RAISE EXCEPTION 'fresh post-grant report did not advance the server revision to 2';
 END IF;

 SELECT count(*) INTO v_rows
 FROM ujani_control.list_device_model_runtime_inventory(NULL,10)
 WHERE device_id='admission-atomic-device'
   AND inventory_revision=2
   AND consent_generation=7;
 SELECT count(*) INTO v_audit_rows
 FROM ujani_control.audit_events
 WHERE tenant_id='admission-test'
   AND event_type='device.model_runtime_inventory.updated'
   AND object_ref='admission-atomic-device';
 IF v_rows <> 1 OR v_audit_rows <> 2 THEN
  RAISE EXCEPTION 'post-grant inventory or audit history is incomplete';
 END IF;

 -- The read-only operator query preserves tenant RLS.
 PERFORM pg_catalog.set_config('ujani.tenant_id','another-tenant',true);
 SELECT count(*) INTO v_rows
 FROM ujani_control.list_device_model_runtime_inventory(NULL,10)
 WHERE device_id='admission-atomic-device';
 IF v_rows <> 0 THEN
  RAISE EXCEPTION 'model inventory query leaked data across tenant context';
 END IF;
 PERFORM pg_catalog.set_config('ujani.tenant_id','admission-test',true);
END;
$block$;

ROLLBACK;
