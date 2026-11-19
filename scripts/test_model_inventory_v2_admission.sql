-- Run after migrations 0001-0014 on PostgreSQL 16.
-- This verifies the post-authentication transaction. Exact device signature
-- verification and complete Draft 2020-12 validation remain adapter duties.
BEGIN;
SELECT pg_catalog.set_config('ujani.tenant_id','inventory-test',true);

INSERT INTO ujani_control.tenants (tenant_id,display_name)
VALUES ('inventory-test','Inventory Test Tenant')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.operator_subjects
 (tenant_id,subject_id,role,enabled,idp_issuer,idp_subject)
VALUES
 ('inventory-test','inventory-admin','administrator',true,'ci','inventory-admin'),
 ('inventory-test','inventory-owner','operator',true,'ci','inventory-owner'),
 ('inventory-test','inventory-owner-2','operator',true,'ci','inventory-owner-2')
ON CONFLICT (tenant_id,subject_id) DO UPDATE
 SET role=EXCLUDED.role,enabled=true;
INSERT INTO ujani_control.devices
 (tenant_id,device_id,display_name,platform,trust_state,owner_consent_state,
  admin_approval_state,active_key_id,key_generation,consent_generation)
VALUES
 ('inventory-test','inventory-device','Inventory Device','linux','enrolled','unknown',
  'approved','inventory-key',1,0),
 ('inventory-test','inventory-device-other','Inventory Device Other','linux','enrolled','unknown',
  'approved','inventory-key-other',1,0)
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 trust_state='enrolled',owner_consent_state='unknown',admin_approval_state='approved',
 active_key_id='inventory-key',key_generation=1,consent_generation=0,
 model_inventory_revision=0;
INSERT INTO ujani_control.device_keys
 (tenant_id,device_id,key_id,public_key,generation,state)
VALUES
 ('inventory-test','inventory-device','inventory-key',decode(repeat('a1',32),'hex'),1,'active'),
 ('inventory-test','inventory-device-other','inventory-key',decode(repeat('a1',32),'hex'),1,'active')
ON CONFLICT (tenant_id,device_id,key_id) DO UPDATE SET state='active',revoked_at=NULL;
INSERT INTO ujani_control.device_owner_bindings
 (tenant_id,device_id,owner_subject_id,bound_by_subject_id,binding_revision,active,binding_digest)
VALUES
 ('inventory-test','inventory-device','inventory-owner','inventory-admin',1,true,decode(repeat('a2',32),'hex'))
ON CONFLICT (tenant_id,device_id) DO UPDATE SET
 owner_subject_id=EXCLUDED.owner_subject_id,
 bound_by_subject_id=EXCLUDED.bound_by_subject_id,
 binding_revision=ujani_control.device_owner_bindings.binding_revision+1,
 active=true,binding_digest=decode(repeat('a3',32),'hex');
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('inventory-test','inventory-device',1,'granted','inventory-owner',decode(repeat('a4',32),'hex'))
ON CONFLICT DO NOTHING;
INSERT INTO ujani_control.model_inventory_policies
 (tenant_id,policy_version,revision,enabled,max_age_ms,updated_by_subject_id)
VALUES ('inventory-test','inventory-policy-v1',1,true,900000,'inventory-admin')
ON CONFLICT (tenant_id) DO UPDATE SET
 policy_version=EXCLUDED.policy_version,
 revision=ujani_control.model_inventory_policies.revision+1,
 enabled=true,max_age_ms=EXCLUDED.max_age_ms,
 updated_by_subject_id=EXCLUDED.updated_by_subject_id;

-- Earlier integration tests temporarily broaden ujani_runtime. Reset it before
-- proving this inventory transaction works with a narrowly scoped service role.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA ujani_control FROM ujani_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ujani_control FROM ujani_runtime;
REVOKE ALL ON SCHEMA ujani_control FROM ujani_runtime;
REVOKE ALL ON FUNCTION ujani_control.accept_model_runtime_inventory_v2(
 text,text,text,bigint,bigint,bytea,timestamptz,bigint,text,bytea,jsonb,uuid
) FROM PUBLIC,ujani_runtime;
GRANT USAGE ON SCHEMA ujani_control TO ujani_runtime;
GRANT SELECT ON ujani_control.devices,ujani_control.device_keys,
 ujani_control.device_owner_bindings,ujani_control.owner_consents,
 ujani_control.operator_subjects,ujani_control.model_inventory_policies,
 ujani_control.device_model_inventory,ujani_control.request_replays,
 ujani_control.audit_events TO ujani_runtime;
GRANT UPDATE (admission_lock_marker) ON ujani_control.device_keys,
 ujani_control.owner_consents,ujani_control.operator_subjects,
 ujani_control.device_owner_bindings TO ujani_runtime;
GRANT UPDATE (model_inventory_revision,updated_at) ON ujani_control.devices TO ujani_runtime;
GRANT INSERT,SELECT ON ujani_control.request_replays TO ujani_runtime;
GRANT INSERT,SELECT ON ujani_control.audit_events TO ujani_runtime;
GRANT INSERT,UPDATE ON ujani_control.device_model_inventory TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.accept_model_runtime_inventory_v2(
 text,text,text,bigint,bigint,bytea,timestamptz,bigint,text,bytea,jsonb,uuid
) TO ujani_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA ujani_control TO ujani_runtime;

SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint;
 v_future_now_ms bigint;
 v_payload jsonb;
 v_revision bigint;
 v_count integer;
BEGIN
 IF has_table_privilege(current_user,'ujani_control.model_inventory_policies','INSERT')
    OR has_table_privilege(current_user,'ujani_control.model_inventory_policies','UPDATE')
    OR has_table_privilege(current_user,'ujani_control.model_inventory_policies','DELETE')
    OR has_table_privilege(current_user,'ujani_control.device_model_inventory','DELETE')
    OR has_column_privilege(current_user,'ujani_control.devices','trust_state','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.devices','owner_consent_state','UPDATE')
    OR has_column_privilege(current_user,'ujani_control.devices','admin_approval_state','UPDATE')
 THEN
  RAISE EXCEPTION 'runtime role can mutate inventory policy, delete inventory, or alter trust/consent';
 END IF;
 IF NOT has_column_privilege(current_user,'ujani_control.devices','model_inventory_revision','UPDATE') THEN
  RAISE EXCEPTION 'runtime role lacks the narrow model inventory revision update privilege';
 END IF;

 v_now_ms := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,
  'generated_at_unix_ms',v_now_ms,
  'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled',
   'owner_consent','granted',
   'organisation_authorisation','authorised',
   'policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),
  'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),
  'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,
   'contains_user_files',false,
   'contains_local_paths',false,
   'contains_credentials',false
  )
 );

 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('b1',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('b2',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000301'
 );
 IF v_revision IS DISTINCT FROM 1 THEN
  RAISE EXCEPTION 'valid dual-consented model inventory was not committed';
 END IF;

 -- Reusing a request ID with a newer body must still be rejected as replay.
 v_payload := pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms+1000));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('b1',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms+1000,'inventory-policy-v1',decode(repeat('b3',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000302'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'replayed model inventory request was accepted'; END IF;

 -- The same generated timestamp with a fresh request ID is still stale.
 v_payload := pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('b4',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('b5',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000303'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'non-monotonic inventory timestamp was accepted'; END IF;

 -- Future observations use a fresh clock sample and remain well beyond the
 -- admission function's 60-second future-skew allowance.
 v_future_now_ms := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint + 120000;
 v_payload := pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_future_now_ms));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('b6',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_future_now_ms,'inventory-policy-v1',decode(repeat('b7',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000304'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'future-dated model inventory was accepted'; END IF;

 v_payload := pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms-901000));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('b8',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms-901000,'inventory-policy-v1',decode(repeat('b9',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000305'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'stale model inventory was accepted'; END IF;

 -- The descriptor's own policy claim is not authority; it must match current admin policy.
 v_payload := pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms+1000));
 v_payload := pg_catalog.jsonb_set(v_payload,'{collection_context,policy_version}',pg_catalog.to_jsonb('inventory-policy-v2'::text));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('ba',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms+1000,'inventory-policy-v2',decode(repeat('bb',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000306'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'unapproved policy version was accepted'; END IF;

 v_payload := pg_catalog.jsonb_set(v_payload,'{collection_context,policy_version}',pg_catalog.to_jsonb('inventory-policy-v1'::text));
 v_payload := pg_catalog.jsonb_set(v_payload,'{privacy,contains_prompts}',pg_catalog.to_jsonb(true));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('bc',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms+1000,'inventory-policy-v1',decode(repeat('bd',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000307'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'inventory claiming prompt collection was accepted'; END IF;

 v_payload := pg_catalog.jsonb_set(v_payload,'{privacy,contains_prompts}',pg_catalog.to_jsonb(false));
 v_payload := pg_catalog.jsonb_set(v_payload,'{device_ref}',pg_catalog.to_jsonb('spoofed-device'::text));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('be',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms+1000,'inventory-policy-v1',decode(repeat('bf',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000308'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'spoofed inventory device reference was accepted'; END IF;

 v_payload := pg_catalog.jsonb_set(v_payload,'{device_ref}',pg_catalog.to_jsonb('inventory-device'::text));
 v_payload := pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms+1000));
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',2,1,
  decode(repeat('c1',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms+1000,'inventory-policy-v1',decode(repeat('c2',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000309'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'stale device key generation was accepted'; END IF;

 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'another-tenant','inventory-device','inventory-key',1,1,
  decode(repeat('c3',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms+1000,'inventory-policy-v1',decode(repeat('c4',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000310'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'cross-tenant model inventory was accepted'; END IF;

 -- A successful call followed by a caller rollback must restore replay, snapshot,
 -- device revision and audit together.
 BEGIN
  v_revision := ujani_control.accept_model_runtime_inventory_v2(
   'inventory-test','inventory-device','inventory-key',1,1,
   decode(repeat('c5',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
   v_now_ms+2000,'inventory-policy-v1',decode(repeat('c6',32),'hex'),
   pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms+2000)),
   '00000000-0000-4000-8000-000000000311'
  );
  IF v_revision IS DISTINCT FROM 2 THEN
   RAISE EXCEPTION 'fresh inventory was not accepted before rollback';
  END IF;
  RAISE EXCEPTION 'rollback sentinel';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM <> 'rollback sentinel' THEN RAISE; END IF;
 END;

 SELECT model_inventory_revision INTO v_count
 FROM ujani_control.devices
 WHERE tenant_id='inventory-test' AND device_id='inventory-device';
 IF v_count <> 1 THEN RAISE EXCEPTION 'caller rollback did not restore inventory revision'; END IF;
 IF EXISTS (SELECT 1 FROM ujani_control.request_replays
            WHERE tenant_id='inventory-test' AND device_id='inventory-device'
              AND request_id=decode(repeat('c5',16),'hex')) THEN
  RAISE EXCEPTION 'caller rollback left an inventory replay claim';
 END IF;

 -- A late audit uniqueness failure must also roll back the replay and snapshot.
 BEGIN
  PERFORM ujani_control.accept_model_runtime_inventory_v2(
   'inventory-test','inventory-device','inventory-key',1,1,
   decode(repeat('c7',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
   v_now_ms+3000,'inventory-policy-v1',decode(repeat('c8',32),'hex'),
   pg_catalog.jsonb_set(v_payload,'{generated_at_unix_ms}',pg_catalog.to_jsonb(v_now_ms+3000)),
   '00000000-0000-4000-8000-000000000301'
  );
  RAISE EXCEPTION 'duplicate inventory audit event unexpectedly committed';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;
 IF EXISTS (SELECT 1 FROM ujani_control.request_replays
            WHERE tenant_id='inventory-test' AND device_id='inventory-device'
              AND request_id=decode(repeat('c7',16),'hex')) THEN
  RAISE EXCEPTION 'late audit failure left an inventory replay claim';
 END IF;
 SELECT count(*) INTO v_count FROM ujani_control.device_model_inventory
 WHERE tenant_id='inventory-test' AND device_id='inventory-device';
 IF v_count <> 1 THEN RAISE EXCEPTION 'late audit failure left partial inventory state'; END IF;
END;
$block$;
RESET ROLE;

-- A disabled policy or device-level organisation denial blocks new inventory.
UPDATE ujani_control.model_inventory_policies
 SET enabled=false,revision=revision+1,updated_by_subject_id='inventory-admin'
 WHERE tenant_id='inventory-test';
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('d1',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('d2',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000312'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'disabled organisation inventory policy was accepted'; END IF;
END;
$block$;
RESET ROLE;

DO $block$
BEGIN
 IF (SELECT visibility_state FROM ujani_control.device_model_inventory
     WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS DISTINCT FROM 'revoked'
    OR (SELECT inventory FROM ujani_control.device_model_inventory
        WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS NOT NULL THEN
  RAISE EXCEPTION 'policy update did not invalidate the stored model inventory';
 END IF;
END;
$block$;

UPDATE ujani_control.model_inventory_policies
 SET enabled=true,revision=revision+1,updated_by_subject_id='inventory-admin'
 WHERE tenant_id='inventory-test';

-- A fresh report under the new policy revision restores visibility.
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 SELECT GREATEST(
  floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint,
  COALESCE(
   (SELECT generated_at_unix_ms + 1
    FROM ujani_control.device_model_inventory
    WHERE tenant_id='inventory-test' AND device_id='inventory-device'),
   1
  )
 ) INTO v_now_ms;
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('da',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('db',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000316'
 );
 IF v_revision IS DISTINCT FROM 2 THEN
  RAISE EXCEPTION 'fresh inventory under the new policy was not accepted';
 END IF;
END;
$block$;
RESET ROLE;

-- The revocation fast path must not move a still-visible snapshot to another device.
-- Both devices deliberately have the same key ID so the foreign key cannot mask
-- the trigger's tenant/device identity check.
SET LOCAL ROLE ujani_runtime;
DO $block$
BEGIN
 BEGIN
  UPDATE ujani_control.device_model_inventory
  SET device_id='inventory-device-other',visibility_state='revoked',inventory=NULL
  WHERE tenant_id='inventory-test' AND device_id='inventory-device';
  RAISE EXCEPTION 'visible inventory revocation changed device identity';
 EXCEPTION WHEN check_violation THEN
  NULL;
 END;
END;
$block$;
RESET ROLE;

UPDATE ujani_control.devices SET admin_approval_state='rejected'
 WHERE tenant_id='inventory-test' AND device_id='inventory-device';
DO $block$
BEGIN
 IF (SELECT visibility_state FROM ujani_control.device_model_inventory
     WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS DISTINCT FROM 'revoked'
    OR (SELECT inventory FROM ujani_control.device_model_inventory
        WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS NOT NULL THEN
  RAISE EXCEPTION 'organisation denial did not hide stored model inventory';
 END IF;
END;
$block$;
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('d3',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('d4',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000313'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'organisation device approval denial was accepted'; END IF;
END;
$block$;
RESET ROLE;

-- A signed owner pause advances consent generation and blocks subsequent intake.
UPDATE ujani_control.devices SET admin_approval_state='approved'
 WHERE tenant_id='inventory-test' AND device_id='inventory-device';

-- Re-establish a fresh, visible descriptor before exercising owner opt-out.
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 SELECT GREATEST(
  floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint,
  COALESCE(
   (SELECT generated_at_unix_ms + 1
    FROM ujani_control.device_model_inventory
    WHERE tenant_id='inventory-test' AND device_id='inventory-device'),
   1
  )
 ) INTO v_now_ms;
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,1,
  decode(repeat('dc',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('dd',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000317'
 );
 IF v_revision IS DISTINCT FROM 3 THEN
  RAISE EXCEPTION 'fresh inventory before owner pause was not accepted';
 END IF;
END;
$block$;
RESET ROLE;

INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('inventory-test','inventory-device',2,'paused','inventory-owner',decode(repeat('d5',32),'hex'));
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,2,
  decode(repeat('d6',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('d7',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000314'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'paused owner consent was accepted'; END IF;
 IF (SELECT visibility_state FROM ujani_control.device_model_inventory
     WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS DISTINCT FROM 'revoked'
    OR (SELECT inventory FROM ujani_control.device_model_inventory
        WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS NOT NULL THEN
  RAISE EXCEPTION 'owner consent pause did not clear the stored model inventory';
 END IF;

END;
$block$;

RESET ROLE;

-- Rebinding a device to another owner must hide the previous owner's inventory.
-- The replacement owner must provide a fresh, generation-bound opt-in.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('inventory-test','inventory-device',3,'granted','inventory-owner',decode(repeat('e1',32),'hex'));
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 SELECT GREATEST(
  v_now_ms,
  COALESCE(
   (SELECT generated_at_unix_ms + 1
    FROM ujani_control.device_model_inventory
    WHERE tenant_id='inventory-test' AND device_id='inventory-device'),
   1
  )
 ) INTO v_now_ms;
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,3,
  decode(repeat('e2',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('e3',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000318'
 );
 IF v_revision IS DISTINCT FROM 4 THEN
  RAISE EXCEPTION 'fresh inventory before owner rebinding was not accepted';
 END IF;
END;
$block$;
RESET ROLE;

UPDATE ujani_control.device_owner_bindings
 SET owner_subject_id='inventory-owner-2',
     binding_revision=binding_revision+1,
     binding_digest=decode(repeat('e4',32),'hex')
 WHERE tenant_id='inventory-test' AND device_id='inventory-device';
DO $block$
BEGIN
 IF (SELECT owner_consent_state FROM ujani_control.devices
     WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS DISTINCT FROM 'unknown' THEN
  RAISE EXCEPTION 'owner binding replacement did not clear the device consent state';
 END IF;
 IF (SELECT visibility_state FROM ujani_control.device_model_inventory
     WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS DISTINCT FROM 'revoked'
    OR (SELECT inventory FROM ujani_control.device_model_inventory
        WHERE tenant_id='inventory-test' AND device_id='inventory-device') IS NOT NULL THEN
  RAISE EXCEPTION 'owner binding replacement must invalidate the previous owner inventory';
 END IF;
END;
$block$;

-- The old owner's consent generation cannot be reused after the owner changes.
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 SELECT GREATEST(
  v_now_ms,
  COALESCE(
   (SELECT generated_at_unix_ms + 1
    FROM ujani_control.device_model_inventory
    WHERE tenant_id='inventory-test' AND device_id='inventory-device'),
   1
  )
 ) INTO v_now_ms;
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,3,
  decode(repeat('e5',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('e6',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000319'
 );
 IF v_revision IS NOT NULL THEN
  RAISE EXCEPTION 'previous owner consent was reused after owner binding replacement';
 END IF;
END;
$block$;
RESET ROLE;

-- A fresh opt-in by the newly bound owner restores visibility only after a new report.
INSERT INTO ujani_control.owner_consents
 (tenant_id,device_id,consent_generation,state,actor_ref,evidence_digest)
VALUES
 ('inventory-test','inventory-device',4,'granted','inventory-owner-2',decode(repeat('e7',32),'hex'));
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE
 v_now_ms bigint := floor(extract(epoch FROM pg_catalog.clock_timestamp()) * 1000)::bigint;
 v_payload jsonb;
 v_revision bigint;
BEGIN
 SELECT GREATEST(
  v_now_ms,
  COALESCE(
   (SELECT generated_at_unix_ms + 1
    FROM ujani_control.device_model_inventory
    WHERE tenant_id='inventory-test' AND device_id='inventory-device'),
   1
  )
 ) INTO v_now_ms;
 v_payload := pg_catalog.jsonb_build_object(
  'schema_version',2,'generated_at_unix_ms',v_now_ms,'device_ref','inventory-device',
  'collection_context',pg_catalog.jsonb_build_object(
   'scope','organisation_enrolled','owner_consent','granted',
   'organisation_authorisation','authorised','policy_version','inventory-policy-v1'
  ),
  'platform',pg_catalog.jsonb_build_object(),'hardware',pg_catalog.jsonb_build_object(),
  'runtimes',pg_catalog.jsonb_build_array(),'models',pg_catalog.jsonb_build_array(),
  'privacy',pg_catalog.jsonb_build_object(
   'contains_prompts',false,'contains_user_files',false,
   'contains_local_paths',false,'contains_credentials',false
  )
 );
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,4,
  decode(repeat('e8',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  v_now_ms,'inventory-policy-v1',decode(repeat('e9',32),'hex'),v_payload,
  '00000000-0000-4000-8000-000000000320'
 );
 IF v_revision IS DISTINCT FROM 5 THEN
  RAISE EXCEPTION 'new owner fresh opt-in did not restore inventory visibility';
 END IF;
END;
$block$;
RESET ROLE;

-- Tenant context is mandatory for reads and writes.
SELECT pg_catalog.set_config('ujani.tenant_id','tenant-b',true);
SET LOCAL ROLE ujani_runtime;
DO $block$
DECLARE visible_rows integer;
 v_revision bigint;
BEGIN
 SELECT count(*) INTO visible_rows FROM ujani_control.device_model_inventory;
 IF visible_rows <> 0 THEN RAISE EXCEPTION 'model inventory leaked across tenant RLS'; END IF;
 v_revision := ujani_control.accept_model_runtime_inventory_v2(
  'inventory-test','inventory-device','inventory-key',1,2,
  decode(repeat('d8',16),'hex'),pg_catalog.clock_timestamp()+interval '20 seconds',
  floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint,
  'inventory-policy-v1',decode(repeat('d9',32),'hex'),
  pg_catalog.jsonb_build_object(),'00000000-0000-4000-8000-000000000315'
 );
 IF v_revision IS NOT NULL THEN RAISE EXCEPTION 'cross-tenant context accepted model inventory'; END IF;
END;
$block$;
RESET ROLE;
-- A disabled administrator cannot revise the organisation model-inventory policy.
-- The policy trigger must reject the write and leave its revision unchanged.
SELECT pg_catalog.set_config('ujani.tenant_id','inventory-test',true);
UPDATE ujani_control.operator_subjects
 SET enabled=false
 WHERE tenant_id='inventory-test' AND subject_id='inventory-admin';
DO $block$
DECLARE
 v_before bigint;
 v_after bigint;
BEGIN
 SELECT revision INTO v_before
 FROM ujani_control.model_inventory_policies
 WHERE tenant_id='inventory-test';
 BEGIN
  UPDATE ujani_control.model_inventory_policies
  SET revision=revision+1,updated_by_subject_id='inventory-admin'
  WHERE tenant_id='inventory-test';
  RAISE EXCEPTION 'disabled administrator unexpectedly changed model inventory policy';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
 SELECT revision INTO v_after
 FROM ujani_control.model_inventory_policies
 WHERE tenant_id='inventory-test';
 IF v_after IS DISTINCT FROM v_before THEN
  RAISE EXCEPTION 'rejected disabled-administrator policy write changed the policy revision';
 END IF;
END;
$block$;
UPDATE ujani_control.operator_subjects
 SET enabled=true
 WHERE tenant_id='inventory-test' AND subject_id='inventory-admin';

ROLLBACK;
