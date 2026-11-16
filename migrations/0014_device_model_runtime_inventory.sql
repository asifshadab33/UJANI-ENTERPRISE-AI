-- Persist the latest privacy-minimised model/runtime inventory for each
-- enrolled device. The Rust service boundary verifies the exact signed body and
-- JSON Schema; this SECURITY INVOKER function rechecks current trust, key,
-- owner binding, owner opt-in and administrator approval in the same transaction
-- as replay claim, revision increment, snapshot write and audit receipt.
-- This stores metadata only. It does not install, select, download or dispatch models.

ALTER TABLE ujani_control.devices
 ADD COLUMN IF NOT EXISTS model_inventory_revision bigint NOT NULL DEFAULT 0
 CHECK (model_inventory_revision >= 0);

CREATE TABLE IF NOT EXISTS ujani_control.device_model_runtime_inventories (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 inventory_revision bigint NOT NULL CHECK (inventory_revision > 0),
 device_key_generation bigint NOT NULL CHECK (device_key_generation > 0),
 consent_generation bigint NOT NULL CHECK (consent_generation > 0),
 generated_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
 payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
 inventory jsonb NOT NULL CHECK (
  jsonb_typeof(inventory) = 'object'
  AND octet_length(inventory::text) <= 1048576
 ),
 PRIMARY KEY (tenant_id, device_id),
 UNIQUE (tenant_id, device_id, request_id),
 FOREIGN KEY (tenant_id, device_id)
  REFERENCES ujani_control.devices(tenant_id, device_id)
);

ALTER TABLE ujani_control.device_model_runtime_inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.device_model_runtime_inventories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.device_model_runtime_inventories;
CREATE POLICY tenant_isolation ON ujani_control.device_model_runtime_inventories
 USING (tenant_id = current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = current_setting('ujani.tenant_id', true));

-- An owner pause/withdrawal, trust revocation, administrator-approval
-- revocation or key-generation change removes the previously shared inventory.
-- The server-side revision counter remains monotonic across this purge.
CREATE OR REPLACE FUNCTION ujani_control.purge_device_model_runtime_inventory_on_device_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 IF NEW.trust_state IS DISTINCT FROM 'enrolled'
    OR NEW.owner_consent_state IS DISTINCT FROM 'granted'
    OR NEW.admin_approval_state IS DISTINCT FROM 'approved'
    OR NEW.key_generation IS DISTINCT FROM OLD.key_generation THEN
  DELETE FROM ujani_control.device_model_runtime_inventories
   WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id;
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS devices_purge_model_runtime_inventory ON ujani_control.devices;
CREATE TRIGGER devices_purge_model_runtime_inventory
 AFTER UPDATE OF trust_state, owner_consent_state, admin_approval_state, key_generation
 ON ujani_control.devices
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.purge_device_model_runtime_inventory_on_device_change();

-- An owner binding change or disabling the bound owner also removes the
-- snapshot, rather than leaving previously shared model metadata visible.
CREATE OR REPLACE FUNCTION ujani_control.purge_device_model_runtime_inventory_on_owner_binding_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_id text;
 v_device_id text;
BEGIN
 IF TG_OP = 'DELETE' THEN
  v_tenant_id := OLD.tenant_id;
  v_device_id := OLD.device_id;
 ELSE
  v_tenant_id := NEW.tenant_id;
  v_device_id := NEW.device_id;
 END IF;
 DELETE FROM ujani_control.device_model_runtime_inventories
  WHERE tenant_id = v_tenant_id AND device_id = v_device_id;
 IF TG_OP = 'DELETE' THEN
  RETURN OLD;
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS device_owner_bindings_purge_model_runtime_inventory
 ON ujani_control.device_owner_bindings;
CREATE TRIGGER device_owner_bindings_purge_model_runtime_inventory
 AFTER UPDATE OR DELETE ON ujani_control.device_owner_bindings
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.purge_device_model_runtime_inventory_on_owner_binding_change();

CREATE OR REPLACE FUNCTION ujani_control.purge_model_runtime_inventory_for_disabled_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 IF NEW.enabled IS DISTINCT FROM OLD.enabled AND NEW.enabled IS DISTINCT FROM true THEN
  DELETE FROM ujani_control.device_model_runtime_inventories i
   USING ujani_control.device_owner_bindings b
   WHERE b.tenant_id = NEW.tenant_id
     AND b.owner_subject_id = NEW.subject_id
     AND b.active IS TRUE
     AND i.tenant_id = b.tenant_id
     AND i.device_id = b.device_id;
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS operator_subjects_purge_model_runtime_inventory
 ON ujani_control.operator_subjects;
CREATE TRIGGER operator_subjects_purge_model_runtime_inventory
 AFTER UPDATE OF enabled ON ujani_control.operator_subjects
 FOR EACH ROW
 EXECUTE FUNCTION ujani_control.purge_model_runtime_inventory_for_disabled_owner();

CREATE OR REPLACE FUNCTION ujani_control.accept_device_model_runtime_inventory(
 p_tenant_id text,
 p_device_id text,
 p_device_key_generation bigint,
 p_request_id bytea,
 p_payload_digest bytea,
 p_generated_at timestamptz,
 p_inventory jsonb
) RETURNS bigint
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_owner_subject_id text;
 v_previous_generated_at timestamptz;
 v_inserted_request_id bytea;
 v_generated_at_ms numeric;
 v_now timestamptz;
 v_revision bigint;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true)
    OR p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_request_id IS NULL OR octet_length(p_request_id) <> 16
    OR p_payload_digest IS NULL OR octet_length(p_payload_digest) <> 32
    OR p_generated_at IS NULL
    OR p_inventory IS NULL
    OR jsonb_typeof(p_inventory) IS DISTINCT FROM 'object'
    OR octet_length(p_inventory::text) > 1048576
    OR NOT (p_inventory ?& ARRAY[
      'schema_version','generated_at_unix_ms','platform','hardware','runtimes','models'
    ])
    OR p_inventory->>'schema_version' IS DISTINCT FROM '1'
    OR jsonb_typeof(p_inventory->'generated_at_unix_ms') IS DISTINCT FROM 'number'
    OR jsonb_typeof(p_inventory->'platform') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_inventory->'hardware') IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_inventory->'runtimes') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_inventory->'models') IS DISTINCT FROM 'array'
    OR NOT ((p_inventory->'platform') ?& ARRAY['os','architecture'])
    OR NOT ((p_inventory->'hardware') ?& ARRAY[
      'cpu_logical_cores','memory_total_mb','memory_available_mb','accelerators'
    ])
    OR jsonb_typeof(p_inventory->'hardware'->'accelerators') IS DISTINCT FROM 'array'
    OR jsonb_array_length(p_inventory->'hardware'->'accelerators') > 32
    OR jsonb_array_length(p_inventory->'runtimes') > 16
    OR jsonb_array_length(p_inventory->'models') > 512 THEN
  RETURN NULL;
 END IF;

 v_generated_at_ms := (p_inventory->>'generated_at_unix_ms')::numeric;
 IF v_generated_at_ms <= 0
    OR v_generated_at_ms <> trunc(v_generated_at_ms)
    OR abs(extract(epoch FROM (
      p_generated_at - to_timestamp(v_generated_at_ms::double precision / 1000.0)
    ))) > 0.001 THEN
  RETURN NULL;
 END IF;

 IF p_inventory ? 'device_ref'
    AND p_inventory->'device_ref' IS DISTINCT FROM 'null'::jsonb
    AND p_inventory->>'device_ref' IS DISTINCT FROM p_device_id THEN
  RETURN NULL;
 END IF;

 IF p_inventory ? 'privacy' THEN
  IF jsonb_typeof(p_inventory->'privacy') IS DISTINCT FROM 'object'
     OR EXISTS (
       SELECT 1
       FROM jsonb_each(p_inventory->'privacy') AS privacy_item
       WHERE privacy_item.key NOT IN (
         'contains_prompts','contains_user_files','contains_local_paths','contains_credentials'
       )
       OR privacy_item.value IS DISTINCT FROM 'false'::jsonb
     ) THEN
   RETURN NULL;
  END IF;
 END IF;

 IF EXISTS (
   SELECT 1
   FROM jsonb_array_elements(p_inventory->'hardware'->'accelerators') AS accelerator(value)
   WHERE jsonb_typeof(accelerator.value) IS DISTINCT FROM 'object'
      OR NOT (accelerator.value ?& ARRAY['kind','vendor','evidence'])
      OR jsonb_typeof(accelerator.value->'evidence') IS DISTINCT FROM 'object'
      OR NOT ((accelerator.value->'evidence') ?& ARRAY[
        'source','confidence','observed_at_unix_ms'
      ])
 ) OR EXISTS (
   SELECT 1
   FROM jsonb_array_elements(p_inventory->'runtimes') AS runtime(value)
   WHERE jsonb_typeof(runtime.value) IS DISTINCT FROM 'object'
      OR NOT (runtime.value ?& ARRAY[
        'runtime_id','provider','version','availability','network_scope','evidence'
      ])
      OR jsonb_typeof(runtime.value->'evidence') IS DISTINCT FROM 'object'
      OR NOT ((runtime.value->'evidence') ?& ARRAY[
        'source','confidence','observed_at_unix_ms'
      ])
 ) OR EXISTS (
   SELECT 1
   FROM jsonb_array_elements(p_inventory->'models') AS model(value)
   WHERE jsonb_typeof(model.value) IS DISTINCT FROM 'object'
      OR NOT (model.value ?& ARRAY[
        'model_ref','runtime_id','display_name','availability','size_bytes','capabilities','evidence'
      ])
      OR jsonb_typeof(model.value->'capabilities') IS DISTINCT FROM 'array'
      OR jsonb_array_length(model.value->'capabilities') > 16
      OR jsonb_typeof(model.value->'evidence') IS DISTINCT FROM 'object'
      OR NOT ((model.value->'evidence') ?& ARRAY[
        'source','confidence','observed_at_unix_ms'
      ])
 ) THEN
  RETURN NULL;
 END IF;

 v_now := clock_timestamp();
 IF p_generated_at < v_now - interval '15 minutes'
    OR p_generated_at > v_now + interval '30 seconds' THEN
  RETURN NULL;
 END IF;

 -- Lock the device before reading trust, key, consent and owner binding. The
 -- owner-consent trigger and key/trust updates serialize on this same row.
 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND
    OR v_device.trust_state <> 'enrolled'
    OR v_device.owner_consent_state <> 'granted'
    OR v_device.admin_approval_state <> 'approved'
    OR v_device.active_key_id IS NULL
    OR v_device.key_generation <> p_device_key_generation
    OR v_device.consent_generation <= 0
    OR v_device.model_inventory_revision >= 9007199254740991 THEN
  RETURN NULL;
 END IF;

 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND active IS TRUE;
 IF NOT FOUND THEN RETURN NULL; END IF;

 PERFORM 1 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id
   AND subject_id = v_owner_subject_id
   AND enabled IS TRUE
 FOR SHARE;
 IF NOT FOUND THEN RETURN NULL; END IF;

 PERFORM 1 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND consent_generation = v_device.consent_generation
   AND state = 'granted'
   AND actor_ref = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND THEN RETURN NULL; END IF;

 PERFORM 1 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id
   AND device_id = p_device_id
   AND key_id = v_device.active_key_id
   AND generation = p_device_key_generation
   AND state = 'active'
   AND valid_from <= v_now
   AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN RETURN NULL; END IF;

 -- Recheck freshness after all authorization locks; a lock wait must not
 -- extend the inventory's acceptance window.
 v_now := clock_timestamp();
 IF p_generated_at < v_now - interval '15 minutes'
    OR p_generated_at > v_now + interval '30 seconds' THEN
  RETURN NULL;
 END IF;

 SELECT generated_at INTO v_previous_generated_at
 FROM ujani_control.device_model_runtime_inventories
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF FOUND AND p_generated_at <= v_previous_generated_at THEN
  RETURN NULL;
 END IF;

 INSERT INTO ujani_control.request_replays
  (tenant_id,device_id,request_id,expires_at,operation_digest)
 VALUES
  (p_tenant_id,p_device_id,p_request_id,v_now + interval '10 minutes',p_payload_digest)
 ON CONFLICT (tenant_id,device_id,request_id) DO NOTHING
 RETURNING request_id INTO v_inserted_request_id;
 IF v_inserted_request_id IS NULL THEN
  RETURN NULL;
 END IF;

 v_revision := v_device.model_inventory_revision + 1;
 UPDATE ujani_control.devices
 SET model_inventory_revision = v_revision,
     updated_at = v_now
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;

 INSERT INTO ujani_control.device_model_runtime_inventories
  (tenant_id,device_id,inventory_revision,device_key_generation,consent_generation,
   generated_at,received_at,request_id,payload_digest,inventory)
 VALUES
  (p_tenant_id,p_device_id,v_revision,p_device_key_generation,v_device.consent_generation,
   p_generated_at,v_now,p_request_id,p_payload_digest,p_inventory)
 ON CONFLICT (tenant_id,device_id) DO UPDATE SET
  inventory_revision = EXCLUDED.inventory_revision,
  device_key_generation = EXCLUDED.device_key_generation,
  consent_generation = EXCLUDED.consent_generation,
  generated_at = EXCLUDED.generated_at,
  received_at = EXCLUDED.received_at,
  request_id = EXCLUDED.request_id,
  payload_digest = EXCLUDED.payload_digest,
  inventory = EXCLUDED.inventory;

 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (p_tenant_id,gen_random_uuid(),p_device_id,'device',
   'device.model_runtime_inventory.updated',
   'accepted:' || left(encode(p_payload_digest,'hex'),16),
   p_device_id);

 RETURN v_revision;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.accept_device_model_runtime_inventory(
 text,text,bigint,bytea,bytea,timestamptz,jsonb
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION ujani_control.list_device_model_runtime_inventory(
 p_device_id text DEFAULT NULL,
 p_limit integer DEFAULT 100
)
RETURNS TABLE (
 tenant_id text,
 device_id text,
 inventory_revision bigint,
 device_key_generation bigint,
 consent_generation bigint,
 generated_at timestamptz,
 received_at timestamptz,
 request_id bytea,
 payload_digest bytea,
 inventory jsonb
)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
 SELECT
  i.tenant_id,
  i.device_id,
  i.inventory_revision,
  i.device_key_generation,
  i.consent_generation,
  i.generated_at,
  i.received_at,
  i.request_id,
  i.payload_digest,
  i.inventory
 FROM ujani_control.device_model_runtime_inventories i
 JOIN ujani_control.devices d
  ON d.tenant_id = i.tenant_id AND d.device_id = i.device_id
 WHERE i.tenant_id = pg_catalog.current_setting('ujani.tenant_id', true)
   AND (p_device_id IS NULL OR i.device_id = p_device_id)
   AND d.trust_state = 'enrolled'
   AND d.owner_consent_state = 'granted'
   AND d.admin_approval_state = 'approved'
   AND d.key_generation = i.device_key_generation
   AND d.consent_generation = i.consent_generation
 ORDER BY i.received_at DESC, i.device_id
 LIMIT LEAST(GREATEST(COALESCE(p_limit,100),1),200);
$function$;

REVOKE ALL ON FUNCTION ujani_control.list_device_model_runtime_inventory(text,integer)
 FROM PUBLIC;

COMMENT ON TABLE ujani_control.device_model_runtime_inventories IS
 'Latest tenant-scoped, owner-consented model/runtime capability snapshot per enrolled device. Contains no prompts, model contents, local paths, credentials or user files. One row per device bounds storage; audit_events retains update receipts.';

COMMENT ON FUNCTION ujani_control.accept_device_model_runtime_inventory(
 text,text,bigint,bytea,bytea,timestamptz,jsonb
) IS
 'SECURITY INVOKER model/runtime inventory intake. Caller verifies the exact device signature and raw-body digest. Rechecks enrolled trust, active key generation, administrator approval, active owner binding and current owner consent under the device row lock; atomically claims replay ID, advances a server-side revision, stores only the latest bounded metadata snapshot and appends an audit receipt. Returns NULL on policy rejection. No inference, model installation or dispatch.';

COMMENT ON FUNCTION ujani_control.list_device_model_runtime_inventory(text,integer) IS
 'SECURITY INVOKER tenant-scoped read-only operator query. Returns at most 200 current-consent snapshots with server revision and evidence timestamps; callers determine stale/unknown capability status from generated_at and received_at.';
