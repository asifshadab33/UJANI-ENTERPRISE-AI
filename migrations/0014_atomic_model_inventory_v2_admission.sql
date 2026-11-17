-- Atomic post-authentication persistence for Enterprise model/runtime inventory v2.
-- The HTTP adapter MUST verify the exact raw device signature and run the complete
-- Draft 2020-12 schema validator before calling this SECURITY INVOKER function.
-- This migration rechecks tenant, current device/key/owner/admin/policy state,
-- freshness and replay while persisting the latest bounded descriptor and audit
-- receipt in one transaction. It never authorises workload execution or dispatch.

ALTER TABLE ujani_control.devices
 ADD COLUMN IF NOT EXISTS model_inventory_revision bigint NOT NULL DEFAULT 0
 CHECK (model_inventory_revision BETWEEN 0 AND 9007199254740991);

CREATE TABLE IF NOT EXISTS ujani_control.model_inventory_policies (
 tenant_id text PRIMARY KEY REFERENCES ujani_control.tenants(tenant_id),
 policy_version text NOT NULL CHECK (policy_version ~ '^[A-Za-z0-9._:-]{1,128}$'),
 revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
 enabled boolean NOT NULL,
 max_age_ms bigint NOT NULL CHECK (max_age_ms BETWEEN 60000 AND 900000),
 updated_by_subject_id text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (tenant_id, updated_by_subject_id)
  REFERENCES ujani_control.operator_subjects(tenant_id, subject_id)
);
ALTER TABLE ujani_control.model_inventory_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.model_inventory_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.model_inventory_policies;
CREATE POLICY tenant_isolation ON ujani_control.model_inventory_policies
 USING (tenant_id = pg_catalog.current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = pg_catalog.current_setting('ujani.tenant_id', true));

-- Policy writers serialize with inventory acceptance and audit writers before
-- acquiring row locks. The authenticated tenant is taken only from session context.
CREATE OR REPLACE FUNCTION ujani_control.lock_model_inventory_policy_audit_chain()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_id text;
BEGIN
 v_tenant_id := pg_catalog.current_setting('ujani.tenant_id', true);
 IF v_tenant_id IS NULL OR v_tenant_id = '' THEN
  RAISE EXCEPTION 'authenticated tenant context is required for model inventory policy' USING ERRCODE = '42501';
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_tenant_id, 0));
 RETURN NULL;
END;
$function$;

DROP TRIGGER IF EXISTS model_inventory_policy_audit_lock ON ujani_control.model_inventory_policies;
CREATE TRIGGER model_inventory_policy_audit_lock
 BEFORE INSERT OR UPDATE ON ujani_control.model_inventory_policies
 FOR EACH STATEMENT EXECUTE FUNCTION ujani_control.lock_model_inventory_policy_audit_chain();

CREATE OR REPLACE FUNCTION ujani_control.validate_model_inventory_policy_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_admin_role text;
 v_admin_enabled boolean;
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true)
    OR NEW.tenant_id IS NULL OR NEW.tenant_id = '' THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 IF TG_OP = 'INSERT' THEN
  IF NEW.revision <> 1 THEN
   RAISE EXCEPTION 'initial model inventory policy revision must be one' USING ERRCODE = '23514';
  END IF;
 ELSE
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.revision <> OLD.revision + 1 THEN
   RAISE EXCEPTION 'model inventory policy revision must advance by exactly one' USING ERRCODE = '23514';
  END IF;
 END IF;
 SELECT role, enabled INTO v_admin_role, v_admin_enabled
 FROM ujani_control.operator_subjects
 WHERE tenant_id = NEW.tenant_id AND subject_id = NEW.updated_by_subject_id
 FOR SHARE;
 IF NOT FOUND OR v_admin_enabled IS DISTINCT FROM true OR v_admin_role <> 'administrator' THEN
  RAISE EXCEPTION 'model inventory policy requires an enabled administrator' USING ERRCODE = '42501';
 END IF;
 NEW.updated_at := pg_catalog.clock_timestamp();
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS model_inventory_policy_revision_validate ON ujani_control.model_inventory_policies;
CREATE TRIGGER model_inventory_policy_revision_validate
 BEFORE INSERT OR UPDATE ON ujani_control.model_inventory_policies
 FOR EACH ROW EXECUTE FUNCTION ujani_control.validate_model_inventory_policy_revision();

CREATE OR REPLACE FUNCTION ujani_control.audit_model_inventory_policy_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 -- A new policy revision invalidates every previously collected descriptor.
 -- Owners/devices must report again under the current administrator policy.
 IF TG_OP = 'UPDATE' THEN
  UPDATE ujani_control.device_model_inventory
  SET visibility_state = 'revoked', inventory = NULL, revoked_at = pg_catalog.clock_timestamp()
  WHERE tenant_id = NEW.tenant_id AND visibility_state = 'visible';
 END IF;
 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (NEW.tenant_id,pg_catalog.gen_random_uuid(),NEW.updated_by_subject_id,'administrator',
   'model_inventory.policy.changed',
   CASE WHEN NEW.enabled THEN 'enabled' ELSE 'disabled' END,
   'version=' || pg_catalog.left(NEW.policy_version,64)
   || ';revision=' || NEW.revision::text
   || ';max_age_ms=' || NEW.max_age_ms::text);
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS model_inventory_policy_audit ON ujani_control.model_inventory_policies;
CREATE TRIGGER model_inventory_policy_audit
 AFTER INSERT OR UPDATE ON ujani_control.model_inventory_policies
 FOR EACH ROW EXECUTE FUNCTION ujani_control.audit_model_inventory_policy_change();

CREATE OR REPLACE FUNCTION ujani_control.reject_model_inventory_policy_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 RAISE EXCEPTION 'model inventory policy history must be disabled or superseded, not deleted'
  USING ERRCODE = '42501';
END;
$function$;

DROP TRIGGER IF EXISTS model_inventory_policy_no_delete ON ujani_control.model_inventory_policies;
CREATE TRIGGER model_inventory_policy_no_delete
 BEFORE DELETE ON ujani_control.model_inventory_policies
 FOR EACH ROW EXECUTE FUNCTION ujani_control.reject_model_inventory_policy_delete();

CREATE TABLE IF NOT EXISTS ujani_control.device_model_inventory (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 inventory_revision bigint NOT NULL CHECK (inventory_revision BETWEEN 1 AND 9007199254740991),
 generated_at_unix_ms bigint NOT NULL CHECK (generated_at_unix_ms BETWEEN 1 AND 9007199254740991),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 device_key_id text NOT NULL,
 device_key_generation bigint NOT NULL CHECK (device_key_generation > 0),
 consent_generation bigint NOT NULL CHECK (consent_generation > 0),
 policy_revision bigint NOT NULL CHECK (policy_revision > 0),
 request_id bytea NOT NULL CHECK (pg_catalog.octet_length(request_id) = 16),
 payload_digest bytea NOT NULL CHECK (pg_catalog.octet_length(payload_digest) = 32),
 visibility_state text NOT NULL DEFAULT 'visible' CHECK (visibility_state IN ('visible','revoked')),
 revoked_at timestamptz,
 inventory jsonb,
 CHECK (
  (visibility_state = 'visible' AND inventory IS NOT NULL AND revoked_at IS NULL
   AND pg_catalog.jsonb_typeof(inventory) = 'object'
   AND pg_catalog.pg_column_size(inventory) <= 2097152)
  OR
  (visibility_state = 'revoked' AND inventory IS NULL AND revoked_at IS NOT NULL)
 ),
 PRIMARY KEY (tenant_id, device_id),
 UNIQUE (tenant_id, device_id, request_id),
 FOREIGN KEY (tenant_id, device_id)
  REFERENCES ujani_control.devices(tenant_id, device_id),
 FOREIGN KEY (tenant_id, device_id, device_key_id)
  REFERENCES ujani_control.device_keys(tenant_id, device_id, key_id)
);
CREATE INDEX IF NOT EXISTS device_model_inventory_received_idx
 ON ujani_control.device_model_inventory (tenant_id, received_at DESC);

ALTER TABLE ujani_control.device_model_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.device_model_inventory FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.device_model_inventory;
CREATE POLICY tenant_isolation ON ujani_control.device_model_inventory
 USING (tenant_id = pg_catalog.current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = pg_catalog.current_setting('ujani.tenant_id', true));

CREATE OR REPLACE FUNCTION ujani_control.validate_device_model_inventory_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device_revision bigint;
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;

 -- Consent, trust, key, administrator-policy or owner-binding changes may
 -- clear the current descriptor without advancing its evidence revision.
 IF TG_OP = 'UPDATE'
    AND OLD.visibility_state = 'visible'
    AND NEW.visibility_state = 'revoked'
    AND NEW.inventory IS NULL
    AND NEW.inventory_revision = OLD.inventory_revision
    AND NEW.generated_at_unix_ms = OLD.generated_at_unix_ms
    AND NEW.device_key_id = OLD.device_key_id
    AND NEW.device_key_generation = OLD.device_key_generation
    AND NEW.consent_generation = OLD.consent_generation
    AND NEW.policy_revision = OLD.policy_revision
    AND NEW.request_id = OLD.request_id
    AND NEW.payload_digest = OLD.payload_digest THEN
  NEW.revoked_at := pg_catalog.clock_timestamp();
  RETURN NEW;
 END IF;

 SELECT model_inventory_revision INTO v_device_revision
 FROM ujani_control.devices
 WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id;
 IF NOT FOUND OR NEW.inventory_revision <> v_device_revision + 1 THEN
  RAISE EXCEPTION 'model inventory revision is not the next device revision' USING ERRCODE = '23514';
 END IF;
 IF TG_OP = 'UPDATE' THEN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.device_id IS DISTINCT FROM OLD.device_id
     OR NEW.inventory_revision <> OLD.inventory_revision + 1
     OR NEW.generated_at_unix_ms <= OLD.generated_at_unix_ms
     OR NEW.request_id = OLD.request_id
     OR NEW.payload_digest = OLD.payload_digest
     OR NEW.visibility_state <> 'visible'
     OR NEW.revoked_at IS NOT NULL THEN
   RAISE EXCEPTION 'model inventory snapshot must advance monotonically' USING ERRCODE = '23514';
  END IF;
 END IF;
 IF NEW.visibility_state <> 'visible' OR NEW.revoked_at IS NOT NULL OR NEW.inventory IS NULL THEN
  RAISE EXCEPTION 'new model inventory revisions must be visible complete snapshots' USING ERRCODE = '23514';
 END IF;
 NEW.received_at := pg_catalog.clock_timestamp();
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS device_model_inventory_revision_validate ON ujani_control.device_model_inventory;
CREATE TRIGGER device_model_inventory_revision_validate
 BEFORE INSERT OR UPDATE ON ujani_control.device_model_inventory
 FOR EACH ROW EXECUTE FUNCTION ujani_control.validate_device_model_inventory_revision();

CREATE OR REPLACE FUNCTION ujani_control.reject_device_model_inventory_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 RAISE EXCEPTION 'current model inventory must be superseded, not deleted'
  USING ERRCODE = '42501';
END;
$function$;

DROP TRIGGER IF EXISTS device_model_inventory_no_delete ON ujani_control.device_model_inventory;
CREATE TRIGGER device_model_inventory_no_delete
 BEFORE DELETE ON ujani_control.device_model_inventory
 FOR EACH ROW EXECUTE FUNCTION ujani_control.reject_device_model_inventory_delete();

-- Remove the stored descriptor immediately when any current authority binding
-- changes. The audit event for the underlying trust/consent/admin operation
-- remains authoritative; a revoked snapshot retains only its digest and revision.
CREATE OR REPLACE FUNCTION ujani_control.invalidate_device_model_inventory_on_authority_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 IF NEW.trust_state IS DISTINCT FROM OLD.trust_state
    OR NEW.owner_consent_state IS DISTINCT FROM OLD.owner_consent_state
    OR NEW.admin_approval_state IS DISTINCT FROM OLD.admin_approval_state
    OR NEW.active_key_id IS DISTINCT FROM OLD.active_key_id
    OR NEW.key_generation IS DISTINCT FROM OLD.key_generation
    OR NEW.consent_generation IS DISTINCT FROM OLD.consent_generation THEN
  UPDATE ujani_control.device_model_inventory
  SET visibility_state = 'revoked', inventory = NULL, revoked_at = pg_catalog.clock_timestamp()
  WHERE tenant_id = NEW.tenant_id AND device_id = NEW.device_id
    AND visibility_state = 'visible';
 END IF;
 RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS device_model_inventory_authority_invalidate ON ujani_control.devices;
CREATE TRIGGER device_model_inventory_authority_invalidate
 AFTER UPDATE OF trust_state,owner_consent_state,admin_approval_state,active_key_id,key_generation,consent_generation
 ON ujani_control.devices
 FOR EACH ROW EXECUTE FUNCTION ujani_control.invalidate_device_model_inventory_on_authority_change();

CREATE OR REPLACE FUNCTION ujani_control.accept_model_runtime_inventory_v2(
 p_tenant_id text,
 p_device_id text,
 p_device_key_id text,
 p_device_key_generation bigint,
 p_consent_generation bigint,
 p_request_id bytea,
 p_request_expires_at timestamptz,
 p_generated_at_unix_ms bigint,
 p_policy_version text,
 p_payload_digest bytea,
 p_inventory jsonb,
 p_event_id uuid
) RETURNS bigint
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_device ujani_control.devices%ROWTYPE;
 v_policy ujani_control.model_inventory_policies%ROWTYPE;
 v_owner_subject_id text;
 v_admin_enabled boolean;
 v_admin_role text;
 v_owner_enabled boolean;
 v_previous_generated_at bigint;
 v_inserted_request_id bytea;
 v_now timestamptz;
 v_generated_at timestamptz;
 v_revision bigint;
 v_saved_revision bigint;
 v_key_count integer;
BEGIN
 IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_tenant_id IS DISTINCT FROM pg_catalog.current_setting('ujani.tenant_id', true) THEN
  RETURN NULL;
 END IF;
 IF p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_id IS NULL OR p_device_key_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_key_generation IS NULL OR p_device_key_generation <= 0
    OR p_consent_generation IS NULL OR p_consent_generation <= 0
    OR p_request_id IS NULL OR pg_catalog.octet_length(p_request_id) <> 16
    OR p_request_expires_at IS NULL
    OR p_generated_at_unix_ms IS NULL
    OR p_generated_at_unix_ms NOT BETWEEN 1 AND 9007199254740991
    OR p_policy_version IS NULL OR p_policy_version !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_payload_digest IS NULL OR pg_catalog.octet_length(p_payload_digest) <> 32
    OR p_inventory IS NULL OR p_event_id IS NULL
    OR pg_catalog.pg_column_size(p_inventory) > 2097152 THEN
  RETURN NULL;
 END IF;

 -- The full nested schema is validated by the trusted adapter before this call.
 -- This SQL guard independently binds the privacy/consent envelope and hard caps.
 -- Keep type checks separate so malformed JSON cannot make a length helper raise.
 IF pg_catalog.jsonb_typeof(p_inventory) IS DISTINCT FROM 'object' THEN
  RETURN NULL;
 END IF;
 SELECT count(*) INTO v_key_count FROM pg_catalog.jsonb_object_keys(p_inventory);
 IF v_key_count <> 9
    OR NOT (p_inventory ?& ARRAY[
     'schema_version','generated_at_unix_ms','device_ref','collection_context',
     'platform','hardware','runtimes','models','privacy'
    ])
    OR p_inventory->>'schema_version' IS DISTINCT FROM '2'
    OR p_inventory->>'generated_at_unix_ms' IS DISTINCT FROM p_generated_at_unix_ms::text
    OR p_inventory->>'device_ref' IS DISTINCT FROM p_device_id THEN
  RETURN NULL;
 END IF;
 IF pg_catalog.jsonb_typeof(p_inventory->'platform') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_inventory->'hardware') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_inventory->'collection_context') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_inventory->'privacy') IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_inventory->'runtimes') IS DISTINCT FROM 'array'
    OR pg_catalog.jsonb_typeof(p_inventory->'models') IS DISTINCT FROM 'array' THEN
  RETURN NULL;
 END IF;
 SELECT count(*) INTO v_key_count
 FROM pg_catalog.jsonb_object_keys(p_inventory->'collection_context');
 IF v_key_count <> 4
    OR NOT ((p_inventory->'collection_context') ?& ARRAY[
     'scope','owner_consent','organisation_authorisation','policy_version'
    ])
    OR p_inventory #>> '{collection_context,scope}' IS DISTINCT FROM 'organisation_enrolled'
    OR p_inventory #>> '{collection_context,owner_consent}' IS DISTINCT FROM 'granted'
    OR p_inventory #>> '{collection_context,organisation_authorisation}' IS DISTINCT FROM 'authorised'
    OR p_inventory #>> '{collection_context,policy_version}' IS DISTINCT FROM p_policy_version THEN
  RETURN NULL;
 END IF;
 SELECT count(*) INTO v_key_count
 FROM pg_catalog.jsonb_object_keys(p_inventory->'privacy');
 IF v_key_count <> 4
    OR NOT ((p_inventory->'privacy') ?& ARRAY[
     'contains_prompts','contains_user_files','contains_local_paths','contains_credentials'
    ])
    OR p_inventory #> '{privacy,contains_prompts}' IS DISTINCT FROM 'false'::jsonb
    OR p_inventory #> '{privacy,contains_user_files}' IS DISTINCT FROM 'false'::jsonb
    OR p_inventory #> '{privacy,contains_local_paths}' IS DISTINCT FROM 'false'::jsonb
    OR p_inventory #> '{privacy,contains_credentials}' IS DISTINCT FROM 'false'::jsonb THEN
  RETURN NULL;
 END IF;
 IF pg_catalog.jsonb_array_length(p_inventory->'runtimes') > 16
    OR pg_catalog.jsonb_array_length(p_inventory->'models') > 512 THEN
  RETURN NULL;
 END IF;

 -- Audit writers, policy changes, owner-consent changes and this acceptance
 -- transaction share one tenant lock. Acquire it before the device row lock.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id, 0));
 SELECT * INTO v_device
 FROM ujani_control.devices
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN
  RETURN NULL;
 END IF;

 v_now := pg_catalog.clock_timestamp();
 IF v_device.trust_state <> 'enrolled'
    OR v_device.admin_approval_state <> 'approved'
    OR v_device.owner_consent_state <> 'granted'
    OR v_device.active_key_id IS DISTINCT FROM p_device_key_id
    OR v_device.key_generation IS DISTINCT FROM p_device_key_generation
    OR v_device.consent_generation IS DISTINCT FROM p_consent_generation
    OR v_device.model_inventory_revision >= 9007199254740991
    OR p_request_expires_at <= v_now
    OR p_request_expires_at > v_now + interval '30 seconds' THEN
  RETURN NULL;
 END IF;

 SELECT * INTO v_policy
 FROM ujani_control.model_inventory_policies
 WHERE tenant_id = p_tenant_id;
 IF NOT FOUND OR v_policy.enabled IS DISTINCT FROM true
    OR v_policy.policy_version IS DISTINCT FROM p_policy_version THEN
  RETURN NULL;
 END IF;

 SELECT role, enabled INTO v_admin_role, v_admin_enabled
 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id
   AND subject_id = v_policy.updated_by_subject_id
 FOR SHARE;
 IF NOT FOUND OR v_admin_enabled IS DISTINCT FROM true OR v_admin_role <> 'administrator' THEN
  RETURN NULL;
 END IF;

 PERFORM 1 FROM ujani_control.device_keys
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND key_id = p_device_key_id AND generation = p_device_key_generation
   AND state = 'active' AND valid_from <= v_now AND revoked_at IS NULL
 FOR SHARE;
 IF NOT FOUND THEN
  RETURN NULL;
 END IF;

 -- Device-owner bindings are read without a row lock to preserve the existing
 -- owner-binding lock order. Their writers serialize first on the tenant lock.
 SELECT owner_subject_id INTO v_owner_subject_id
 FROM ujani_control.device_owner_bindings
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id AND active IS TRUE;
 IF NOT FOUND THEN
  RETURN NULL;
 END IF;
 SELECT enabled INTO v_owner_enabled
 FROM ujani_control.operator_subjects
 WHERE tenant_id = p_tenant_id AND subject_id = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND OR v_owner_enabled IS DISTINCT FROM true THEN
  RETURN NULL;
 END IF;
 PERFORM 1 FROM ujani_control.owner_consents
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND consent_generation = p_consent_generation
   AND state = 'granted' AND actor_ref = v_owner_subject_id
 FOR SHARE;
 IF NOT FOUND THEN
  RETURN NULL;
 END IF;

 -- Re-sample trusted database time after lock waits. Device and policy changes
 -- cannot interleave while the tenant/device locks are held.
 v_now := pg_catalog.clock_timestamp();
 v_generated_at := pg_catalog.to_timestamp(p_generated_at_unix_ms::double precision / 1000.0);
 IF p_request_expires_at <= v_now
    OR p_request_expires_at > v_now + interval '30 seconds'
    OR v_generated_at < v_now - (v_policy.max_age_ms * interval '1 millisecond')
    OR v_generated_at > v_now + interval '60 seconds' THEN
  RETURN NULL;
 END IF;

 SELECT generated_at_unix_ms INTO v_previous_generated_at
 FROM ujani_control.device_model_inventory
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id;
 IF FOUND AND p_generated_at_unix_ms <= v_previous_generated_at THEN
  RETURN NULL;
 END IF;

 -- Replay claim, current snapshot, device revision and audit receipt are atomic.
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
 INSERT INTO ujani_control.device_model_inventory
  (tenant_id,device_id,inventory_revision,generated_at_unix_ms,received_at,
   device_key_id,device_key_generation,consent_generation,policy_revision,
   request_id,payload_digest,visibility_state,revoked_at,inventory)
 VALUES
  (p_tenant_id,p_device_id,v_revision,p_generated_at_unix_ms,v_now,
   p_device_key_id,p_device_key_generation,p_consent_generation,v_policy.revision,
   p_request_id,p_payload_digest,'visible',NULL,p_inventory)
 ON CONFLICT (tenant_id,device_id) DO UPDATE SET
  inventory_revision = EXCLUDED.inventory_revision,
  generated_at_unix_ms = EXCLUDED.generated_at_unix_ms,
  received_at = EXCLUDED.received_at,
  device_key_id = EXCLUDED.device_key_id,
  device_key_generation = EXCLUDED.device_key_generation,
  consent_generation = EXCLUDED.consent_generation,
  policy_revision = EXCLUDED.policy_revision,
  request_id = EXCLUDED.request_id,
  payload_digest = EXCLUDED.payload_digest,
  visibility_state = 'visible',
  revoked_at = NULL,
  inventory = EXCLUDED.inventory
 RETURNING inventory_revision INTO v_saved_revision;
 IF v_saved_revision IS DISTINCT FROM v_revision THEN
  RAISE EXCEPTION 'model inventory revision was not committed' USING ERRCODE = '40001';
 END IF;

 UPDATE ujani_control.devices
 SET model_inventory_revision = v_revision,
     updated_at = v_now
 WHERE tenant_id = p_tenant_id AND device_id = p_device_id
   AND model_inventory_revision = v_device.model_inventory_revision;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'model inventory device revision changed during acceptance' USING ERRCODE = '40001';
 END IF;

 INSERT INTO ujani_control.audit_events
  (tenant_id,event_id,actor_ref,actor_role,event_type,outcome,object_ref)
 VALUES
  (p_tenant_id,p_event_id,p_device_id,'device',
   'device.model_inventory.accepted','stored',
   'device=' || pg_catalog.left(p_device_id,64)
   || ';revision=' || v_revision::text
   || ';policy_revision=' || v_policy.revision::text
   || ';digest=' || pg_catalog.left(pg_catalog.encode(p_payload_digest,'hex'),16));

 -- Audit-chain contention must not allow a request or inventory to expire while
 -- waiting. Raising aborts the replay, snapshot, watermark and audit together.
 v_now := pg_catalog.clock_timestamp();
 IF p_request_expires_at <= v_now
    OR v_generated_at < v_now - (v_policy.max_age_ms * interval '1 millisecond')
    OR v_generated_at > v_now + interval '60 seconds' THEN
  RAISE EXCEPTION 'model inventory authorization or evidence expired while recording audit'
   USING ERRCODE = '40001';
 END IF;
 RETURN v_revision;
END;
$function$;

REVOKE ALL ON FUNCTION ujani_control.accept_model_runtime_inventory_v2(
 text,text,text,bigint,bigint,bytea,timestamptz,bigint,text,bytea,jsonb,uuid
) FROM PUBLIC;

COMMENT ON FUNCTION ujani_control.accept_model_runtime_inventory_v2(
 text,text,text,bigint,bigint,bytea,timestamptz,bigint,text,bytea,jsonb,uuid
) IS
 'SECURITY INVOKER post-authentication Enterprise inventory transaction. The adapter verifies the exact device signature and full v2 JSON Schema first. Rechecks current enrolled trust, key ID/generation, active owner binding and consent generation, enabled administrator policy/version, request expiry, payload privacy envelope, freshness and replay. Stores only the latest bounded descriptor and appends a digest-only audit receipt atomically. It grants no workload or execution rights.';

COMMENT ON TABLE ujani_control.device_model_inventory IS
 'Latest tenant-scoped model/runtime inventory v2 snapshot. Stores bounded capability/resource metadata only; never prompts, model contents, personal files, local paths or credentials. The adapter must fully validate the shared schema before calling the atomic acceptance function.';
