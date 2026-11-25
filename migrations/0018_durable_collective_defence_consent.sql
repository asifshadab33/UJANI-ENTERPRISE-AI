-- Durable, tenant-isolated two-party Collective Defence consent authority.
-- Apply after migrations 0001-0017.
--
-- The authenticated service MUST verify Ed25519 signatures against protected,
-- tenant-bound administrator/user keys before calling these functions. This
-- migration persists the verified claims and performs generation/CAS,
-- idempotency and audit append atomically. It is not a key store and does not
-- provide an external monotonic rollback anchor.
--
-- No event collection, transmission, remote execution or endpoint action is
-- enabled by this migration. Missing/expired/mismatched consent is denial.

-- A dedicated NOLOGIN executor owns the SECURITY DEFINER routines. It is not
-- a table owner and has no BYPASSRLS attribute, so FORCE ROW LEVEL SECURITY
-- remains active even inside the privileged routines.
DO $role$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='ujani_consent_writer') THEN
  CREATE ROLE ujani_consent_writer NOLOGIN;
 END IF;
END;
$role$;

CREATE TABLE IF NOT EXISTS ujani_control.collective_defence_tenant_consent (
 tenant_id text PRIMARY KEY REFERENCES ujani_control.tenants(tenant_id),
 enabled boolean NOT NULL DEFAULT false,
 generation bigint NOT NULL CHECK (generation > 0),
 purpose text NOT NULL CHECK (purpose = 'collective-defence.read-only.v1'),
 event_schema_version text NOT NULL CHECK (event_schema_version = '1.0'),
 retention_seconds integer NOT NULL CHECK (
  retention_seconds >= 0 AND retention_seconds <= 7776000
  AND (NOT enabled OR retention_seconds > 0)
 ),
 notice_version text NOT NULL CHECK (length(notice_version) BETWEEN 1 AND 64),
 notice_sha256 bytea NOT NULL CHECK (octet_length(notice_sha256) = 32
  AND notice_sha256 <> decode(repeat('00',32),'hex')),
 actor_key_id text NOT NULL CHECK (actor_key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK (expires_at > issued_at),
 CHECK (expires_at <= issued_at + interval '24 hours')
);

CREATE TABLE IF NOT EXISTS ujani_control.collective_defence_individual_consent (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 principal_id text NOT NULL CHECK (principal_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 device_id text NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 tenant_generation bigint NOT NULL CHECK (tenant_generation > 0),
 generation bigint NOT NULL CHECK (generation > 0),
 purpose text NOT NULL CHECK (purpose = 'collective-defence.read-only.v1'),
 notice_version text NOT NULL CHECK (length(notice_version) BETWEEN 1 AND 64),
 notice_sha256 bytea NOT NULL CHECK (octet_length(notice_sha256) = 32
  AND notice_sha256 <> decode(repeat('00',32),'hex')),
 actor_key_id text NOT NULL CHECK (actor_key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id, principal_id, device_id),
 FOREIGN KEY (tenant_id, device_id)
  REFERENCES ujani_control.devices(tenant_id, device_id),
 CHECK (expires_at > issued_at),
 CHECK (expires_at <= issued_at + interval '24 hours')
);

CREATE TABLE IF NOT EXISTS ujani_control.collective_defence_consent_audit (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 sequence_id bigint NOT NULL CHECK (sequence_id > 0),
 event_id uuid NOT NULL,
 scope text NOT NULL CHECK (scope IN ('tenant','individual')),
 principal_id text,
 device_id text,
 action text NOT NULL CHECK (action IN ('enabled','disabled','withdrawn','renewed')),
 previous_generation bigint NOT NULL CHECK (previous_generation >= 0),
 next_generation bigint NOT NULL CHECK (next_generation > previous_generation),
 actor_key_id text NOT NULL,
 idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
 request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
 committed_at timestamptz NOT NULL,
 previous_hash bytea NOT NULL CHECK (octet_length(previous_hash) = 32),
 record_hash bytea NOT NULL CHECK (octet_length(record_hash) = 32),
 PRIMARY KEY (tenant_id, sequence_id),
 UNIQUE (tenant_id, event_id),
 UNIQUE (tenant_id, scope, idempotency_key),
 CHECK ((scope = 'tenant' AND principal_id IS NULL AND device_id IS NULL)
     OR (scope = 'individual' AND principal_id IS NOT NULL AND device_id IS NOT NULL))
);

DO $policy$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY[
  'collective_defence_tenant_consent',
  'collective_defence_individual_consent',
  'collective_defence_consent_audit'
 ] LOOP
  EXECUTE format('ALTER TABLE ujani_control.%I ENABLE ROW LEVEL SECURITY', table_name);
  EXECUTE format('ALTER TABLE ujani_control.%I FORCE ROW LEVEL SECURITY', table_name);
  EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON ujani_control.%I', table_name);
  EXECUTE format(
   'CREATE POLICY tenant_isolation ON ujani_control.%I USING (tenant_id = current_setting(''ujani.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''ujani.tenant_id'', true))',
   table_name
  );
 END LOOP;
END;
$policy$;

CREATE OR REPLACE FUNCTION ujani_control.reject_collective_defence_consent_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ujani_control
AS $function$
BEGIN
 RAISE EXCEPTION 'Collective Defence consent audit is append-only';
END;
$function$;

DROP TRIGGER IF EXISTS collective_defence_consent_audit_immutable
 ON ujani_control.collective_defence_consent_audit;
CREATE TRIGGER collective_defence_consent_audit_immutable
 BEFORE UPDATE OR DELETE ON ujani_control.collective_defence_consent_audit
 FOR EACH ROW EXECUTE FUNCTION ujani_control.reject_collective_defence_consent_audit_mutation();

-- Internal append primitive. Callers hold the tenant advisory transaction lock.
-- Duplicate requests return the original event only when their digest matches.
CREATE OR REPLACE FUNCTION ujani_control.append_collective_defence_consent_audit(
 p_tenant_id text,
 p_scope text,
 p_principal_id text,
 p_device_id text,
 p_action text,
 p_previous_generation bigint,
 p_next_generation bigint,
 p_actor_key_id text,
 p_idempotency_key text,
 p_request_digest bytea
)
RETURNS TABLE(sequence_id bigint, event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_tenant_context text;
 v_existing ujani_control.collective_defence_consent_audit%ROWTYPE;
 v_previous_hash bytea;
 v_sequence bigint;
 v_event_id uuid;
 v_committed_at timestamptz := clock_timestamp();
 v_payload jsonb;
 v_record_hash bytea;
BEGIN
 v_tenant_context := current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = ''
    OR p_tenant_id IS DISTINCT FROM v_tenant_context THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 IF p_scope NOT IN ('tenant','individual')
    OR p_action NOT IN ('enabled','disabled','withdrawn','renewed')
    OR p_previous_generation < 0
    OR p_next_generation <= p_previous_generation
    OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
    OR p_idempotency_key IS NULL OR length(p_idempotency_key) NOT BETWEEN 1 AND 128
    OR p_actor_key_id IS NULL OR p_actor_key_id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN
  RAISE EXCEPTION 'invalid consent audit input' USING ERRCODE = '22023';
 END IF;

 SELECT * INTO v_existing
 FROM ujani_control.collective_defence_consent_audit
 WHERE tenant_id = p_tenant_id AND scope = p_scope
   AND idempotency_key = p_idempotency_key;
 IF FOUND THEN
  IF v_existing.request_digest IS DISTINCT FROM p_request_digest THEN
   RAISE EXCEPTION 'consent idempotency key reused with different request' USING ERRCODE = '23505';
  END IF;
  RETURN QUERY SELECT v_existing.sequence_id, v_existing.event_id;
  RETURN;
 END IF;

 SELECT sequence_id, record_hash INTO v_sequence, v_previous_hash
 FROM ujani_control.collective_defence_consent_audit
 WHERE tenant_id = p_tenant_id
 ORDER BY sequence_id DESC LIMIT 1;
 v_sequence := coalesce(v_sequence, 0) + 1;
 v_previous_hash := coalesce(v_previous_hash, decode(repeat('00',32),'hex'));
 v_event_id := gen_random_uuid();
 v_payload := jsonb_build_object(
  'schema_version', 1,
  'tenant_id', p_tenant_id,
  'sequence_id', v_sequence,
  'event_id', v_event_id,
  'scope', p_scope,
  'principal_id', p_principal_id,
  'device_id', p_device_id,
  'action', p_action,
  'previous_generation', p_previous_generation,
  'next_generation', p_next_generation,
  'actor_key_id', p_actor_key_id,
  'idempotency_key', p_idempotency_key,
  'request_digest', encode(p_request_digest,'hex'),
  'committed_at_utc', to_char(v_committed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
 );
 v_record_hash := sha256(v_previous_hash || convert_to(v_payload::text,'UTF8'));
 INSERT INTO ujani_control.collective_defence_consent_audit
  (tenant_id,sequence_id,event_id,scope,principal_id,device_id,action,
   previous_generation,next_generation,actor_key_id,idempotency_key,
   request_digest,committed_at,previous_hash,record_hash)
 VALUES
  (p_tenant_id,v_sequence,v_event_id,p_scope,p_principal_id,p_device_id,p_action,
   p_previous_generation,p_next_generation,p_actor_key_id,p_idempotency_key,
   p_request_digest,v_committed_at,v_previous_hash,v_record_hash);
 RETURN QUERY SELECT v_sequence, v_event_id;
END;
$function$;

-- The caller must verify the administrator's Ed25519 signature and key-to-tenant
-- binding before invoking this transaction function.
CREATE OR REPLACE FUNCTION ujani_control.record_collective_defence_tenant_consent(
 p_tenant_id text,
 p_enabled boolean,
 p_expected_generation bigint,
 p_purpose text,
 p_schema_version text,
 p_retention_seconds integer,
 p_notice_version text,
 p_notice_sha256 bytea,
 p_actor_key_id text,
 p_issued_at timestamptz,
 p_expires_at timestamptz,
 p_idempotency_key text,
 p_request_digest bytea
)
RETURNS TABLE(sequence_id bigint, event_id uuid, generation bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_current_generation bigint;
 v_next_generation bigint;
 v_existing ujani_control.collective_defence_consent_audit%ROWTYPE;
 v_audit RECORD;
 v_tenant_context text;
BEGIN
 v_tenant_context := current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = ''
    OR p_tenant_id IS DISTINCT FROM v_tenant_context THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id,0));

 SELECT * INTO v_existing FROM ujani_control.collective_defence_consent_audit
 WHERE tenant_id=p_tenant_id AND scope='tenant' AND idempotency_key=p_idempotency_key;
 IF FOUND THEN
  IF v_existing.request_digest IS DISTINCT FROM p_request_digest THEN
   RAISE EXCEPTION 'consent idempotency key reused with different request' USING ERRCODE = '23505';
  END IF;
  RETURN QUERY SELECT v_existing.sequence_id,v_existing.event_id,v_existing.next_generation;
  RETURN;
 END IF;

 SELECT generation INTO v_current_generation
 FROM ujani_control.collective_defence_tenant_consent
 WHERE tenant_id=p_tenant_id FOR UPDATE;
 IF NOT FOUND THEN
  IF p_expected_generation IS NOT NULL THEN
   RAISE EXCEPTION 'tenant consent generation conflict' USING ERRCODE = '40001';
  END IF;
  v_current_generation := 0;
 ELSE
  IF p_expected_generation IS DISTINCT FROM v_current_generation THEN
   RAISE EXCEPTION 'tenant consent generation conflict' USING ERRCODE = '40001';
  END IF;
 END IF;
 v_next_generation := v_current_generation + 1;

 IF p_purpose IS DISTINCT FROM 'collective-defence.read-only.v1'
    OR p_schema_version IS DISTINCT FROM '1.0'
    OR p_retention_seconds < 0 OR p_retention_seconds > 7776000
    OR (p_enabled AND p_retention_seconds = 0)
    OR p_notice_version IS NULL OR length(p_notice_version) NOT BETWEEN 1 AND 64
    OR p_notice_sha256 IS NULL OR octet_length(p_notice_sha256) <> 32
    OR p_notice_sha256 = decode(repeat('00',32),'hex')
    OR p_actor_key_id IS NULL OR p_actor_key_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_issued_at IS NULL OR p_expires_at IS NULL
    OR p_issued_at > clock_timestamp() + interval '30 seconds'
    OR p_expires_at <= p_issued_at
    OR p_expires_at > p_issued_at + interval '24 hours'
    OR p_expires_at <= clock_timestamp()
    OR p_idempotency_key IS NULL OR length(p_idempotency_key) NOT BETWEEN 1 AND 128
    OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
  RAISE EXCEPTION 'invalid tenant consent claims' USING ERRCODE = '22023';
 END IF;

 INSERT INTO ujani_control.collective_defence_tenant_consent
  (tenant_id,enabled,generation,purpose,event_schema_version,retention_seconds,
   notice_version,notice_sha256,actor_key_id,issued_at,expires_at,updated_at)
 VALUES
  (p_tenant_id,p_enabled,v_next_generation,p_purpose,p_schema_version,p_retention_seconds,
   p_notice_version,p_notice_sha256,p_actor_key_id,p_issued_at,p_expires_at,clock_timestamp())
 ON CONFLICT (tenant_id) DO UPDATE SET
  enabled=EXCLUDED.enabled,generation=EXCLUDED.generation,purpose=EXCLUDED.purpose,
  event_schema_version=EXCLUDED.event_schema_version,retention_seconds=EXCLUDED.retention_seconds,
  notice_version=EXCLUDED.notice_version,notice_sha256=EXCLUDED.notice_sha256,
  actor_key_id=EXCLUDED.actor_key_id,issued_at=EXCLUDED.issued_at,
  expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at;

 SELECT * INTO v_audit FROM ujani_control.append_collective_defence_consent_audit(
  p_tenant_id,'tenant',NULL,NULL,CASE WHEN p_enabled THEN 'enabled' ELSE 'disabled' END,
  v_current_generation,v_next_generation,p_actor_key_id,p_idempotency_key,p_request_digest
 );
 RETURN QUERY SELECT v_audit.sequence_id,v_audit.event_id,v_next_generation;
END;
$function$;

-- The caller must verify the user's Ed25519 signature and exact
-- tenant/device/principal key binding before invoking this function.
CREATE OR REPLACE FUNCTION ujani_control.record_collective_defence_individual_consent(
 p_tenant_id text,
 p_principal_id text,
 p_device_id text,
 p_enabled boolean,
 p_tenant_generation bigint,
 p_expected_generation bigint,
 p_purpose text,
 p_notice_version text,
 p_notice_sha256 bytea,
 p_actor_key_id text,
 p_issued_at timestamptz,
 p_expires_at timestamptz,
 p_idempotency_key text,
 p_request_digest bytea
)
RETURNS TABLE(sequence_id bigint, event_id uuid, generation bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ujani_control
AS $function$
DECLARE
 v_current_generation bigint;
 v_next_generation bigint;
 v_tenant ujani_control.collective_defence_tenant_consent%ROWTYPE;
 v_existing ujani_control.collective_defence_consent_audit%ROWTYPE;
 v_audit RECORD;
 v_tenant_context text;
BEGIN
 v_tenant_context := current_setting('ujani.tenant_id', true);
 IF v_tenant_context IS NULL OR v_tenant_context = ''
    OR p_tenant_id IS DISTINCT FROM v_tenant_context THEN
  RAISE EXCEPTION 'authenticated tenant context mismatch' USING ERRCODE = '42501';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id,0));

 SELECT * INTO v_existing FROM ujani_control.collective_defence_consent_audit
 WHERE tenant_id=p_tenant_id AND scope='individual' AND idempotency_key=p_idempotency_key;
 IF FOUND THEN
  IF v_existing.request_digest IS DISTINCT FROM p_request_digest THEN
   RAISE EXCEPTION 'consent idempotency key reused with different request' USING ERRCODE = '23505';
  END IF;
  RETURN QUERY SELECT v_existing.sequence_id,v_existing.event_id,v_existing.next_generation;
  RETURN;
 END IF;

 SELECT * INTO v_tenant FROM ujani_control.collective_defence_tenant_consent
 WHERE tenant_id=p_tenant_id FOR SHARE;
 IF NOT FOUND OR NOT v_tenant.enabled
    OR v_tenant.generation <> p_tenant_generation
    OR v_tenant.expires_at <= clock_timestamp() THEN
  RAISE EXCEPTION 'current tenant opt-in is required' USING ERRCODE = '42501';
 END IF;

 SELECT generation INTO v_current_generation
 FROM ujani_control.collective_defence_individual_consent
 WHERE tenant_id=p_tenant_id AND principal_id=p_principal_id AND device_id=p_device_id
 FOR UPDATE;
 IF NOT FOUND THEN
  IF p_expected_generation IS NOT NULL THEN
   RAISE EXCEPTION 'individual consent generation conflict' USING ERRCODE = '40001';
  END IF;
  v_current_generation := 0;
 ELSE
  IF p_expected_generation IS DISTINCT FROM v_current_generation THEN
   RAISE EXCEPTION 'individual consent generation conflict' USING ERRCODE = '40001';
  END IF;
 END IF;
 v_next_generation := v_current_generation + 1;

 IF p_principal_id IS NULL OR p_principal_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_device_id IS NULL OR p_device_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_purpose IS DISTINCT FROM 'collective-defence.read-only.v1'
    OR p_notice_version IS NULL OR length(p_notice_version) NOT BETWEEN 1 AND 64
    OR p_notice_sha256 IS NULL OR octet_length(p_notice_sha256) <> 32
    OR p_notice_sha256 = decode(repeat('00',32),'hex')
    OR p_actor_key_id IS NULL OR p_actor_key_id !~ '^[A-Za-z0-9._:-]{1,128}$'
    OR p_issued_at IS NULL OR p_expires_at IS NULL
    OR p_issued_at > clock_timestamp() + interval '30 seconds'
    OR p_expires_at <= p_issued_at
    OR p_expires_at > p_issued_at + interval '24 hours'
    OR p_expires_at <= clock_timestamp()
    OR p_idempotency_key IS NULL OR length(p_idempotency_key) NOT BETWEEN 1 AND 128
    OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
  RAISE EXCEPTION 'invalid individual consent claims' USING ERRCODE = '22023';
 END IF;

 INSERT INTO ujani_control.collective_defence_individual_consent
  (tenant_id,principal_id,device_id,enabled,tenant_generation,generation,purpose,
   notice_version,notice_sha256,actor_key_id,issued_at,expires_at,updated_at)
 VALUES
  (p_tenant_id,p_principal_id,p_device_id,p_enabled,p_tenant_generation,v_next_generation,
   p_purpose,p_notice_version,p_notice_sha256,p_actor_key_id,p_issued_at,p_expires_at,clock_timestamp())
 ON CONFLICT (tenant_id,principal_id,device_id) DO UPDATE SET
  enabled=EXCLUDED.enabled,tenant_generation=EXCLUDED.tenant_generation,
  generation=EXCLUDED.generation,purpose=EXCLUDED.purpose,
  notice_version=EXCLUDED.notice_version,notice_sha256=EXCLUDED.notice_sha256,
  actor_key_id=EXCLUDED.actor_key_id,issued_at=EXCLUDED.issued_at,
  expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at;

 SELECT * INTO v_audit FROM ujani_control.append_collective_defence_consent_audit(
  p_tenant_id,'individual',p_principal_id,p_device_id,
  CASE WHEN p_enabled THEN 'enabled' ELSE 'withdrawn' END,
  v_current_generation,v_next_generation,p_actor_key_id,p_idempotency_key,p_request_digest
 );
 RETURN QUERY SELECT v_audit.sequence_id,v_audit.event_id,v_next_generation;
END;
$function$;

CREATE OR REPLACE FUNCTION ujani_control.collective_defence_consent_is_current(
 p_tenant_id text,
 p_principal_id text,
 p_device_id text,
 p_now timestamptz DEFAULT clock_timestamp()
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, ujani_control
AS $function$
 SELECT current_setting('ujani.tenant_id',true) = p_tenant_id
  AND EXISTS (
   SELECT 1
   FROM ujani_control.collective_defence_tenant_consent tenant
   JOIN ujani_control.collective_defence_individual_consent individual
    ON individual.tenant_id=tenant.tenant_id
   WHERE tenant.tenant_id=p_tenant_id
    AND individual.principal_id=p_principal_id
    AND individual.device_id=p_device_id
    AND tenant.enabled AND individual.enabled
    AND individual.tenant_generation=tenant.generation
    AND tenant.expires_at > p_now
    AND individual.expires_at > p_now
  );
$function$;

COMMENT ON TABLE ujani_control.collective_defence_tenant_consent IS
 'Current versioned administrator opt-in. Default is off; every update advances a generation.';
COMMENT ON TABLE ujani_control.collective_defence_individual_consent IS
 'Independent user/device opt-in. It is valid only for the exact current tenant policy generation.';
COMMENT ON TABLE ujani_control.collective_defence_consent_audit IS
 'Tenant-scoped append-only hash chain for consent decisions. Database owners can still rewrite history; production requires an external monotonic anchor.';
COMMENT ON FUNCTION ujani_control.record_collective_defence_tenant_consent IS
 'Atomic generation-CAS tenant consent write plus audit append. Caller must authenticate and verify the administrator signature before invocation.';
COMMENT ON FUNCTION ujani_control.record_collective_defence_individual_consent IS
 'Atomic generation-CAS individual consent write plus audit append. Caller must authenticate and verify the user/device signature before invocation.';

-- Restrict direct table access to the non-login function owner. The runtime
-- role can invoke only the audited transaction functions and the read-only
-- current-consent predicate. The executor is not a table owner and cannot
-- bypass FORCE ROW LEVEL SECURITY.
GRANT USAGE ON SCHEMA ujani_control TO ujani_consent_writer;
GRANT SELECT, INSERT, UPDATE ON
 ujani_control.collective_defence_tenant_consent,
 ujani_control.collective_defence_individual_consent
 TO ujani_consent_writer;
GRANT SELECT, INSERT ON ujani_control.collective_defence_consent_audit
 TO ujani_consent_writer;
GRANT CREATE ON SCHEMA ujani_control TO ujani_consent_writer;
ALTER FUNCTION ujani_control.append_collective_defence_consent_audit(
 text,text,text,text,text,bigint,bigint,text,text,bytea
) OWNER TO ujani_consent_writer;
ALTER FUNCTION ujani_control.record_collective_defence_tenant_consent(
 text,boolean,bigint,text,text,integer,text,bytea,text,timestamptz,timestamptz,text,bytea
) OWNER TO ujani_consent_writer;
ALTER FUNCTION ujani_control.record_collective_defence_individual_consent(
 text,text,text,boolean,bigint,bigint,text,text,bytea,text,timestamptz,timestamptz,text,bytea
) OWNER TO ujani_consent_writer;
ALTER FUNCTION ujani_control.collective_defence_consent_is_current(
 text,text,text,timestamptz
) OWNER TO ujani_consent_writer;
REVOKE CREATE ON SCHEMA ujani_control FROM ujani_consent_writer;

REVOKE ALL ON FUNCTION ujani_control.append_collective_defence_consent_audit(
 text,text,text,text,text,bigint,bigint,text,text,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION ujani_control.record_collective_defence_tenant_consent(
 text,boolean,bigint,text,text,integer,text,bytea,text,timestamptz,timestamptz,text,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION ujani_control.record_collective_defence_individual_consent(
 text,text,text,boolean,bigint,bigint,text,text,bytea,text,timestamptz,timestamptz,text,bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION ujani_control.collective_defence_consent_is_current(
 text,text,text,timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ujani_control.append_collective_defence_consent_audit(
 text,text,text,text,text,bigint,bigint,text,text,bytea
) TO ujani_consent_writer;
GRANT EXECUTE ON FUNCTION ujani_control.record_collective_defence_tenant_consent(
 text,boolean,bigint,text,text,integer,text,bytea,text,timestamptz,timestamptz,text,bytea
) TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.record_collective_defence_individual_consent(
 text,text,text,boolean,bigint,bigint,text,text,bytea,text,timestamptz,timestamptz,text,bytea
) TO ujani_runtime;
GRANT EXECUTE ON FUNCTION ujani_control.collective_defence_consent_is_current(
 text,text,text,timestamptz
) TO ujani_runtime;
