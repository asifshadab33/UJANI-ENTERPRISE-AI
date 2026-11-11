-- UJANI Enterprise customer-hosted control-plane schema foundation.
-- Apply using a dedicated migration owner. Runtime connections must use a
-- non-owner role; RLS does not replace setting tenant context per transaction.
CREATE SCHEMA IF NOT EXISTS ujani_control;
CREATE TABLE IF NOT EXISTS ujani_control.tenants (
 tenant_id text PRIMARY KEY CHECK (tenant_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ujani_control.operator_subjects (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 subject_id text NOT NULL CHECK (subject_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 role text NOT NULL CHECK (role IN ('viewer','operator','administrator')),
 enabled boolean NOT NULL DEFAULT true,
 idp_issuer text NOT NULL CHECK (length(idp_issuer) BETWEEN 1 AND 512),
 idp_subject text NOT NULL CHECK (length(idp_subject) BETWEEN 1 AND 512),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, subject_id),
 UNIQUE (tenant_id, idp_issuer, idp_subject)
);
CREATE TABLE IF NOT EXISTS ujani_control.devices (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 device_id text NOT NULL CHECK (device_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 display_name text NOT NULL CHECK (length(display_name) <= 256),
 platform text NOT NULL CHECK (length(platform) BETWEEN 1 AND 64),
 trust_state text NOT NULL CHECK (trust_state IN ('pending','enrolled','revoked','decommissioned')),
 owner_consent_state text NOT NULL CHECK (owner_consent_state IN ('unknown','granted','paused','withdrawn')),
 admin_approval_state text NOT NULL CHECK (admin_approval_state IN ('pending','approved','rejected','revoked')),
 active_key_id text,
 key_generation bigint NOT NULL DEFAULT 0 CHECK (key_generation >= 0),
 last_seen_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, device_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.device_keys (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
 generation bigint NOT NULL CHECK (generation > 0),
 state text NOT NULL CHECK (state IN ('active','retired','revoked')),
 valid_from timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz,
 PRIMARY KEY (tenant_id, device_id, key_id),
 UNIQUE (tenant_id, device_id, generation),
 FOREIGN KEY (tenant_id, device_id) REFERENCES ujani_control.devices(tenant_id, device_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.owner_consents (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 consent_generation bigint NOT NULL CHECK (consent_generation > 0),
 state text NOT NULL CHECK (state IN ('granted','paused','withdrawn')),
 actor_ref text NOT NULL CHECK (length(actor_ref) BETWEEN 1 AND 128),
 evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
 occurred_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, device_id, consent_generation),
 FOREIGN KEY (tenant_id, device_id) REFERENCES ujani_control.devices(tenant_id, device_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.workloads (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 workload_id text NOT NULL CHECK (workload_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
 class text NOT NULL CHECK (length(class) BETWEEN 1 AND 64),
 state text NOT NULL CHECK (state IN ('draft','pending_approval','approved','rejected','cancelled','completed')),
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, workload_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.approvals (
 tenant_id text NOT NULL,
 approval_id text NOT NULL CHECK (approval_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 workload_id text NOT NULL,
 approver_subject_id text NOT NULL,
 decision text NOT NULL CHECK (decision IN ('approved','rejected','revoked')),
 manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, approval_id),
 FOREIGN KEY (tenant_id, workload_id) REFERENCES ujani_control.workloads(tenant_id, workload_id),
 FOREIGN KEY (tenant_id, approver_subject_id) REFERENCES ujani_control.operator_subjects(tenant_id, subject_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.leases (
 tenant_id text NOT NULL,
 lease_id text NOT NULL CHECK (lease_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 device_id text NOT NULL,
 workload_id text NOT NULL,
 manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
 device_key_generation bigint NOT NULL CHECK (device_key_generation > 0),
 state text NOT NULL CHECK (state IN ('reserved','active','released','expired','cancelled','revoked')),
 expires_at timestamptz NOT NULL,
 revision bigint NOT NULL CHECK (revision > 0),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, lease_id),
 FOREIGN KEY (tenant_id, device_id) REFERENCES ujani_control.devices(tenant_id, device_id),
 FOREIGN KEY (tenant_id, workload_id) REFERENCES ujani_control.workloads(tenant_id, workload_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.request_replays (
 tenant_id text NOT NULL,
 device_id text NOT NULL,
 request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
 expires_at timestamptz NOT NULL,
 operation_digest bytea NOT NULL CHECK (octet_length(operation_digest) = 32),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, device_id, request_id),
 FOREIGN KEY (tenant_id, device_id) REFERENCES ujani_control.devices(tenant_id, device_id)
);
CREATE TABLE IF NOT EXISTS ujani_control.audit_events (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 sequence_id bigserial NOT NULL,
 event_id uuid NOT NULL UNIQUE,
 actor_ref text NOT NULL CHECK (length(actor_ref) BETWEEN 1 AND 128),
 actor_role text NOT NULL CHECK (actor_role IN ('device','viewer','operator','administrator','system')),
 event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
 outcome text NOT NULL CHECK (length(outcome) BETWEEN 1 AND 64),
 object_ref text CHECK (object_ref IS NULL OR length(object_ref) <= 256),
 occurred_at timestamptz NOT NULL DEFAULT now(),
 previous_digest bytea CHECK (previous_digest IS NULL OR octet_length(previous_digest) = 32),
 event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
 PRIMARY KEY (tenant_id, sequence_id)
);
DO $$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['operator_subjects','devices','device_keys','owner_consents','workloads','approvals','leases','request_replays','audit_events'] LOOP
  EXECUTE format('ALTER TABLE ujani_control.%I ENABLE ROW LEVEL SECURITY', table_name);
  EXECUTE format('ALTER TABLE ujani_control.%I FORCE ROW LEVEL SECURITY', table_name);
  EXECUTE format('CREATE POLICY tenant_isolation ON ujani_control.%I USING (tenant_id = current_setting(''ujani.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''ujani.tenant_id'', true))', table_name);
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION ujani_control.reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'UJANI audit events are append-only';
END;
$$;
DROP TRIGGER IF EXISTS audit_events_no_update_delete ON ujani_control.audit_events;
CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON ujani_control.audit_events
FOR EACH ROW EXECUTE FUNCTION ujani_control.reject_audit_mutation();
COMMENT ON TABLE ujani_control.audit_events IS 'Append-only tenant-scoped audit chain. Insert path must verify sequence and previous digest in the same transaction; never store prompts, tokens, secrets or raw telemetry.';
