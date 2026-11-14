-- Durable, tenant-scoped single-use consumption for signed Self-Evolution approvals.
-- Apply only after 0001_customer_hosted_control_plane.sql.
-- The host must verify the Ed25519 signature and exact proposal/target binding first,
-- then INSERT this row in the same transaction as any future approval-authorized state
-- transition. Success is only the row returned by INSERT ... ON CONFLICT DO NOTHING
-- RETURNING; a duplicate approval_id or nonce is a replay and must fail closed.
-- This table stores digests and bounded approval metadata, never patches or source code.

CREATE TABLE IF NOT EXISTS ujani_control.self_evolution_approval_replays (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 approval_id text NOT NULL CHECK (approval_id ~ '^[A-Za-z0-9._-]{1,128}$'),
 approver_subject_id text NOT NULL,
 approver_key_id text NOT NULL CHECK (approver_key_id ~ '^[A-Za-z0-9._-]{1,128}$'),
 nonce bytea NOT NULL CHECK (octet_length(nonce) = 16),
 repository text NOT NULL CHECK (repository ~ '^[A-Za-z0-9._-]{1,128}/[A-Za-z0-9._-]{1,128}$'),
 base_ref text NOT NULL CHECK (length(base_ref) BETWEEN 1 AND 128),
 source_revision text NOT NULL CHECK (
  (length(source_revision) = 40 OR length(source_revision) = 64)
  AND source_revision ~ '^[A-Fa-f0-9]+$'
 ),
 proposal_sha256 bytea NOT NULL CHECK (octet_length(proposal_sha256) = 32),
 target_sha256 bytea NOT NULL CHECK (octet_length(target_sha256) = 32),
 approved_scope_sha256 bytea NOT NULL CHECK (octet_length(approved_scope_sha256) = 32),
 approved_scope_count integer NOT NULL CHECK (approved_scope_count BETWEEN 1 AND 32),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, approval_id),
 UNIQUE (tenant_id, nonce),
 FOREIGN KEY (tenant_id, approver_subject_id)
  REFERENCES ujani_control.operator_subjects(tenant_id, subject_id),
 CHECK (expires_at > consumed_at)
);

CREATE INDEX IF NOT EXISTS self_evolution_approval_replays_expiry_idx
 ON ujani_control.self_evolution_approval_replays (tenant_id, expires_at);

ALTER TABLE ujani_control.self_evolution_approval_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.self_evolution_approval_replays FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.self_evolution_approval_replays;
CREATE POLICY tenant_isolation ON ujani_control.self_evolution_approval_replays
 USING (tenant_id = current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = current_setting('ujani.tenant_id', true));

COMMENT ON TABLE ujani_control.self_evolution_approval_replays IS
 'Single-use tenant-scoped tombstones for already-verified Self-Evolution approvals. Insert with ON CONFLICT DO NOTHING RETURNING inside the caller transaction; unique approval ID and nonce constraints serialize concurrent replay attempts. No patch or source payload is stored.';
