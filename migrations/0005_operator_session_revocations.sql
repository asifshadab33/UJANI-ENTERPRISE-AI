-- Durable, tenant-isolated operator-session revocation records.
-- Apply after 0001_customer_hosted_control_plane.sql.
-- Store only session identifiers/metadata, never bearer tokens or signing keys.
-- Runtime code must use SET LOCAL ujani.tenant_id from authenticated identity.

CREATE TABLE IF NOT EXISTS ujani_control.operator_session_revocations (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 subject_id text NOT NULL,
 nonce bytea NOT NULL CHECK (octet_length(nonce) = 16),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT now(),
 reason text NOT NULL CHECK (reason IN ('logout','admin_revoked','security_incident')),
 revoked_by_subject_id text,
 PRIMARY KEY (tenant_id, subject_id, nonce),
 FOREIGN KEY (tenant_id, subject_id)
  REFERENCES ujani_control.operator_subjects(tenant_id, subject_id),
 FOREIGN KEY (tenant_id, revoked_by_subject_id)
  REFERENCES ujani_control.operator_subjects(tenant_id, subject_id),
 CHECK (expires_at > revoked_at)
);

CREATE INDEX IF NOT EXISTS operator_session_revocations_expiry_idx
 ON ujani_control.operator_session_revocations (tenant_id, expires_at);

ALTER TABLE ujani_control.operator_session_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ujani_control.operator_session_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ujani_control.operator_session_revocations;
CREATE POLICY tenant_isolation ON ujani_control.operator_session_revocations
 USING (tenant_id = current_setting('ujani.tenant_id', true))
 WITH CHECK (tenant_id = current_setting('ujani.tenant_id', true));

COMMENT ON TABLE ujani_control.operator_session_revocations IS
 'Tenant-scoped operator session revocation tombstones. Store the opaque session nonce only, never bearer tokens or key material. Runtime writes are insert-only; cleanup of expired rows belongs to a separately privileged maintenance role.';
