-- Additive durable replay and monotonic-stream storage for shared task-contract v1.
-- This migration stores metadata/digests only; it never stores prompts or payload bytes.
-- Apply as the migration owner. Runtime access must use a non-owner role and set
-- ujani.tenant_id transaction-locally. No dispatch or execution is enabled here.

CREATE TABLE IF NOT EXISTS ujani_control.task_contract_replays (
 tenant_id text NOT NULL REFERENCES ujani_control.tenants(tenant_id),
 task_id text NOT NULL CHECK (task_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 sender_device_id text NOT NULL CHECK (sender_device_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
 nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
 envelope_digest bytea NOT NULL CHECK (octet_length(envelope_digest) = 32),
 payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
 expires_at timestamptz NOT NULL,
 state text NOT NULL CHECK (state IN (
  'received','validating','awaiting_approval','queued','reserved','running',
  'completed','failed','cancelled','timed_out','rejected','expired'
 )),
 revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, task_id),
 UNIQUE (tenant_id, sender_device_id, nonce),
 FOREIGN KEY (tenant_id, sender_device_id)
  REFERENCES ujani_control.devices(tenant_id, device_id)
);

CREATE INDEX IF NOT EXISTS task_contract_replays_expiry_idx
 ON ujani_control.task_contract_replays (tenant_id, expires_at);

CREATE TABLE IF NOT EXISTS ujani_control.task_contract_sequences (
 tenant_id text NOT NULL,
 task_id text NOT NULL,
 message_type text NOT NULL CHECK (message_type IN ('task_status','execution_receipt')),
 last_sequence bigint NOT NULL CHECK (last_sequence BETWEEN 1 AND 9007199254740991),
 message_digest bytea NOT NULL CHECK (octet_length(message_digest) = 32),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, task_id, message_type),
 FOREIGN KEY (tenant_id, task_id)
  REFERENCES ujani_control.task_contract_replays(tenant_id, task_id)
);

DO $$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['task_contract_replays','task_contract_sequences'] LOOP
  EXECUTE format('ALTER TABLE ujani_control.%I ENABLE ROW LEVEL SECURITY', table_name);
  EXECUTE format('ALTER TABLE ujani_control.%I FORCE ROW LEVEL SECURITY', table_name);
  EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON ujani_control.%I', table_name);
  EXECUTE format(
   'CREATE POLICY tenant_isolation ON ujani_control.%I USING (tenant_id = current_setting(''ujani.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''ujani.tenant_id'', true))',
   table_name
  );
 END LOOP;
END $$;

COMMENT ON TABLE ujani_control.task_contract_replays IS
 'Tenant-scoped task ID and 32-byte nonce replay claims. Insert atomically before admission; retain tombstones according to the configured replay-retention policy. Stores digests only, never task payloads.';
COMMENT ON TABLE ujani_control.task_contract_sequences IS
 'Independent monotonic sequence watermarks for task_status and execution_receipt streams. Advance with a conditional upsert inside the same transaction as the authenticated message/task update.';
