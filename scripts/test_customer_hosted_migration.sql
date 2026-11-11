-- Executed after 0001_customer_hosted_control_plane.sql against a disposable PostgreSQL DB.
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ujani_runtime') THEN
  CREATE ROLE ujani_runtime LOGIN PASSWORD 'ci-only-test-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
 END IF;
END $$;
GRANT USAGE ON SCHEMA ujani_control TO ujani_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ujani_control TO ujani_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ujani_control TO ujani_runtime;
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('tenant-a','Tenant A'), ('tenant-b','Tenant B')
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO ujani_control.devices
 (tenant_id, device_id, display_name, platform, trust_state, owner_consent_state, admin_approval_state)
VALUES
 ('tenant-a','device-a','Device A','linux','enrolled','granted','approved'),
 ('tenant-b','device-b','Device B','linux','enrolled','granted','approved')
ON CONFLICT (tenant_id, device_id) DO NOTHING;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';
DO $$
DECLARE visible_tenants integer;
DECLARE visible_devices integer;
DECLARE bypass_rls boolean;
BEGIN
 SELECT count(*) INTO visible_tenants FROM ujani_control.tenants;
 SELECT count(*) INTO visible_devices FROM ujani_control.devices;
 SELECT rolbypassrls INTO bypass_rls FROM pg_roles WHERE rolname = current_user;
 IF visible_tenants <> 1 OR visible_devices <> 1 THEN
  RAISE EXCEPTION 'tenant RLS leak: tenants %, devices %', visible_tenants, visible_devices;
 END IF;
 IF bypass_rls THEN
  RAISE EXCEPTION 'runtime role unexpectedly has BYPASSRLS';
 END IF;
 BEGIN
  INSERT INTO ujani_control.devices
   (tenant_id, device_id, display_name, platform, trust_state, owner_consent_state, admin_approval_state)
  VALUES ('tenant-b','forged-device','Forged','linux','pending','unknown','pending');
  RAISE EXCEPTION 'cross-tenant insert unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
END $$;

INSERT INTO ujani_control.audit_events
 (tenant_id, event_id, actor_ref, actor_role, event_type, outcome, event_digest)
VALUES
 ('tenant-a','00000000-0000-4000-8000-000000000001','operator-a','administrator','ci.test','success',decode(repeat('ab',32),'hex'));

DO $$
BEGIN
 BEGIN
  UPDATE ujani_control.audit_events SET outcome = 'tampered'
   WHERE tenant_id = 'tenant-a' AND event_id = '00000000-0000-4000-8000-000000000001';
  RAISE EXCEPTION 'audit update unexpectedly succeeded';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM = 'audit update unexpectedly succeeded' THEN RAISE; END IF;
 END;
 BEGIN
  DELETE FROM ujani_control.audit_events
   WHERE tenant_id = 'tenant-a' AND event_id = '00000000-0000-4000-8000-000000000001';
  RAISE EXCEPTION 'audit delete unexpectedly succeeded';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM = 'audit delete unexpectedly succeeded' THEN RAISE; END IF;
 END;
END $$;
ROLLBACK;
RESET ROLE;
