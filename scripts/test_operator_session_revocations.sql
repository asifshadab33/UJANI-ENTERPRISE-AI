-- Executed after migrations 0001 and 0005 against PostgreSQL 16.
-- The owner creates fixture identities; runtime operations are tested under RLS.

INSERT INTO ujani_control.operator_subjects
 (tenant_id, subject_id, role, enabled, idp_issuer, idp_subject)
VALUES
 ('tenant-a','operator-a','administrator',true,'https://idp.example','subject-a'),
 ('tenant-b','operator-b','administrator',true,'https://idp.example','subject-b')
ON CONFLICT (tenant_id, subject_id) DO NOTHING;

GRANT SELECT, INSERT ON ujani_control.operator_session_revocations TO ujani_runtime;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';

DO $$
DECLARE visible_rows integer;
BEGIN
 INSERT INTO ujani_control.operator_session_revocations
  (tenant_id, subject_id, nonce, expires_at, revoked_at, reason, revoked_by_subject_id)
 VALUES
  ('tenant-a','operator-a',decode(repeat('11',16),'hex'),
   now() + interval '10 minutes', now(), 'logout', 'operator-a');

 SELECT count(*) INTO visible_rows
  FROM ujani_control.operator_session_revocations
  WHERE tenant_id = 'tenant-a' AND subject_id = 'operator-a';
 IF visible_rows <> 1 THEN
  RAISE EXCEPTION 'tenant A cannot read its own revocation record';
 END IF;

 SELECT count(*) INTO visible_rows
  FROM ujani_control.operator_session_revocations
  WHERE tenant_id = 'tenant-b';
 IF visible_rows <> 0 THEN
  RAISE EXCEPTION 'tenant A can read tenant B revocation records';
 END IF;

 BEGIN
  INSERT INTO ujani_control.operator_session_revocations
   (tenant_id, subject_id, nonce, expires_at, revoked_at, reason)
  VALUES
   ('tenant-b','operator-b',decode(repeat('22',16),'hex'),
    now() + interval '10 minutes', now(), 'admin_revoked');
  RAISE EXCEPTION 'cross-tenant revocation insert unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;

 BEGIN
  INSERT INTO ujani_control.operator_session_revocations
   (tenant_id, subject_id, nonce, expires_at, revoked_at, reason)
  VALUES
   ('tenant-a','operator-a',decode(repeat('11',16),'hex'),
    now() + interval '10 minutes', now(), 'logout');
  RAISE EXCEPTION 'duplicate session nonce unexpectedly succeeded';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;

 BEGIN
  UPDATE ujani_control.operator_session_revocations
   SET reason = 'security_incident'
   WHERE tenant_id = 'tenant-a' AND subject_id = 'operator-a';
  RAISE EXCEPTION 'runtime role unexpectedly updated immutable revocation evidence';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;

 BEGIN
  DELETE FROM ujani_control.operator_session_revocations
   WHERE tenant_id = 'tenant-a' AND subject_id = 'operator-a';
  RAISE EXCEPTION 'runtime role unexpectedly deleted revocation evidence';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
END $$;
ROLLBACK;
RESET ROLE;
