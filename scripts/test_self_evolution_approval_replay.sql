-- Executed after migrations 0001 and 0006 on a disposable PostgreSQL database.
-- Requires the ujani_runtime role created by test_customer_hosted_migration.sql.
INSERT INTO ujani_control.tenants (tenant_id, display_name)
VALUES ('tenant-a','Tenant A'), ('tenant-b','Tenant B')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO ujani_control.operator_subjects
 (tenant_id, subject_id, role, enabled, idp_issuer, idp_subject)
VALUES
 ('tenant-a','admin-a','administrator',true,'https://idp.example.test','subject-admin-a'),
 ('tenant-b','admin-b','administrator',true,'https://idp.example.test','subject-admin-b')
ON CONFLICT (tenant_id, subject_id) DO NOTHING;

GRANT SELECT, INSERT ON ujani_control.self_evolution_approval_replays TO ujani_runtime;
REVOKE UPDATE, DELETE ON ujani_control.self_evolution_approval_replays FROM ujani_runtime;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id = 'tenant-a';

DO $$
DECLARE
 inserted_id text;
 visible_rows integer;
 can_update boolean;
 can_delete boolean;
BEGIN
 -- The host inserts only after signature, proposal digest and trusted-target checks.
 -- ON CONFLICT DO NOTHING RETURNING is the atomic single-use consumption operation.
 INSERT INTO ujani_control.self_evolution_approval_replays
  (tenant_id, approval_id, approver_subject_id, approver_key_id, nonce,
   repository, base_ref, source_revision, proposal_sha256, target_sha256,
   approved_scope_sha256, approved_scope_count, expires_at)
 VALUES
  ('tenant-a','approval-a','admin-a','admin-key-a',decode(repeat('11',16),'hex'),
   'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
   decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
   decode(repeat('44',32),'hex'),1,now() + interval '5 minutes')
 ON CONFLICT DO NOTHING
 RETURNING approval_id INTO inserted_id;
 IF inserted_id IS DISTINCT FROM 'approval-a' THEN
  RAISE EXCEPTION 'first verified approval consumption did not insert exactly once';
 END IF;

 -- Reusing the same nonce with a different approval ID is a replay.
 BEGIN
  INSERT INTO ujani_control.self_evolution_approval_replays
   (tenant_id, approval_id, approver_subject_id, approver_key_id, nonce,
    repository, base_ref, source_revision, proposal_sha256, target_sha256,
    approved_scope_sha256, approved_scope_count, expires_at)
  VALUES
   ('tenant-a','approval-b','admin-a','admin-key-a',decode(repeat('11',16),'hex'),
    'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
    decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
    decode(repeat('44',32),'hex'),1,now() + interval '5 minutes')
  ON CONFLICT DO NOTHING
  RETURNING approval_id INTO inserted_id;
  IF inserted_id IS NOT NULL THEN
   RAISE EXCEPTION 'replayed approval nonce was consumed twice';
  END IF;
 END;

 -- Reusing the same approval ID with a new nonce is also a replay.
 BEGIN
  INSERT INTO ujani_control.self_evolution_approval_replays
   (tenant_id, approval_id, approver_subject_id, approver_key_id, nonce,
    repository, base_ref, source_revision, proposal_sha256, target_sha256,
    approved_scope_sha256, approved_scope_count, expires_at)
  VALUES
   ('tenant-a','approval-a','admin-a','admin-key-a',decode(repeat('55',16),'hex'),
    'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('a',40),
    decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
    decode(repeat('44',32),'hex'),1,now() + interval '5 minutes')
  ON CONFLICT DO NOTHING
  RETURNING approval_id INTO inserted_id;
  IF inserted_id IS NOT NULL THEN
   RAISE EXCEPTION 'replayed approval ID was consumed twice';
  END IF;
 END;

 SELECT count(*) INTO visible_rows
  FROM ujani_control.self_evolution_approval_replays;
 IF visible_rows <> 1 THEN
  RAISE EXCEPTION 'tenant-a should see one consumed approval, got %', visible_rows;
 END IF;

 SELECT has_table_privilege(current_user,
   'ujani_control.self_evolution_approval_replays','UPDATE'),
        has_table_privilege(current_user,
   'ujani_control.self_evolution_approval_replays','DELETE')
 INTO can_update, can_delete;
 IF can_update OR can_delete THEN
  RAISE EXCEPTION 'runtime role can mutate or erase consumed approval tombstones';
 END IF;

 BEGIN
  UPDATE ujani_control.self_evolution_approval_replays
   SET proposal_sha256 = decode(repeat('99',32),'hex')
   WHERE tenant_id = 'tenant-a' AND approval_id = 'approval-a';
  RAISE EXCEPTION 'runtime update unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
 BEGIN
  DELETE FROM ujani_control.self_evolution_approval_replays
   WHERE tenant_id = 'tenant-a' AND approval_id = 'approval-a';
  RAISE EXCEPTION 'runtime delete unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;

 PERFORM set_config('ujani.tenant_id','tenant-b',true);
 SELECT count(*) INTO visible_rows
  FROM ujani_control.self_evolution_approval_replays;
 IF visible_rows <> 0 THEN
  RAISE EXCEPTION 'tenant-b can see tenant-a approval replay rows';
 END IF;

 PERFORM set_config('ujani.tenant_id','',true);
 SELECT count(*) INTO visible_rows
  FROM ujani_control.self_evolution_approval_replays;
 IF visible_rows <> 0 THEN
  RAISE EXCEPTION 'missing tenant context did not fail closed for approval replay rows';
 END IF;

 PERFORM set_config('ujani.tenant_id','tenant-a',true);
 BEGIN
  INSERT INTO ujani_control.self_evolution_approval_replays
   (tenant_id, approval_id, approver_subject_id, approver_key_id, nonce,
    repository, base_ref, source_revision, proposal_sha256, target_sha256,
    approved_scope_sha256, approved_scope_count, expires_at)
  VALUES
   ('tenant-b','forged-approval','admin-b','admin-key-b',decode(repeat('66',16),'hex'),
    'asifshadab33/UJANI-ENTERPRISE-AI','main',repeat('b',40),
    decode(repeat('77',32),'hex'),decode(repeat('88',32),'hex'),
    decode(repeat('99',32),'hex'),1,now() + interval '5 minutes');
  RAISE EXCEPTION 'cross-tenant approval replay insert unexpectedly succeeded';
 EXCEPTION WHEN insufficient_privilege THEN
  NULL;
 END;
END $$;

ROLLBACK;
RESET ROLE;
