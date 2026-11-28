-- Run after migrations 0001-0020 on a disposable PostgreSQL 16 database.
-- Proves the runtime role cannot be used as a direct login and an untrusted
-- database principal cannot invoke tenant routines even after setting the
-- caller-writable custom GUC. The authenticated service remains responsible
-- for deriving tenant context from verified identity.

DO $setup$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ujani_untrusted_test'
 ) THEN
  EXECUTE 'CREATE ROLE ujani_untrusted_test LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
 END IF;
END;
$setup$;

DO $roles$
DECLARE
 v_runtime_can_login boolean;
 v_service_can_login boolean;
BEGIN
 SELECT rolcanlogin INTO v_runtime_can_login
 FROM pg_catalog.pg_roles WHERE rolname = 'ujani_runtime';
 SELECT rolcanlogin INTO v_service_can_login
 FROM pg_catalog.pg_roles WHERE rolname = 'ujani_service';

 IF v_runtime_can_login IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'ujani_runtime must be NOLOGIN';
 END IF;
 IF v_service_can_login IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'ujani_service must be the dedicated LOGIN role';
 END IF;
 IF NOT pg_catalog.pg_has_role('ujani_service', 'ujani_runtime', 'MEMBER') THEN
  RAISE EXCEPTION 'trusted service cannot assume runtime role';
 END IF;
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members
  WHERE roleid = 'ujani_runtime'::regrole
    AND member <> 'ujani_service'::regrole
 ) THEN
  RAISE EXCEPTION 'a principal other than ujani_service can assume ujani_runtime';
 END IF;
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members
  WHERE roleid = 'ujani_service'::regrole
 ) THEN
  RAISE EXCEPTION 'ujani_service is assumable by another role';
 END IF;
 IF pg_catalog.pg_has_role('ujani_untrusted_test', 'ujani_runtime', 'MEMBER') THEN
  RAISE EXCEPTION 'untrusted test principal can assume runtime role';
 END IF;
 IF pg_catalog.has_function_privilege(
  'ujani_service',
  'ujani_control.collective_defence_consent_is_current(text,text,text)',
  'EXECUTE'
 ) THEN
  RAISE EXCEPTION 'service must SET ROLE ujani_runtime instead of inheriting routine privileges';
 END IF;
 IF pg_catalog.has_function_privilege(
  'ujani_untrusted_test',
  'ujani_control.collective_defence_consent_is_current(text,text,text)',
  'EXECUTE'
 ) THEN
  RAISE EXCEPTION 'untrusted principal unexpectedly has consent routine EXECUTE';
 END IF;
 IF pg_catalog.has_table_privilege(
  'ujani_untrusted_test',
  'ujani_control.collective_defence_tenant_consent',
  'SELECT'
 ) THEN
  RAISE EXCEPTION 'untrusted principal unexpectedly has consent table SELECT';
 END IF;
END;
$roles$;

-- The trusted service can explicitly assume the NOLOGIN runtime role.
SET SESSION AUTHORIZATION ujani_service;
SET ROLE ujani_runtime;
DO $service$
BEGIN
 IF current_user <> 'ujani_runtime' THEN
  RAISE EXCEPTION 'trusted service did not enter the runtime role';
 END IF;
END;
$service$;
RESET ROLE;
RESET SESSION AUTHORIZATION;

-- An untrusted SQL client can set a custom GUC, but cannot invoke SECURITY
-- DEFINER consent routines or read tenant consent tables.
SET SESSION AUTHORIZATION ujani_untrusted_test;
DO $untrusted$
DECLARE
 v_execute_denied boolean := false;
 v_read_denied boolean := false;
BEGIN
 PERFORM pg_catalog.set_config('ujani.tenant_id', 'tenant-b', true);

 BEGIN
  PERFORM ujani_control.collective_defence_consent_is_current(
   'tenant-b', 'user-b', 'device-b'
  );
 EXCEPTION WHEN insufficient_privilege THEN
  v_execute_denied := true;
 END;
 IF NOT v_execute_denied THEN
  RAISE EXCEPTION 'untrusted principal invoked consent routine after setting tenant GUC';
 END IF;

 BEGIN
  PERFORM 1 FROM ujani_control.collective_defence_tenant_consent;
 EXCEPTION WHEN insufficient_privilege THEN
  v_read_denied := true;
 END;
 IF NOT v_read_denied THEN
  RAISE EXCEPTION 'untrusted principal read tenant consent table after setting tenant GUC';
 END IF;
END;
$untrusted$;
RESET SESSION AUTHORIZATION;

DROP ROLE ujani_untrusted_test;
