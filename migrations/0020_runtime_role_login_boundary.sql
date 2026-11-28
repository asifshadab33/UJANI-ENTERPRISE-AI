-- Migration 0020: prevent direct login through the tenant-scoped runtime role.
--
-- The trusted customer-hosted service is the only principal allowed to assume
-- ujani_runtime. End users and devices must never receive database credentials.
-- This narrows the database boundary; it does not authenticate tenant context
-- on behalf of the service. The host must still derive tenant identity from
-- verified OIDC/device identity and set transaction-local context itself.

DO $block$
DECLARE
 v_runtime_role_oid oid;
 v_service_role_oid oid;
BEGIN
 SELECT oid INTO v_runtime_role_oid
 FROM pg_catalog.pg_roles
 WHERE rolname = 'ujani_runtime';
 IF v_runtime_role_oid IS NULL THEN
  RAISE EXCEPTION 'ujani_runtime must be provisioned before migration 0020'
   USING ERRCODE = '42704';
 END IF;

 SELECT oid INTO v_service_role_oid
 FROM pg_catalog.pg_roles
 WHERE rolname = 'ujani_service';
 IF v_service_role_oid IS NULL THEN
  RAISE EXCEPTION 'ujani_service must be provisioned before migration 0020'
   USING ERRCODE = '42704';
 END IF;

 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles
  WHERE oid = v_service_role_oid
    AND (rolcanlogin IS NOT TRUE OR rolsuper IS TRUE OR rolbypassrls IS TRUE
      OR rolcreatedb IS TRUE OR rolcreaterole IS TRUE OR rolreplication IS TRUE
      OR rolinherit IS TRUE)
 ) THEN
  RAISE EXCEPTION 'ujani_service must be LOGIN, NOINHERIT, non-owner and least-privileged'
   USING ERRCODE = '42501';
 END IF;

 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_namespace
  WHERE nspname = 'ujani_control' AND nspowner = v_service_role_oid
 ) OR EXISTS (
  SELECT 1 FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'ujani_control' AND c.relowner = v_service_role_oid
 ) THEN
  RAISE EXCEPTION 'ujani_service must not own the control schema or its objects'
   USING ERRCODE = '42501';
 END IF;

 -- Only the trusted service login may assume the runtime role. Fail closed
 -- rather than silently preserving an unknown or stale role membership.
 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members
  WHERE roleid = v_runtime_role_oid
    AND member <> v_service_role_oid
 ) THEN
  RAISE EXCEPTION 'ujani_runtime has unexpected member roles; only ujani_service may assume it'
   USING ERRCODE = '42501';
 END IF;

 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members
  WHERE member = v_service_role_oid
    AND roleid <> v_runtime_role_oid
 ) THEN
  RAISE EXCEPTION 'ujani_service has unexpected role memberships'
   USING ERRCODE = '42501';
 END IF;

 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members
  WHERE member = v_runtime_role_oid
 ) THEN
  RAISE EXCEPTION 'ujani_runtime must not inherit or assume additional roles'
   USING ERRCODE = '42501';
 END IF;

 EXECUTE 'ALTER ROLE ujani_runtime NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
 EXECUTE 'ALTER ROLE ujani_service LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';

 IF NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_auth_members
  WHERE roleid = v_runtime_role_oid AND member = v_service_role_oid
 ) THEN
  EXECUTE 'GRANT ujani_runtime TO ujani_service';
 END IF;

 -- The service must explicitly SET ROLE ujani_runtime for each transaction.
 -- Remove any direct grants that could bypass this boundary.
 EXECUTE 'REVOKE ALL ON SCHEMA ujani_control FROM ujani_service';
 EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA ujani_control FROM ujani_service';
 EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA ujani_control FROM ujani_service';
 EXECUTE 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ujani_control FROM ujani_service';

 IF EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles
  WHERE oid = v_runtime_role_oid AND rolcanlogin IS TRUE
 ) THEN
  RAISE EXCEPTION 'ujani_runtime must not be able to log in directly'
   USING ERRCODE = '42501';
 END IF;

 IF NOT pg_catalog.pg_has_role('ujani_service', 'ujani_runtime', 'MEMBER') THEN
  RAISE EXCEPTION 'ujani_service must be able to assume ujani_runtime'
   USING ERRCODE = '42501';
 END IF;
END;
$block$;

COMMENT ON ROLE ujani_runtime IS
 'NOLOGIN least-privilege tenant runtime; assumable only by trusted ujani_service';
COMMENT ON ROLE ujani_service IS
 'Trusted customer-hosted service login; credentials must never be issued to users or devices';
