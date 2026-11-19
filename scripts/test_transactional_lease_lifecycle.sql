-- Run after migrations 0001-0015 and scripts/test_atomic_telemetry_lease_admission.sql.
-- Uses the admission-test fixture created by the earlier PostgreSQL integration
-- suite. All lifecycle mutations are executed as the non-BYPASSRLS runtime role.
SELECT pg_catalog.set_config('ujani.tenant_id','admission-test',false);

-- The runtime is deliberately not an owner, superuser or BYPASSRLS role. Its
-- lease writes are restricted to lifecycle columns; admission evidence remains
-- read-only even though the lifecycle functions use SECURITY INVOKER.
DO $block$
DECLARE
 v_superuser boolean;
 v_bypass_rls boolean;
BEGIN
 SELECT rolsuper, rolbypassrls INTO v_superuser, v_bypass_rls
 FROM pg_catalog.pg_roles WHERE rolname='ujani_runtime';
 IF v_superuser IS DISTINCT FROM false OR v_bypass_rls IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'ujani_runtime must remain non-superuser and non-BYPASSRLS';
 END IF;
 IF pg_catalog.has_column_privilege('ujani_runtime','ujani_control.leases','state','UPDATE') IS DISTINCT FROM true
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.leases','expires_at','UPDATE') IS DISTINCT FROM true
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.leases','manifest_digest','UPDATE') IS DISTINCT FROM false
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','reservation_revision','UPDATE') IS DISTINCT FROM true
    OR pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','owner_consent_state','UPDATE') IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'ujani_runtime lifecycle grants unexpected: lease state %, expiry %, manifest %, device reservation %, owner consent %',
   pg_catalog.has_column_privilege('ujani_runtime','ujani_control.leases','state','UPDATE'),
   pg_catalog.has_column_privilege('ujani_runtime','ujani_control.leases','expires_at','UPDATE'),
   pg_catalog.has_column_privilege('ujani_runtime','ujani_control.leases','manifest_digest','UPDATE'),
   pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','reservation_revision','UPDATE'),
   pg_catalog.has_column_privilege('ujani_runtime','ujani_control.devices','owner_consent_state','UPDATE');
 END IF;
END;
$block$;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';

-- Refresh authenticated telemetry so this test remains independent of the time
-- spent in the preceding migration and inventory tests. This call deliberately
-- runs under the narrow runtime role rather than the migration owner.
DO $block$
DECLARE accepted boolean;
BEGIN
 accepted := ujani_control.accept_device_telemetry_v2(
  'admission-test','admission-atomic-device',3,3,2,
  decode(repeat('e6',16),'hex'),clock_timestamp(),
  decode(repeat('e7',32),'hex'),4000,8192,'cool','ac','idle');
 IF accepted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'fresh telemetry for lease lifecycle test was rejected';
 END IF;
END;
$block$;

-- Create one lease using the existing authenticated-admission SQL primitive.
DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-atomic-device','admission-workload','admission-approval',
  'admission-lifecycle-lease',decode(repeat('e8',16),'hex'),decode(repeat('e9',32),'hex'),
  decode(repeat('44',32),'hex'),1,5,500,512,decode(repeat('ea',32),'hex'),
  clock_timestamp()+interval '2 minutes','00000000-0000-4000-8000-000000000206');
 IF admitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'lease lifecycle fixture admission was rejected';
 END IF;
END;
$block$;

-- Renewal requires the current device key, current owner consent generation,
-- current administrator approval and the same approved workload manifest.
DO $block$
DECLARE renewed boolean;
BEGIN
 renewed := ujani_control.renew_device_lease(
  'admission-test','admission-atomic-device','admission-workload',
  'admission-lifecycle-lease',1,5,
  decode(repeat('eb',16),'hex'),decode(repeat('ec',32),'hex'),
  decode(repeat('44',32),'hex'),clock_timestamp()+interval '4 minutes',
  '00000000-0000-4000-8000-000000000207');
 IF renewed IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'valid lease renewal was rejected';
 END IF;
END;
$block$;

-- The same request ID cannot renew twice, even when the second requested expiry
-- would otherwise be a valid extension.
DO $block$
DECLARE renewed boolean;
BEGIN
 renewed := ujani_control.renew_device_lease(
  'admission-test','admission-atomic-device','admission-workload',
  'admission-lifecycle-lease',1,5,
  decode(repeat('eb',16),'hex'),decode(repeat('ed',32),'hex'),
  decode(repeat('44',32),'hex'),clock_timestamp()+interval '4 minutes 30 seconds',
  '00000000-0000-4000-8000-000000000208');
 IF renewed IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'replayed lease renewal was accepted';
 END IF;
END;
$block$;

-- A stale owner-consent generation is denied without consuming its replay ID.
DO $block$
DECLARE renewed boolean;
BEGIN
 renewed := ujani_control.renew_device_lease(
  'admission-test','admission-atomic-device','admission-workload',
  'admission-lifecycle-lease',1,4,
  decode(repeat('ee',16),'hex'),decode(repeat('ef',32),'hex'),
  decode(repeat('44',32),'hex'),clock_timestamp()+interval '4 minutes 30 seconds',
  '00000000-0000-4000-8000-000000000209');
 IF renewed IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'stale consent generation renewed a lease';
 END IF;
END;
$block$;

-- A duplicate audit event forces the entire renewal transaction to roll back,
-- including its replay claim and expiry update.
DO $block$
DECLARE
 before_expiry timestamptz;
 after_expiry timestamptz;
 replay_count integer;
BEGIN
 SELECT expires_at INTO before_expiry FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-lifecycle-lease';
 BEGIN
  PERFORM ujani_control.renew_device_lease(
   'admission-test','admission-atomic-device','admission-workload',
   'admission-lifecycle-lease',1,5,
   decode(repeat('f0',16),'hex'),decode(repeat('f1',32),'hex'),
   decode(repeat('44',32),'hex'),clock_timestamp()+interval '4 minutes 45 seconds',
   '00000000-0000-4000-8000-000000000201');
  RAISE EXCEPTION 'duplicate renewal audit event did not fail';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;
 SELECT expires_at INTO after_expiry FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-lifecycle-lease';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
   AND request_id=decode(repeat('f0',16),'hex');
 IF after_expiry IS DISTINCT FROM before_expiry OR replay_count <> 0 THEN
  RAISE EXCEPTION 'failed renewal left a partial expiry or replay write';
 END IF;
END;
$block$;

-- A duplicate audit event must also roll back release state, capacity revision
-- and replay. The subsequent valid release must advance the device revision.
DO $block$
DECLARE
 before_revision bigint;
 after_revision bigint;
 lease_state text;
 replay_count integer;
BEGIN
 SELECT reservation_revision INTO before_revision FROM ujani_control.devices
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 BEGIN
  PERFORM ujani_control.release_device_lease(
   'admission-test','admission-atomic-device','admission-workload',
   'admission-lifecycle-lease',1,
   decode(repeat('f2',16),'hex'),decode(repeat('f3',32),'hex'),
   decode(repeat('44',32),'hex'),'00000000-0000-4000-8000-000000000201');
  RAISE EXCEPTION 'duplicate release audit event did not fail';
 EXCEPTION WHEN unique_violation THEN
  NULL;
 END;
 SELECT reservation_revision INTO after_revision FROM ujani_control.devices
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device';
 SELECT state INTO lease_state FROM ujani_control.leases
 WHERE tenant_id='admission-test' AND lease_id='admission-lifecycle-lease';
 SELECT count(*) INTO replay_count FROM ujani_control.request_replays
 WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
   AND request_id=decode(repeat('f2',16),'hex');
 IF after_revision <> before_revision OR lease_state <> 'reserved' OR replay_count <> 0 THEN
  RAISE EXCEPTION 'failed release left partial lease, capacity or replay state';
 END IF;
END;
$block$;

DO $block$
DECLARE released boolean;
BEGIN
 released := ujani_control.release_device_lease(
  'admission-test','admission-atomic-device','admission-workload',
  'admission-lifecycle-lease',1,
  decode(repeat('f4',16),'hex'),decode(repeat('f5',32),'hex'),
  decode(repeat('44',32),'hex'),'00000000-0000-4000-8000-000000000210');
 IF released IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'valid lease release was rejected';
 END IF;
END;
$block$;
COMMIT;
RESET ROLE;

-- Verify that release frees the reservation. The existing telemetry sample
-- predates the release, so the released lease must not be counted as an active
-- reservation when the same measured headroom is admitted again.
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';
DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-atomic-device','admission-workload','admission-approval',
  'admission-lifecycle-capacity-lease',decode(repeat('f6',16),'hex'),decode(repeat('f7',32),'hex'),
  decode(repeat('44',32),'hex'),1,5,4000,8192,decode(repeat('f8',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000211');
 IF admitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'released lease continued to consume capacity';
 END IF;
END;
$block$;
COMMIT;
RESET ROLE;

SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';
DO $block$
DECLARE released boolean;
BEGIN
 released := ujani_control.release_device_lease(
  'admission-test','admission-atomic-device','admission-workload',
  'admission-lifecycle-capacity-lease',1,
  decode(repeat('f9',16),'hex'),decode(repeat('fa',32),'hex'),
  decode(repeat('44',32),'hex'),'00000000-0000-4000-8000-000000000212');
 IF released IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'capacity verification lease could not be released';
 END IF;
END;
$block$;
COMMIT;
RESET ROLE;

-- Prepare a due lease for the separate concurrent expiry/reconciliation test.
SET ROLE ujani_runtime;
BEGIN;
SET LOCAL ujani.tenant_id='admission-test';
DO $block$
DECLARE admitted boolean;
BEGIN
 admitted := ujani_control.admit_device_lease(
  'admission-test','admission-atomic-device','admission-workload','admission-approval',
  'admission-lifecycle-expiry-race',decode(repeat('fb',16),'hex'),decode(repeat('fc',32),'hex'),
  decode(repeat('44',32),'hex'),1,5,500,512,decode(repeat('fd',32),'hex'),
  clock_timestamp()+interval '4 minutes','00000000-0000-4000-8000-000000000213');
 IF admitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'lease expiry fixture admission was rejected';
 END IF;
END;
$block$;

-- Test-only clock simulation: the expiry API itself never accepts a caller
-- supplied timestamp or state. Keep the due row reserved until concurrent calls
-- exercise the idempotent worker transition.
UPDATE ujani_control.leases
SET expires_at=clock_timestamp()-interval '1 second'
WHERE tenant_id='admission-test' AND lease_id='admission-lifecycle-expiry-race';

DO $block$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM ujani_control.leases
  WHERE tenant_id='admission-test' AND lease_id='admission-lifecycle-expiry-race'
    AND state='reserved' AND expires_at <= clock_timestamp()
 ) THEN
  RAISE EXCEPTION 'expiry concurrency fixture is not due and reserved';
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM ujani_control.devices
  WHERE tenant_id='admission-test' AND device_id='admission-atomic-device'
    AND owner_consent_state='granted' AND admin_approval_state='approved'
 ) THEN
  RAISE EXCEPTION 'lease lifecycle test lost its dual-consent fixture';
 END IF;
END;
$block$;
COMMIT;
RESET ROLE;
