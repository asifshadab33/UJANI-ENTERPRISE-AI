# UJANI Enterprise AI — external validation checklist

Status: prepared for a customer-hosted lab team. This checklist is not evidence that a production service exists or that any test has passed. Record exact commit SHAs, database version, deployment profile, OS build and test identities.

## A. Trusted-device lifecycle

- [ ] Enrollment requires a trusted administrator signature and new-device proof of possession.
- [ ] Key rotation requires old-key and new-key proofs; old generations fail immediately.
- [ ] Revocation persists across process restart and is fail-closed during registry/key-provider outage.
- [ ] Cross-tenant device lookup, enrollment, rotation and revocation are rejected.
- [ ] Replay protection survives concurrent instances, restart and backup restore.
- [ ] Protected key-provider and external monotonic-anchor behavior is tested with outage, ambiguous response and stale snapshot cases.

## B. Authenticated lease and scheduling

- [ ] Every request binds tenant, device, key generation, method, resource, request ID, expiry, body digest, workload ID and manifest digest.
- [ ] Acquire, renew, release, cancel and expiry are idempotent under concurrent requests.
- [ ] Expired, revoked, stale-generation, wrong-owner and wrong-manifest requests fail closed.
- [ ] Resource reservations reconcile CPU/memory limits and telemetry watermarks across restart.
- [ ] Owner pause, user activity, schedule, power, thermal, data-classification and egress gates are rechecked immediately before work.
- [ ] No sleeping or powered-off device is awakened.
- [ ] Remote workload dispatch remains disabled throughout this validation phase.

## C. Telemetry admission and resource freshness

- [ ] Verify every telemetry request is authenticated and signed by the enrolled device before the SQL admission function is called.
- [ ] Bind tenant context from authenticated identity; never accept tenant identity from request JSON.
- [ ] Reject replayed request IDs, duplicate or regressing generation/sequence values, stale/future timestamps and malformed resource values.
- [ ] Verify admission fails when device trust is revoked, owner consent is withdrawn or administrator approval is denied.
- [ ] Verify telemetry rows and device checkpoints roll back atomically on transaction failure.
- [ ] Verify concurrent samples serialize on the device row and preserve the highest accepted generation/sequence.
- [ ] Verify telemetry contains only bounded capacity, thermal, power and participation metadata—not prompts, file contents, local paths, process command lines or employee activity.
- [ ] Verify tenant RLS isolates samples and missing tenant context fails closed.

**Known limitation:** the SQL function is a SECURITY INVOKER admission boundary, not a signature verifier or network endpoint. A production authenticated device agent/service adapter is still required.

## D. Tenant persistence and operator identity

- [ ] Apply the migration using a separate migration-owner identity.
- [ ] Verify runtime role has no tenant-registry INSERT/UPDATE/DELETE and no BYPASSRLS.
- [ ] Verify every request sets tenant context from authenticated identity using transaction-local state.
- [ ] Test cross-tenant reads/writes, missing tenant context, SQL injection attempts and concurrent transactions.
- [ ] Test transaction rollback, connection-pool reuse and tenant-context leakage between pooled connections.
- [ ] Verify operator OIDC issuer, audience, signature, nonce/state, MFA, tenant membership and role mapping.
- [ ] Verify audit event and business mutation are transactionally consistent before any mutation endpoint is enabled.
- [ ] Test database failover, backup/restore, rollback protection and external checkpoint recovery.

**Known limitation:** the current Enterprise repository contains a PostgreSQL schema/migration and policy interfaces, but no production Rust PostgreSQL repository, OIDC/HTTP hosting adapter or atomic cross-store transaction service. The schema CI test is not evidence of those components.

## E. Operator console and deployment

- [ ] Connect the console only to a real authenticated service; no mock fleet data in production.
- [ ] Verify viewer/operator/administrator role separation and tenant scoping.
- [ ] Verify session expiry, key rotation, CSRF/origin checks, HTTPS and secure cookies.
- [ ] Test service health/readiness, request size/rate limits, structured redacted logs and audit availability.
- [ ] Test customer-selected deployment profiles, preflight sizing, optional component installation and rollback.
- [ ] Confirm no central UJANI-operated service receives customer fleet data by default.

## F. Security and operational safety

- [ ] Independently review threat model, service account permissions, key custody, backup strategy and anti-rollback design.
- [ ] Test worker isolation, network egress denial, filesystem scope, resource quotas and emergency stop on each supported OS.
- [ ] Test worker loss, controller loss, database outage, time skew, clock rollback and partial output.
- [ ] Verify consent withdrawal and administrator revocation stop future scheduling.
- [ ] Verify audit contains no prompts, raw workload data, private keys or credentials.
- [ ] Confirm optional collective-defence integrations are read-only by default and separately opted in by the organisation and participant.

## G. Evidence and release decision

For each test record: test ID, tenant fixture, tester role, device identity (non-secret), OS/build, service commit, schema version, database version, policy/config version, steps, expected/actual result, redacted logs, pass/fail, severity and linked issue/PR.

Do not enable remote execution, autonomous containment or production workload dispatch until tenant persistence, authenticated hosting, durable audit, protected key custody, external anti-rollback, lease atomicity, OS isolation and independent security review have all passed.
