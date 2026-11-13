# Enterprise Operator Control Plane — service contract and production gates

## Scope implemented in the current preview

The policy crate now contains `operator_control_plane`, a transport-independent application service core that:

- validates and authenticates HMAC-SHA256 signed, short-lived operator sessions;
- binds every session to a tenant, subject and role;
- caps session lifetime at 15 minutes and rejects future-issued, expired, malformed and tampered tokens;
- calls a repository with the authenticated tenant identifier (never a tenant supplied by the browser);
- rejects a repository response whose tenant does not match the authenticated session;
- validates overview schema, freshness, record limits, unique device IDs and non-contradictory fleet counts;
- requires an append-only audit sink to acknowledge each successful or denied overview read before returning a response (fail closed when audit is unavailable).

The console reads the versioned `GET /api/v1/operator/overview` response. The service core and UI currently share the contract, but the repository does **not yet contain a network listener, an OIDC/SAML adapter, a production database-backed overview repository, a durable audit sink, or a deployed endpoint**. The application is therefore not yet live-connected or production-ready.

## Identity and session boundary

The hosting identity adapter must verify the identity provider's signature, issuer, audience, nonce/state, tenant membership, account status, MFA/conditional-access policy and role mapping before calling `mint_after_identity_verification`. Never expose that method as a browser-callable route or accept tenant/role claims directly from a request.

The resulting token is opaque to the browser application but signed, not encrypted. It contains only subject ID, tenant ID, role, issue/expiry timestamps and a random nonce. Use a cryptographically secure random source for the nonce and a per-deployment signing key from a KMS/HSM/OS secret provider. Key material must not be stored beside application data. The current implementation has one active signing key; rotating it invalidates outstanding sessions. The policy core now exposes a fail-closed per-session revocation verifier contract. Migration `0005_operator_session_revocations.sql` supplies the tenant-scoped PostgreSQL tombstone schema; the hosting adapter must check it on every authenticated request and insert revocations in the same tenant context. The database migration and policy interface are foundations, not a completed SQL repository or HTTP logout route.

The HTTP adapter must set the token only in a cookie with `Secure; HttpOnly; SameSite=Strict; Path=/` and a `__Host-` prefix, never in local storage, query parameters or JavaScript-readable storage. Enforce HTTPS, HSTS, CSRF protections on every future state-changing route, strict response headers, origin checks and request/body limits. The overview route is GET-only and read-only.

## Repository and tenant isolation

Implement `OperatorOverviewRepository` against a durable database or service with tenant filtering in the query itself. Do not fetch all tenants and filter in the browser. The authenticated tenant must be part of every device, workload, approval, telemetry and lease query. Return only the minimum operational data needed by an operator; never expose prompts, model inputs, file paths, employee activity, secrets, raw device logs or provider credentials.

The service validates that the returned tenant matches the session. This is a second boundary, not a substitute for database row-level security and server-side authorization.

The inventory must keep separate counts for:
- registered devices;
- trusted devices with both individual owner consent and administrator approval;
- online devices with fresh authenticated telemetry;
- devices that pass policy and resource admission now.

A registered device is not automatically trusted, online or schedulable. Sleeping/offline/stale devices must not be counted as schedulable. Remaining RAM and CPU must already account for OS reserve and active leases exactly once. Fleet-wide RAM must never be represented as one pooled memory allocation for a single model.

## Audit and operational controls

Implement `OperatorAuditSink` using an append-only, durable, tamper-evident audit store. Each event should include authenticated tenant, subject, role, time and outcome. Do not include prompt content, tokens, secret values or raw telemetry. The current service fails closed if the audit sink cannot acknowledge the event.

Before production, add:
1. OIDC/SAML integration and administrator-managed tenant/role provisioning.
2. A durable, transactionally consistent multi-tenant inventory/telemetry/workload/approval repository.
3. An external monotonic anchor or equivalent rollback protection for critical trust and lease state; local HMAC files alone do not provide rollback resistance.
4. Production protected-provider loading, rotation authorization and revocation distribution. A versioned operator-session key ring with explicit key IDs and bounded overlap is now implemented in the policy core.
5. Key rotation, revocation and recovery procedures for device keys and storage integrity keys.
6. Rate limits, request-size/time limits, structured security logging, metrics, health/readiness endpoints and backup/restore drills.
7. Browser integration tests for unauthenticated, expired, revoked, cross-tenant, stale-snapshot and audit-unavailable cases.
8. Independent security review and controlled lab validation.

## Explicitly out of scope for this milestone

No remote command execution, workload dispatch, endpoint containment, firewall writes, employee monitoring or automatic cloud fallback is enabled. Approval screens must remain read-only until durable approval workflows, role separation, CSRF protection and audit transactions are implemented and reviewed.

## Local validation

The policy crate's unit tests exercise token integrity/expiry, tenant-boundary rejection, overview consistency and fail-closed audit behavior. Hosted CI additionally runs the workspace tests on Linux, Windows and macOS. These tests do not prove a production identity-provider integration, durable repository, live HTTP service, browser deployment or real device connectivity.

## Customer-hosted deployment foundation

The recommended customer-owned topology, initial PostgreSQL tenant/RLS migration, audit-event schema and implementation gates are documented in [Customer-hosted Control Plane Deployment](CUSTOMER-HOSTED-CONTROL-PLANE-DEPLOYMENT.md). The migration is a schema foundation, not a live database adapter; the operator console remains unavailable until a real authenticated service is deployed.
