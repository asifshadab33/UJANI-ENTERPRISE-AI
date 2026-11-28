# ADR proposal: self-hosted authenticated Enterprise control-plane host

- **Status:** Proposed — implementation must not begin from this ADR until the security review and provider-compatibility checklist are accepted.
- **Date:** 27 November 2026
- **Scope:** UJANI Enterprise only. No Public AI runtime dependency and no third repository.

## Context

The Enterprise policy crate already contains transport-independent device-trust, consent, lease, durable-ledger and operator-read primitives. The operator console is a static read-only preview. There is no deployed HTTP listener, OIDC adapter, production tenant-scoped repository, durable audit sink or live service endpoint.

The next step is an authenticated, customer-hosted control-plane adapter. It must not turn UJANI into a central compute provider, and it must not enable remote execution.

## Proposed decision

1. **Keep policy and transport separate.** Preserve `ujani-enterprise-policy` as the transport-independent policy/application core. Add a separate in-repository host crate only when implementation begins; do not put HTTP, browser, database-pool or IdP concerns into the policy crate.
2. **HTTP stack:** use Axum on Tokio, with Tower middleware and narrowly selected `tower-http` layers for request IDs, tracing, body limits, timeouts and security headers. Pin all dependencies and commit the Cargo.lock update. Do not add a generic reverse-proxy framework or a second application server.
3. **Identity:** use standards-based OpenID Connect Authorization Code flow with PKCE (S256), state and nonce. Use a maintained OIDC client library after checking its current release, MSRV, license and security posture. Validate issuer, audience, signature, expiry/not-before, nonce, authorised party where applicable, tenant membership, account status, role mapping and required MFA/conditional-access evidence before minting a UJANI session. Never accept tenant or role values from browser fields or headers.
4. **Session:** keep the existing short-lived, revocable operator-session policy contract. The browser receives only a `__Host-` cookie with Secure, HttpOnly and Path=/; no Domain attribute, localStorage, query-string token or JavaScript-readable credential. Do not blindly require `SameSite=Strict` for the OIDC transaction: a top-level cross-site Authorization Code callback may require a short-lived `SameSite=Lax` correlation cookie (or an explicitly tested equivalent). After callback validation, rotate into the application session and choose Lax/Strict based on browser end-to-end tests for the supported response mode. Enforce CSRF tokens, strict Origin checks and no state-changing GET routes.
5. **Database boundary:** use a service-owned PostgreSQL pool and transaction-scoped repository. End users, browser code and enrolled devices receive no database credentials or direct database path. Derive tenant identity from the verified server-side principal, set transaction-local tenant context inside the trusted service transaction, execute tenant-filtered queries, and reset/close the transaction before pool reuse. A caller-settable PostgreSQL custom GUC is not authentication.
6. **Audit:** successful and denied operator reads must produce a durable append-only audit record before a response is returned. Audit storage failure is fail-closed. Audit records contain actor, tenant, route, decision, correlation ID and timestamps, but no prompts, file contents, secrets or raw device logs.
7. **Deployment boundary:** support customer-hosted deployment behind a documented TLS-terminating reverse proxy. The service trusts forwarded headers only from an explicitly allowlisted proxy and must not be exposed on an unrestricted public interface by default. Document secrets, cookie, CSP, HSTS, backups, key rotation, readiness and recovery.
8. **Initial API scope:** ship only authenticated, read-only `GET /api/v1/operator/overview` and the bounded advisory model/task-match route after contract tests. No inventory mutation, approval mutation, lease creation, worker dispatch, remote execution, endpoint containment or firewall write route in this milestone.

## Required verification before production

- OIDC tests with a disposable local identity provider: wrong issuer/audience, invalid signature, nonce/state mismatch, expired/not-yet-valid token, missing tenant membership, disabled account, insufficient role and missing required MFA evidence.
- Tenant isolation tests: caller-supplied tenant ignored; cross-tenant reads/writes denied; custom-GUC spoofing cannot create a client database trust path; pooled connections cannot retain tenant context after commit, rollback or cancellation.
- Session tests: cookie flags, expiry, revocation, rotation, CSRF, Origin and replay behaviour, including cross-site IdP redirect/callback behaviour for every supported OIDC response mode. Prove the chosen SameSite policy does not break login while preserving CSRF and Origin protections.
- Audit tests: successful and denied reads are recorded; storage failure prevents response; retries do not duplicate or lose audit decisions.
- HTTP tests: malformed, oversized and slow requests; rate limits; timeouts; panic/error redaction; no credential or prompt leakage.
- Linux, Windows and macOS CI for policy/adapter code, plus browser end-to-end tests against the test IdP and disposable database.
- Independent review of the threat model and customer deployment guide.

## Consequences and non-goals

- The first release remains read-only and customer-hosted; compute tasks stay on the enrolled organisation's devices.
- OIDC tenant membership is the authentication source; PostgreSQL RLS and transaction-local context are defence-in-depth, not identity proof.
- The host must own the single authoritative transaction for tenant context, replay claims, admission/lease mutations and audit before any future worker admission is enabled.
- The existing file-backed registry/ledger split and independent rollback-anchor gap remain blockers for dispatch.
- HSM/KMS/TPM support, external monotonic anchoring, receiver-side process isolation and signed execution receipts remain separate P0 gates.
- This ADR does not authorise remote execution or change any runtime behaviour.

## Alternatives considered

- **Put Axum directly in the policy crate:** rejected because it couples core authorization to transport and database lifecycle.
- **Use browser-side tenant filtering or a caller-set PostgreSQL GUC as the boundary:** rejected because neither authenticates the caller or independently protects cross-tenant data.
- **Build the Vite/TypeScript console before the API contract is live:** rejected because it would create a polished but disconnected interface and duplicate unstable API assumptions.
- **Enable remote execution while the control plane is read-only:** rejected because trust, dual consent, transactional leases, protected key custody, isolation and recovery are not yet end-to-end proven.
