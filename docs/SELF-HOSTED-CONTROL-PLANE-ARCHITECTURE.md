# UJANI Enterprise self-hosted control plane architecture

Status: accepted implementation baseline, subject to security review before deployment.

## Product decision

UJANI Enterprise is deployed and operated by the customer. UJANI does not require a UJANI-operated central cloud, central fleet database, or central compute service. The customer chooses the deployment location, identity provider, data residency, retention and device participation policy.

The control plane coordinates customer-owned resources; it does not turn separate devices' RAM into one shared memory pool. A workload is eligible only when a specific device has enough available capacity after operating-system reserves and existing leases.

## Default deployment profile

- HTTP service: Rust with Axum, Tokio and Tower middleware. Keep the service separate from the side-effect-free ujani-enterprise-policy crate.
- Database: customer-managed PostgreSQL with SQLx migrations and transaction support. Tenant filters and row-level security are enforced in the database/repository, never in browser code.
- Identity: OIDC provider selected by the customer. Keycloak is the self-hostable reference profile; Microsoft Entra ID and other conforming OIDC providers may be configured. The server validates issuer, audience, signature, nonce/state, tenant membership, account status and mapped roles before minting a UJANI session.
- Secrets and keys: provider interface for customer-selected KMS/HSM/TPM/OS secret stores. No production signing key may be read from the writable application data directory, a database row or a browser request. Rotation, revocation, recovery and key identifiers are explicit.
- Transport: HTTPS at the service boundary. Secure __Host- HttpOnly SameSite cookies, strict Origin checks, CSRF tokens for mutations, CSP/HSTS and bounded request/response sizes. The service must refuse unsafe production bind/configuration rather than silently expose an unauthenticated listener.
- Audit: append-only, tamper-evident tenant-scoped audit records. Security-critical operations fail closed if the audit transaction cannot commit.
- Console: same-origin read-only operator console. It displays real authenticated API data or a clear unavailable/unknown state; no demo fleet, invented health, or client-side authorization.

## Keep the first release simple

The initial administrator journey should be a guided setup wizard:

1. Choose Single server or Existing organisation platform. Explain the trade-off in plain language.
2. Connect the organisation's identity provider and verify the callback before proceeding.
3. Select the database and key provider. Run connection and permission checks; never ask the user to paste private keys into the console.
4. Review the data collected, retention, device participation and region. Defaults are local to the customer and read-only.
5. Enrol one test device, verify its identity and owner consent, then show its last authenticated heartbeat.
6. Invite additional administrators and operators with least-privilege roles.
7. Finish with a readiness report and a clear list of any unavailable protections.

Advanced settings belong behind an Advanced section. Do not require ordinary operators to understand cryptographic algorithms, SQL, container orchestration or lease internals.

## Trust and workload gates

The control plane is delivered in stages:

- Stage 0 — Read-only service: health/readiness, authenticated login, tenant-scoped overview, durable audit and read-only inventory.
- Stage 1 — Device trust: invitation/enrollment, proof of possession, owner consent, administrator approval, key rotation/revocation, freshness and anti-rollback.
- Stage 2 — Authenticated leases: acquire/renew/release bound to tenant, enrolled device, workload manifest digest, policy version, resource reservation and expiry. Atomic ledger + audit transactions and replay tests are mandatory.
- Stage 3 — Read-only workload visibility: show queued/approved/expired states and reasons. No dispatch.
- Later, separately reviewed: isolated workload receiver and execution only after receiver-side authorization, OS sandboxing, protected key custody, independent security review and explicit customer enablement.

Remote execution, arbitrary shell, autonomous containment and cross-tenant telemetry are disabled in every initial stage.

## Privacy and resource policy

- Local-first by default; no task prompts or user files are sent to a cloud provider by this control plane.
- No device telemetry is collected until the tenant and individual participation policy allow it.
- Do not upload file contents, prompts, credentials, raw command lines or unrestricted logs.
- Use bounded, low-frequency/event-driven health reporting, backoff, cancellation and device pause controls.
- Never schedule on a device whose telemetry is stale, consent is missing/revoked, trust is uncertain, or OS reserves leave insufficient capacity.
- Make retention and deletion visible and tenant-configurable.

## Reliability and recovery

- Migrations are versioned and reversible where safe; destructive migrations require backup and explicit operator confirmation.
- Provide backup/restore drills, health/readiness endpoints, structured redacted logs, metrics, bounded retries, idempotency keys and an operator runbook.
- A database, identity, key-provider or audit outage must not silently downgrade authorization or permit dispatch.
- External monotonic rollback protection is required for durable trust/lease state; a hash or MAC stored beside a writable ledger is not sufficient.

## Acceptance gates

Before a customer production deployment:

- OIDC login/callback tests with a local test IdP.
- Cross-tenant and role-boundary tests at database and HTTP layers.
- Missing, expired, tampered, revoked and rotated key/session tests.
- CSRF, Origin, cookie, HTTPS, request-size and timeout tests.
- Concurrent lease, replay, expiry, restart, ledger-tampering and audit-failure tests.
- Backup/restore and key-recovery drills.
- Linux, Windows and macOS CI where applicable, plus controlled customer-lab validation.
- Independent security review and a documented threat model.

Passing unit/CI tests is not a substitute for customer deployment validation or independent review.
