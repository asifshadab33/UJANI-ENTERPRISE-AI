# Architecture decision: PostgreSQL is the production authority

Status: accepted architecture decision (2026-11-22). This records the production persistence boundary; it does not claim that a production HTTP service or live fleet control plane is implemented.

## Decision

PostgreSQL is the **single authoritative production store** for tenant-bound device identity, enrollment and key-generation state, owner consent, administrator approval, request replay/idempotency, telemetry freshness and watermarks, reservations, leases, and durable audit.

The production authenticated service must make each security-sensitive state transition through the existing tenant-scoped PostgreSQL functions and migrations. Identity and tenant scope must be derived from verified authentication and trusted repository state, never from caller-supplied tenant/device/role fields.

The Rust `DurableDeviceRegistry` and `DurableLedger` remain useful policy/persistence adapters for development, isolated local use and tests. They must **not independently authorize production leases**, and production must not dual-write to PostgreSQL and the file-backed ledger as competing authorities.

## Existing foundations to reuse

The repository already contains policy and persistence primitives, signed device-request and telemetry admission contracts, owner-consent checks, replay/freshness validation, and PostgreSQL migration work. Relevant database milestones include:

- `0008_atomic_device_lease_admission.sql`: atomic device-lease admission foundation.
- `0010`: atomic telemetry/lease admission work.
- `0013`: revoke leases when owner consent changes; a later grant does not reactivate revoked leases.
- `0015`: transactional lease lifecycle.
- `0016`: authenticated telemetry v3 database admission, including replay, monotonic generation/sequence, freshness, reservation watermark and audit coupling.

These are foundations, not evidence of a deployed authenticated service. Reuse and test them; do not create a second registry, schema, admission function or lease engine.

## Required production request path

1. The HTTP host authenticates the caller/device using the approved OIDC and device-signature boundary, with TLS/server identity and strict request limits.
2. The host verifies the exact signed request bytes and device key generation using the existing policy boundary. It must not parse and reserialize signed telemetry before checking its body digest.
3. Tenant, device, key ID/generation, request ID, telemetry and workload identity are derived from the authenticated principal and trusted tenant-scoped repository. Untrusted request fields are not authoritative.
4. In one PostgreSQL transaction, set tenant context from that authenticated principal and invoke the existing `SECURITY INVOKER` functions. The transaction must bind replay/idempotency, current trust and consent, administrator policy, telemetry generation/freshness, capacity/reservation or lease mutation, and the corresponding durable audit event.
5. Any authorization, audit, key-provider, repository or transaction failure fails closed. Ambiguous outcomes must be reconciled from PostgreSQL state; the service must not retry a consumed request/challenge blindly.
6. The operator console may display production state only from authenticated, tenant-scoped service responses. Demo fixtures must remain visibly labelled and must never be mixed with live records.

The database functions do not verify Ed25519 signatures. They may be called only after the Rust/device-authentication boundary succeeds. The host must not treat SQL admission alone as proof that the HTTP caller was authenticated.

## Prohibited split-brain patterns

- No production lease may be authorized solely by the file-backed Rust ledger.
- No independent PostgreSQL and file-ledger decisions for the same production device or lease.
- No dual-write sequence in which one store commits while the other is treated as authoritative.
- No browser-supplied tenant ID, device ID, consent flag, approval state or trust label as authorization.
- No cached eligibility or stale telemetry as a substitute for current database checks.
- No remote execution, worker dispatch, model distribution or endpoint containment as a side effect of enrollment or admission.

## Remaining implementation and verification gates

This decision does not close the authenticated control-plane work. Before production use, the project still needs:

- A maintained Rust HTTP host with verified OIDC/tenant RBAC, device authentication, TLS deployment boundary, CSRF/origin protections, bounded bodies, timeouts and graceful shutdown.
- Production protected key provisioning, rotation, revocation, backup and recovery, plus independently protected anti-rollback state.
- Tenant-scoped PostgreSQL repositories and a single transaction for replay, consent/trust, admission, lease/reservation mutation and audit.
- Durable telemetry/inventory persistence and retention, operator-console integration with real authenticated data, and fail-closed audit behavior.
- Concurrency, restart, crash/ambiguous-commit, backup/restore, replay, revocation, owner-withdrawal, cross-tenant and audit-failure tests.
- Independent security review and deployment/operations runbooks.

Remote execution and worker dispatch remain disabled until these gates are implemented, tested and independently reviewed. Passing CI for policy code or SQL migrations alone is not production readiness.

## Relationship to cross-platform packaging

Windows, Linux and macOS adapters share this production authority. An OS adapter may collect bounded, privacy-minimised measurements and prove device identity, but it cannot establish tenant trust, override consent, or authorize a lease locally. Optional platform packages do not create separate per-OS admission authorities.
