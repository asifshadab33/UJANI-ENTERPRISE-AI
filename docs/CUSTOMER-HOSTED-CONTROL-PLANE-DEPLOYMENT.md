# Customer-hosted Enterprise control-plane deployment

Status: implementation blueprint plus initial database migration. This is not yet a deployable service. The repository intentionally does not ship a UJANI-operated central server.

## Deployment ownership

Each customer deploys and operates the control plane inside its own approved environment. The customer owns DNS, TLS certificates, identity provider, database, backups, key custody, retention, operator accounts and incident response. UJANI source code provides the service and protocol implementation; it does not receive customer fleet data by default.

Recommended initial topology:
- Rust HTTP service using Axum/Tokio, bound only to the customer-approved private interface or reverse proxy.
- Customer OIDC provider (for example, Keycloak or Microsoft Entra ID) for login, MFA and group/role mapping. No local password database.
- PostgreSQL as the authoritative tenant-scoped repository.
- Customer-selected protected key provider (TPM-backed service, HSM, KMS or OS/enterprise secret manager) for operator-session, device-admin and storage-integrity keys.
- Separately protected monotonic checkpoint/anchor for critical trust and lease state.
- Static read-only operator console served same-origin by the service or customer reverse proxy.

Do not make PostgreSQL, key-provider or management endpoints public. Do not expose a generic command runner. No remote workload dispatch, endpoint containment or firewall writes are enabled by this blueprint.

## Identity and sessions

The identity adapter must validate OIDC issuer, audience, signature, state/nonce, expiry, account status, tenant membership, MFA/conditional access and customer-managed role mapping before constructing trusted identity claims. The browser never chooses a tenant or role.

The service core supports:
- Short-lived, signed sessions (maximum 15 minutes).
- A versioned key-ring token format with an explicit key ID.
- One active signing key plus up to three configured previous keys during a controlled overlap.
- Immediate rejection of tokens signed by a key removed from the configured ring.
- A provider interface that supports customer HSM/KMS/OS-backed MAC signing and verification without exporting key material into the service process; the current software key ring is the tested reference implementation.

The key ring is only a verifier/signer primitive. Production key retrieval, rotation authorization, revocation distribution, secure cookie transport, CSRF, HTTPS and OIDC integration remain responsibilities of the not-yet-built hosting adapter. Do not place keys in environment dumps, logs, browser storage or writable application-data directories.

## Database migration foundation

The initial PostgreSQL schema is in migrations/0001_customer_hosted_control_plane.sql. It establishes composite tenant keys and foreign keys, device/key lifecycle state, owner-consent evidence, workload and approval records, leases, replay identifiers and append-only audit event rows.

Tenant-owned tables enforce row-level security using the transaction-local setting ujani.tenant_id. Every request must:
1. Authenticate the operator/device before opening the business transaction.
2. Begin a database transaction.
3. Set ujani.tenant_id with SET LOCAL from the authenticated principal, never from request JSON.
4. Perform all tenant reads/writes through that transaction.
5. Commit audit event and state mutation together.
6. Roll back on any failure.

The application database role must not own the schema/tables, must not have BYPASSRLS, and must not be superuser. Migration credentials are separate from runtime credentials. The audit append path must serialize/hash-chain event sequence and previous digest in the same transaction; the trigger prevents UPDATE/DELETE but is not, by itself, cryptographic tamper evidence against a database administrator. Export signed checkpoints to the external monotonic anchor.

**RLS threat boundary:** the transaction-local custom setting is writable by SQL executed under the same application role. These policies protect against omitted tenant predicates and accidental cross-tenant queries; they do not, by themselves, withstand arbitrary SQL injection or a fully compromised runtime database credential. The service must use parameterized queries, prohibit dynamic SQL, expose no user-controlled SQL path and keep the runtime role least-privileged. Before production, security review must decide whether stronger isolation requires per-tenant database roles or a separately verified tenant-context mechanism. The PostgreSQL CI test validates policy behavior for correctly set context; it is not a SQL-injection or compromised-role test.

The migration is a foundation only: it does not yet provide SQLx repository code, transaction wrappers, connection-pool tenant context or a production audit writer. CI now applies the migration to a disposable PostgreSQL 16 service and tests cross-tenant read/write isolation plus audit update/delete rejection; this validates the schema boundary, not the future Rust repository or production deployment.

## Ordered implementation gates

1. OIDC adapter and role mapping; no browser-supplied tenant or role.
2. PostgreSQL repository using per-transaction tenant context and RLS, with integration tests for cross-tenant reads/writes.
3. Atomic idempotency/replay + device trust + lease + audit transaction; no split commit across independent stores.
4. Durable hash-chained audit writer and signed external checkpoints.
5. Protected key-provider interface and rotation/revocation workflows.
6. Axum HTTPS adapter with bounded bodies/timeouts, rate limits, secure cookies, CSRF/origin checks, security headers and health/readiness.
7. Read-only console integration against the real service; no fabricated/demo fleet state.
8. Independent security review and controlled lab tests.

Remote dispatch remains disabled until all trust, isolation, lease, audit, consent and independent-review gates are complete.
