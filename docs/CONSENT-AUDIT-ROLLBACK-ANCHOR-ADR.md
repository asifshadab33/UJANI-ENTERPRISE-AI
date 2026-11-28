# ADR proposal: external monotonic anchor for consent and security audit state

- **Status:** Proposed — this is a design contract, not an implementation or production assurance.
- **Date:** 28 November 2026
- **Related findings:** #353 (authenticated tenant identity), #356 (database rollback)
- **Scope:** UJANI Enterprise only. No remote execution or cross-tenant data sharing is authorized by this proposal.

## Context and threat boundary

Migration `0018_durable_collective_defence_consent.sql` stores an append-only, tenant-scoped hash chain in PostgreSQL. The migration itself documents the limitation: a database owner or restore operation can replace the database with an older internally consistent snapshot. The in-database chain cannot independently establish that its head is the latest committed head.

The current `ujani.tenant_id` PostgreSQL custom setting is also caller-settable by a database client. A hash-chain checkpoint does not authenticate that caller. The service-only credential and verified-identity boundary in #353 is a prerequisite, not something this anchor design replaces.

## Proposed decision

Add a transport-independent `ConsentAuditAnchor` port to the future customer-hosted control-plane host. The port must be backed by a separately administered trust domain, such as a customer-controlled append-only anchor service with atomic conditional writes and KMS/HSM-backed signing, or an independently operated transparency/audit service with equivalent monotonic semantics. A KMS/HSM provides protected key custody; it is not by itself assumed to provide a monotonic counter or compare-and-swap API. A second table, schema, database, volume, backup, or role inside the same PostgreSQL trust/restore domain is **not** an external anchor.

Each checkpoint has a canonical, versioned representation containing:

- tenant identifier and checkpoint schema version;
- monotonic tenant sequence and previous checkpoint version;
- exact consent-audit chain head digest at that sequence;
- canonical checkpoint digest and an idempotency/request identifier;
- trusted anchor commit time supplied by the anchor service (not the application clock).

The anchor operation must provide an atomic compare-and-append contract:

1. A new checkpoint advances the tenant sequence strictly beyond the stored sequence and is bound to the expected previous checkpoint version.
2. A retry of the exact same checkpoint is idempotent and returns the original result.
3. The same tenant/sequence with a different digest, a lower sequence, a stale predecessor, or an unexpected fork is rejected and raises a security event.
4. The application cannot overwrite or delete an accepted checkpoint. Anchor key rotation must preserve verification of historical checkpoints.

For security-sensitive consent and lease authority transitions, use an explicit two-phase authority state:

1. In one PostgreSQL transaction, append the consent/lease audit event and persist the new generation as **pending-anchor**. A pending generation is not authoritative: every consent predicate and lease-admission path must reject it.
2. Append the exact tenant/sequence/head checkpoint to the external anchor using compare-and-append.
3. In a second PostgreSQL transaction, mark only that exact pending generation as anchored and persist the anchor receipt/version. The state becomes eligible for use only after the service verifies that the current external anchor still matches the stored generation and digest.

If the external append fails, the operation remains pending and unusable. If the process crashes after the external append but before the second database transaction, recovery verifies the external receipt and idempotently completes the anchored transition. If the database transaction or reconciliation is ambiguous, deny authority and require reconciliation; do not silently advance consent/lease authority or simply return success and retry in the background. The implementation must define an idempotent outbox/reconciliation protocol for every crash boundary.

Verify the externally anchored sequence and digest at service startup, after restore, and before any consent/lease decision that could authorize collection, transmission, admission or dispatch. If the database is behind the anchor, has a different digest at the anchored sequence, presents a fork, or the anchor is unavailable/stale, fail closed. Never infer that an older but internally valid PostgreSQL hash chain is current. Remote execution remains disabled.

## Restore and outage protocol

- A restored database behind the external checkpoint is quarantined from consent/lease writes and authority decisions.
- Recovery must replay or restore the append-only audit evidence up to the anchored sequence, verify every digest/link and current consent generation, then re-enable the affected tenant only after explicit reconciliation.
- If the external anchor cannot prove the current head, do not re-enable consent or leases based on local state alone.
- An anchor outage blocks new security-sensitive transitions and any decision requiring fresh anchored authority. Read-only diagnostics may remain available only if they are clearly labelled unverified and cannot trigger side effects.
- Retention, export, key rotation, customer ownership, outage SLAs and disaster-recovery responsibilities must be documented before production use.

## Required implementation and verification

- A fake anchor for deterministic unit tests and a customer-selected production adapter with authenticated, least-privilege credentials.
- Atomic compare-and-append, duplicate retry, same-sequence conflict, lower-sequence replay, fork, timeout, unavailable and key-rotation tests.
- Crash injection at every boundary: before DB commit, after DB commit/before anchor append, after anchor append/before acknowledgement, and during recovery.
- PostgreSQL snapshot-restore tests proving an older snapshot cannot restore revoked consent or a retired/revoked lease.
- Multi-tenant isolation tests proving the checkpoint key is tenant-scoped and the authenticated server principal—not a caller-supplied tenant field or custom GUC alone—selects the tenant.
- Tests for stale/missing anchors, anchor service rollback attempts, conflicting checkpoints and unavailable verification; all must deny security-sensitive use.
- Independent threat-model review and Linux/Windows/macOS customer-hosted deployment validation.

## Explicit non-claims

This ADR adds no anchor provider, key, network service, database migration or runtime gate. It does not close #356. It does not solve #353. The current PostgreSQL hash chain remains tamper-evident only within its stated trust assumptions, not rollback-proof. Collective Defence consent, telemetry collection/transmission and lease/dispatch paths must remain disabled until the authenticated service boundary and external anchor are implemented and verified end to end.
