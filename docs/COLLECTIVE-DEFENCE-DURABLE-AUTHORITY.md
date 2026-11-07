# Collective Defence Durable Consent Authority

## Status

Design specification for the next implementation phase. This document does not claim that durable consent storage, a production key provider, a control-plane service, or an event-ingestion endpoint exists. The current `collective_defence_consent` module remains a side-effect-free verification and authorization primitive.

## Security invariants

1. Sharing is denied unless both the tenant administrator and the individual user have independently opted in.
2. Tenant consent is scoped to one tenant and a versioned purpose/schema. Individual consent is scoped to one tenant, principal, and device, and records the exact notice version and digest.
3. Missing, malformed, expired, stale, unavailable, or ambiguous authority state is denial. No cache may turn an authority outage into permission.
4. Revocation becomes effective at the authoritative commit point. A caller must not report successful withdrawal before the revocation and its audit record are durably committed.
5. Every collection and transmission boundary checks current authority. A short-lived permit is not a substitute for a fresh authoritative generation check.
6. Tenant state and audit records are tenant-isolated. No query may return another tenant's records.
7. Consent storage never authorizes remote access, remote execution, automated containment, or workload placement.

## Authority records

The first implementation should use explicit, versioned records rather than serializing Rust structs implicitly.

- **TenantConsentRecord**: tenant ID, enabled state, monotonically increasing tenant generation, purpose, event schema version, retention ceiling, signing key ID, notice/policy version, issued/updated timestamps, expiry, and record schema version.
- **IndividualConsentRecord**: tenant ID, principal ID, device ID, enabled state, monotonically increasing individual generation, tenant generation accepted by the user, purpose, notice version and SHA-256 digest, signing key ID, timestamps, expiry, and record schema version.
- **ConsentAuditRecord**: unique event ID, tenant/principal/device scope, actor class and key ID, action, previous and next generations, notice digest where applicable, commit timestamp, and a hash link to the prior audit record. Do not store raw conversations, file paths, credentials, or unrestricted endpoint telemetry.
- **AuthoritySnapshot**: deterministic canonical encoding of all active records plus the audit-chain head, snapshot schema version, and global snapshot generation.

Identifiers must be validated and bounded. Unknown fields and unsupported schema versions must be rejected. Canonical encoding must be deterministic and domain-separated before hashing/signing.

## Storage and anti-rollback contract

Build the consent authority as a separate module over a narrow persistence interface. Do not silently reuse the device registry's local HMAC key or treat a local database as a rollback-resistant trust anchor.

The storage interface must provide:

- tenant-scoped read of current tenant consent and one user's device consent;
- atomic update of consent plus audit append;
- conditional update against expected tenant and individual generations;
- idempotency keys for retried administrator/user commands;
- bounded record count and snapshot size;
- cross-process serialization or linearizable transactions;
- explicit unavailable, corrupt, conflict, capacity, and generation-exhaustion errors.

The production implementation must use a transactional database for records and audit rows plus a separate trust-domain monotonic anchor (for example, a managed KMS-backed service or strongly consistent control-plane service). The anchor contract must provide atomic compare-and-set on a registry/tenant namespace and bind the next generation to the exact snapshot digest. A file, local SQLite database, or backup directory on the same host is not an anti-rollback anchor.

### Commit and recovery protocol

1. Authenticate the actor and verify the signed command, scope, purpose, expiry, and expected generation.
2. In one database transaction, append the audit event and write the next canonical snapshot/outbox record using a unique idempotency key. Do not expose the new generation as committed yet.
3. Advance the external anchor with compare-and-set from the exact prior generation to the new generation and snapshot digest.
4. Mark the database transaction committed/visible only after the anchor succeeds. If the anchor is unavailable or rejects the CAS, return denial/unavailable and do not issue a permit.
5. On restart, reconcile pending transactions against the external anchor. A database snapshot ahead of, behind, or different from the anchor must be quarantined or restored from a snapshot that exactly matches the anchor; never guess or silently reset generations.
6. If a process crashes between database commit and anchor advancement, recovery must be able to resume the same idempotent anchor CAS. If it crashes after anchor advancement but before publication, recovery must publish only the exact anchored snapshot.

The implementation must document the database/anchor failure matrix and prove that no crash window can resurrect withdrawn consent.

## API boundary

Expose operations equivalent to:

- `record_tenant_decision(signed_command, expected_generation, idempotency_key)`
- `record_individual_decision(signed_command, expected_generation, idempotency_key)`
- `load_authorization_context(tenant_id, principal_id, device_id)`
- `revoke_tenant(authorized_admin_command, expected_generation, idempotency_key)`
- `withdraw_individual(signed_user_command, expected_generation, idempotency_key)`

The API must return a committed generation and audit event ID only after durable commit. Reads must return an explicit unavailable/error result rather than an empty/default consent object when storage cannot be trusted.

## Concurrency and revocation semantics

- Two updates against the same generation: exactly one succeeds; the other receives a generation conflict.
- A tenant disable increments tenant generation and invalidates every prior individual authorization by generation mismatch; it must not rewrite or silently enroll individual records.
- An individual withdrawal increments only that individual's generation and invalidates all permits for that principal/device.
- Re-enabling either gate requires a new signed decision and a new generation; old permits and old signed decisions must not become valid again.
- A tenant move, principal change, device replacement, signing-key rotation, notice change, or purpose/schema change must invalidate the relevant prior authorization.
- A transmission permit must be revalidated against fresh authoritative generations immediately before sending. If the authority is unreachable, transmission is blocked.

## Required test matrix

1. Tenant opt-in alone and individual opt-in alone both deny sharing.
2. Independent dual opt-in permits only the exact tenant/principal/device tuple.
3. Expiry, clock skew, purpose/schema mismatch, notice digest mismatch, unknown key, and invalid signature deny.
4. Tenant disable invalidates all previously issued permits; individual withdrawal invalidates only the selected principal/device.
5. Restart preserves generations, decisions, idempotency outcomes, and audit chain.
6. Restore of an older but correctly authenticated snapshot is detected by the external anchor.
7. Anchor outage, database outage, CAS conflict, disk-full, corrupt snapshot, and generation exhaustion all fail closed.
8. Crash injection at every step of the commit/recovery protocol never resurrects consent or loses a committed withdrawal.
9. Concurrent cross-process updates cannot both commit the same expected generation.
10. Cross-tenant reads/writes and audit-chain tampering are rejected.
11. Key rotation and notice-version changes require explicit migration/re-consent behavior.
12. Retention cleanup cannot remove the audit evidence required to explain a consent/revocation decision.

## Delivery sequence

1. Implement storage traits, canonical record encoding, and in-memory reference backend with deterministic tests.
2. Implement crash-safe durable backend and external monotonic-anchor adapter behind injected interfaces.
3. Add fault-injection, concurrency, restart, rollback, and revocation-race tests.
4. Add authenticated control-plane endpoints and tenant-isolated RBAC only after the storage contract is reviewed.
5. Add user/admin consent and withdrawal UI with the exact notice digest wired to the signed decision.
6. Add read-only event ingestion only after consent authority and event-schema validation are integrated at both collection and transmission boundaries.
7. Conduct independent security review and controlled opt-in pilot.

No step in this plan enables remote execution or automated containment.
