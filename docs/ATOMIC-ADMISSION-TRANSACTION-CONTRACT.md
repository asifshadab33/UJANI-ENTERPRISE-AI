# Atomic authenticated resource-admission transaction

## Status and scope

This document defines the production service boundary. It is an implementation contract, not evidence that a PostgreSQL service or distributed worker dispatch exists. The Rust policy crate contains authenticated device telemetry admission and durable reservation primitives. Migration 0010 now provides a single PostgreSQL statement transaction for the telemetry-ingest-plus-lease path; the separate DurableDeviceRegistry replay state and DurableLedger scheduling-evidence path are still not one cross-store transaction. Keep worker dispatch disabled.

The target is a tenant-scoped PostgreSQL transaction for admission state. It must not attempt to make a filesystem registry, a remote KMS, an external monotonic anchor and PostgreSQL one distributed transaction. Those external dependencies are authenticated before the SQL transaction and must have explicit fail-closed and reconciliation semantics.

## Trusted inputs

The HTTP adapter must derive, never trust from request JSON:

- tenant and authenticated operator/service principal from the configured identity provider;
- expected device, active device-key generation, workload and manifest digest from a tenant-scoped repository;
- administrator verifying keys and policy revision from protected deployment configuration;
- exact HTTP method and resource identifier from the registered route;
- canonical request-body bytes for signature and digest verification.

The enrolled device signature authenticates the asserted telemetry; it does not prove physical truth. Do not persist prompts, model contents, local paths, personal files or unrelated user activity.

## Required transaction boundary

One database transaction must own and commit all mutable admission facts:

1. Lock the tenant-scoped device admission row and verify it is active, not revoked, and still at the authenticated key generation.
2. Verify persisted device-owner opt-in and its monotonic consent revision. Verify the independently signed administrator policy permits this device, workload class and requested capability.
3. Enforce request nonce uniqueness and expiry, with a tenant/device/key-generation scope. A duplicate nonce is rejected.
4. Enforce strictly increasing telemetry generation and sample sequence. Reject equal/lower values, future timestamps outside the configured clock-skew allowance, stale samples, and reservation-revision mismatches.
5. Re-evaluate current resource capacity, existing reservations, quotas, thermal/power/interactive-use policy and workload requirements while holding the appropriate capacity/device locks.
6. Insert the reservation and lease with an unpredictable capability whose verifier is stored as a domain-separated digest. Do not persist a bearer lease token.
7. Advance the telemetry generation, sample sequence and reservation revision.
8. Append the tenant-scoped audit receipt in the same transaction, linked to the authenticated principal, policy revision, consent revision, request digest and admission outcome. Do not include raw telemetry beyond the minimum necessary evidence.
9. Commit once. Return an admission receipt only after commit.

A denial may be recorded in a separate bounded audit transaction, but it must never create or partially retain a reservation. If a transaction aborts, nonce consumption, telemetry watermarks, capacity accounting, lease creation and success receipt must all roll back together.

## Implemented SQL composition boundary (migration 0010)

`ujani_control.admit_device_lease_with_telemetry` composes the existing `accept_device_telemetry_v2` and `admit_device_lease` functions in one PostgreSQL statement transaction. Before accepting telemetry it locks the tenant-scoped device row and compares the device-key generation and owner-consent generation covered by the signed request with the current database values. Key rotation, revocation and consent updates that use the same device-row lock therefore linearize before or after this admission.

The function requires two distinct request IDs: one for the telemetry request and one for the lease-admission operation. On success, telemetry replay/sample/watermarks, lease replay/reservation/revision and the append-only audit event commit together. If telemetry is accepted but lease policy denies admission, a nested PostgreSQL subtransaction rolls back the telemetry write and replay claim and returns `false`. Unexpected database or audit errors propagate and abort the statement. The function is `SECURITY INVOKER`, preserves tenant RLS and does not verify cryptographic signatures itself.

The CI SQL regression covers successful admission, interactive-use denial with no partial telemetry, a late duplicate-audit failure with full rollback, and a stale device-key generation. This is a database composition primitive, not a live HTTP listener. The trusted adapter must verify the exact signed device body and administrator approval, derive tenant identity from authenticated context, call this function, and return success only after commit. The separate DurableDeviceRegistry/DurableLedger scheduling-evidence path and external monotonic-anchor/KMS operations still require explicit reconciliation; no remote job dispatch or execution is enabled.
## Concurrency and capacity invariants

- Serialize admission for a device using a row lock or an equivalent serializable transaction strategy.
- Serialize capacity accounting for the resource pool or use atomic conditional updates that cannot oversubscribe CPU or memory.
- Every reservation has exactly one owning tenant, device, workload, policy revision and lease.
- A lease can be renewed only by its currently enrolled owning device while owner opt-in and administrator policy remain valid.
- Owner opt-out, device revocation, policy denial or device retirement prevents new admission and renewal. The owner may still release their own lease.
- Expiry and reconciliation are idempotent and update capacity plus audit state transactionally.
- A stale telemetry sample cannot overwrite a newer generation, sequence or reservation revision.
- Retries use a stable idempotency key and return the original committed receipt; they must not create a second reservation.

## External dependencies and failure semantics

- KMS/HSM/OS-protected key operations occur outside the SQL transaction where possible. The adapter supplies a key identifier and authenticated verification result; raw protected key material must not be copied into application state.
- External monotonic-anchor calls have bounded deadlines and cooperative cancellation. A timeout with an ambiguous compare-and-set outcome requires read-back reconciliation before retry; do not assume rollback.
- No database transaction may remain open while waiting on a remote anchor, identity provider or key-management network call.
- If identity, key custody, anchor reconciliation or policy evidence is unavailable, fail closed and create no lease.
- Audit durability is a database commit requirement. External log export is asynchronous through a transactional outbox and must not be confused with the authoritative in-transaction receipt.

## Required PostgreSQL schema and indexes

The implementation must provide tenant-scoped tables (or equivalent existing tables with verified constraints) for:

- device admission state: active key generation, consent state/revision, latest telemetry generation/sequence, latest reservation revision;
- consumed request nonce: tenant, device, key generation, nonce digest and expiry, with a uniqueness constraint;
- resource capacity and reservations: tenant/pool/device/workload, CPU and memory units, reservation state and revision;
- leases: reservation reference, token digest, owner device, issued/expiry timestamps and lifecycle state;
- audit receipts: tenant-scoped monotonic sequence, event digest/previous digest and minimal authenticated decision metadata;
- transactional outbox: receipt reference, delivery state, bounded retry metadata.

Use foreign keys and composite tenant keys to prevent cross-tenant references. Add bounded retention/partitioning for expired nonces and telemetry evidence without deleting reservation, lease or audit facts still required for reconciliation.

## Required tests before service integration is considered complete

1. Duplicate nonce: exactly one transaction can commit.
2. Out-of-order and replayed telemetry: no watermark or capacity mutation.
3. Future and stale sample: reject at the service boundary.
4. Concurrent capacity requests: never exceed configured CPU or memory.
5. Transaction rollback at every write stage: no partial nonce, watermark, reservation, lease or success receipt.
6. Consent revoked concurrently with admission: lock ordering yields either a valid pre-revocation admission or a complete denial, never admission after revocation linearizes.
7. Concurrent lease renew/release/expiry: one valid terminal outcome and correct capacity accounting.
8. Idempotent retry after lost response: return the original receipt without duplicate capacity.
9. Tenant substitution and cross-tenant foreign-key attempts: reject.
10. Database restart/crash around commit: recovery yields either the complete committed transaction or none of it.
11. Audit-chain sequence/digest consistency under concurrent admission.
12. External provider timeout and ambiguous anchor outcome: no unsafe retry or false success.

## Release gate

This contract does not authorize dispatch. After implementation, require exact-head CI, migration tests on supported PostgreSQL versions, concurrency/stress tests, fault injection, independent review of transaction isolation and lock ordering, and deployment evidence for identity and key custody. Worker dispatch remains disabled until OS-enforced isolation, assignment verification, result verification, revocation, lease expiry, audit, rollback and independent security review are proven end to end.
