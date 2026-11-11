# Device trust service integration contract

Status: next-phase implementation contract. The repository now contains both the in-memory signed device-trust policy primitive and `device_trust::durable::DurableDeviceRegistry`, an HMAC-authenticated persistent adapter with OS-lock coordination and an external monotonic-anchor interface. The durable adapter is not itself an HTTP service, identity provider, tenant RBAC engine, append-only audit sink, lease service, or production deployment. The external anti-rollback anchor and protected key-provider integration remain deployment blockers; do not describe the registry as production-ready.

## Verified implementation status

- **Present in the policy crate:** signed administrator enrollment/rotation/revocation commands, device proof-of-possession, tenant and key-generation binding, signed device request envelopes, request replay protection, workload/manifest/body binding, and a durable HMAC-authenticated registry adapter.
- **Present in the scheduling evidence path:** the worker's signed telemetry binds effective CPU quota, available CPU headroom, configured CPU reserve, total/available/reserved memory, owner pause, OS-isolation readiness, a strictly increasing per-device sample generation and the per-device reservation revision reflected by the sample. The administrator-signed policy pins the expected revision for the same challenge. The V4 durable ledger consumes the challenge and advances the generation/watermark in one authenticated transaction; lower/equal generations, future/regressed watermarks and superseded contexts are rejected across process restarts. Lease creation, release and expiry advance the device revision, and reservation admission reconciles only leases newer than the signed sample. The signature proves which enrolled key asserted the measurements, not that the measurements are physically true; a trusted agent and authenticated service remain required. The worker agent must persist its generation counter across process restarts and reboots; resetting it requires controlled re-enrollment under a new device identity rather than silently accepting a lower counter.
- **Present as policy and persistence primitives:** the in-memory `Ledger` has capability-bound reservation/renew/release semantics; `DurableLedger` persists reservation state, challenge nonces, per-device telemetry generations, reservation watermarks and per-lease commit revisions in HMAC-authenticated V4 snapshots, coordinates processes with OS file locks, reads legacy V2/V3 snapshots for migration, supports injected integrity keys and an optional external monotonic-anchor interface, and exposes durable lease renew/release/expiry operations. `scheduling_evidence` provides signed-evidence verification and a durable reservation wrapper. These remain library/service-core components, not an authenticated network service.
- **Present as a transport-independent admission boundary:** `authenticate_verify_and_reserve_worker_telemetry` authenticates the exact POST/resource route through `DurableDeviceRegistry`, binds the request digest to `canonical_worker_telemetry_body`, rechecks the currently enrolled key generation after request authentication, binds tenant/device/workload/manifest identity, verifies worker and administrator signatures, consumes the durable telemetry challenge/generation, then invokes the existing dual-consent, capacity and durable reservation path. The worker owner opt-in and administrator schedule are independently signed and both must pass. This function is not an HTTP listener and does not persist a queryable telemetry history.
- **Not yet delivered:** a production KMS/HSM/TPM key-provider adapter and separately hosted linearizable anti-rollback anchor; authenticated HTTP endpoints; tenant-scoped RBAC and IdP integration; a tenant-scoped repository that loads device/workload records from authenticated identity; one authoritative transaction coupling request replay, telemetry generation, lease reservation and audit; durable append-only authorization audit; and production telemetry persistence/retention. Registry replay state and the reservation ledger are separate stores, so a request nonce can be consumed even if a later evidence or reservation step fails. The operation fails closed, but cross-store atomicity is not implemented.
- **Safety boundary:** no workload dispatch, remote execution, autonomous containment, or broad endpoint telemetry is authorized by this contract. Keep these disabled until the control plane and deployment trust boundary are independently reviewed.

## Current authenticated telemetry admission core (not HTTP)

The hosting adapter must pass the exact canonical claims bytes returned by `canonical_worker_telemetry_body`; it must not parse and reserialize those claims as JSON before the device-request body-digest check. The signed request route is fixed to `POST` plus `worker-telemetry:admission`. The separate telemetry signature covers the same canonical claims bytes.

The service must load the expected tenant, device and workload from a tenant-scoped repository and pass the repository tenant as the expected tenant. The function compares that tenant to the identity recovered from the durable device registry; it does not provide the repository or IdP itself. Administrator verifying keys must come from protected deployment configuration, not from the request.

The device request replay nonce is persisted before the telemetry challenge and reservation ledger are updated. If a later stage fails, callers must not retry the same request ID or challenge; they must obtain a fresh challenge/request and reconcile any ambiguous anchor result. This is deliberately fail-closed, but it is not a distributed transaction. Do not dispatch work or expose the helper as a production endpoint until registry replay, telemetry generation, reservation/lease mutation and audit share one authoritative transaction.

The owner opt-in is currently a signed worker telemetry assertion, not yet a separately persisted consent record. Production must add explicit owner-consent lifecycle/revocation evidence and recheck it in the same authoritative admission transaction.

## Trust bootstrap

- Load administrator Ed25519 verifying keys from a protected deployment trust store (HSM/KMS/TPM-backed adapter or tightly controlled secret manager).
- Do not accept administrator public keys from enrollment requests, devices, tenants or ordinary API callers.
- Assign each administrator key a stable key ID and lifecycle generation. Key replacement and revocation must be an audited, authenticated administrative operation.
- Keep private signing keys outside this repository and outside the writable registry/ledger directory.

## Durable authoritative registry

Persist, transactionally:
- device ID, tenant ID, lifecycle state, creation/approval/revocation timestamps and actor;
- active device key ID, public key, monotonic generation and rotation history;
- owner consent and administrator approval evidence references;
- registry version and audit event sequence.

Unique constraints must prevent one device identity from being bound to multiple tenants. A device move between tenants is a de-enrollment followed by a separately approved enrollment; it is never an in-place tenant reassignment.

Registry mutations and audit events must commit in one database transaction. State must be protected against unauthorized writes and backup/restore rollback. A stale restored registry must not resurrect a revoked device; use a monotonic external generation or append-only signed checkpoint.

## Signed request envelope

Every agent-to-control-plane request must carry:
- tenant ID, device ID, active key ID and key generation;
- HTTP method and canonical resource/action;
- unique random request ID (at least 128 bits);
- issued-at and expiry timestamps;
- Ed25519 signature over a versioned, domain-separated canonical encoding of all fields and the body digest.

Reject unknown schema versions, non-canonical encodings, expired or overlong windows, excessive clock skew, unknown devices, revoked devices, tenant mismatch, stale key generation, wrong method/resource binding, body-digest mismatch and replayed request IDs. Consume the request ID atomically with the authenticated operation or durable idempotency record. Never authorize from cached identity, enrollment, role, approval or lease state.

## Enrollment and key lifecycle

1. An administrator creates a short-lived, single-use enrollment challenge for one tenant and intended device.
2. Device proves possession of its new private key and returns the challenge signed by that key.
3. Administrator approval signature binds tenant, device, key ID, public key fingerprint, challenge, expiry and policy.
4. Service validates both proofs and atomically records the enrollment plus audit event.
5. Rotation requires administrator authorization and proof from both the currently enrolled key and the proposed new key. Increment key generation atomically; all old-generation requests immediately fail.
6. Revocation increments generation, marks the device revoked, invalidates sessions/leases and publishes an auditable revocation event. It must be fail-closed during control-plane or registry outages.

## Lease API binding

The lease service must authenticate the signed request before policy evaluation and bind each lease to:
- authenticated tenant and device identity;
- workload ID and exact manifest digest;
- lease ID, capability digest, key generation and expiry;
- requested resource limits and approved data/network policy.

Acquire, renew, release and cancel must be idempotent and transactionally coupled to the durable reservation ledger. Renewal must reject expired/revoked/stale-key leases. A lease capability alone is not device identity; it supplements, never replaces, authenticated device requests. Do not accept caller-supplied identity or public keys as proof of trust.

## Operational controls

- Rate-limit enrollment, authentication failures, key rotation and lease operations per tenant/device.
- Bound body sizes, request concurrency, nonce retention, audit retention and database growth.
- Use TLS with server identity validation; mutual TLS may be an additional layer, not a replacement for signed request authorization.
- Return generic authentication failures to untrusted callers while recording detailed internal reason codes without secrets.
- Alert on repeated replay, tenant mismatch, stale-generation use, revoked-device traffic and clock skew.
- Ensure registry and replay state survive restart and are consistent across all service instances.
- Add disaster recovery tests proving a restored backup cannot roll back revocation or replay protection.

## Required integration tests before any remote dispatch

- enrollment requires both admin approval and device proof;
- forged/caller-supplied admin key is not trusted;
- cross-tenant enrollment, lookup and lease access fail;
- key rotation invalidates old key generation immediately;
- revoked devices cannot authenticate, renew or release/dispatch work;
- replay fails across concurrent service instances and after restart;
- request method, path, body digest, tenant, manifest digest and expiry are signature-bound;
- registry/ledger corruption or key-provider outage fails closed;
- lease acquire/renew/release/cancel is atomic and idempotent under races;
- audit event and state mutation are transactionally consistent.

## Explicit non-goals of the current library layer

The policy and persistence crates do not provide authenticated HTTP endpoints, tenant RBAC/IdP integration, production KMS/HSM/TPM key custody, a separately hosted monotonic anchor, a transactional audit sink, or cross-store atomicity between device registry and lease ledger. Signed telemetry proves which enrolled key asserted the reported values; it does not prove that the values are accurate or measured by a tamper-resistant sensor. A trusted agent, authenticated service boundary, OS-enforced quotas and independent security review remain required. Passing unit tests is necessary but not sufficient to enable remote worker dispatch.
