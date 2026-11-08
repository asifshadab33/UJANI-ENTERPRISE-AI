# UJANI Enterprise AI — roadmap

This roadmap is a statement of intended work, not a claim that these capabilities exist today.

**Primary objective:** use existing, already-powered and underutilised authorised compute to reduce avoidable dependence on central AI data centres and energy use. Never wake sleeping devices or consume resources without owner opt-in and administrator approval. Distributed execution is preferred only when equivalent successful work is demonstrably lower-energy after device, network, retry and cooling overhead.

## Phase 0 — architecture and policy foundations (current)
- [x] Define organisation-owned/authorised hardware scope.
- [x] Document enrolment, policy, security and threat boundaries.
- [x] Add initial Rust policy types and admission tests.
- [ ] Agree a versioned task/capability protocol with UJANI Public AI.

## Phase 1 — trusted lab prototype
- [x] Signed administrator device-enrollment command primitives with proof of possession and tenant binding (policy library only; no authenticated service endpoint).
- [x] Signed device-key rotation/revocation primitives with monotonic per-device key generations and replay checks (policy library only; protected key provider and live service lifecycle remain pending).
- [ ] Read-only CPU/RAM/GPU/NPU/runtime inventory.
- [ ] Device heartbeat and availability reporting.
- [x] Policy-library verification of dual-signed worker telemetry and administrator scheduling decisions bound to the exact workload manifest and a single-use dispatch challenge (trusted enrollment registry remains external).
- [ ] Admin UI showing enrolled devices and policy state.
- [ ] No workload execution until identity and policy checks pass.

## Phase 2 — safe scheduling
- [x] Add a pure energy-comparison policy that includes incremental device, network, retry/failure and cooling energy; requires equivalent-workload verification; labels estimated inputs; and prefers central execution on ties.
- [ ] Workload classes, priorities and deadlines.
- [ ] Resource reservations and per-device quotas in a live scheduler.
- [x] File-backed local reservation policy store with OS advisory locks, crash-recovery snapshots, token-bound lease renewal/release and persisted single-use dispatch challenges (not a distributed scheduler or production database).
- [ ] Idle/interactive-aware scheduling with user-visible opt-out.
- [ ] GPU memory and accelerator compatibility checks.
- [ ] Cancellation, timeout and cleanup behaviour.
- [ ] Benchmarking against a documented baseline.

## Phase 3 — isolation and governance
- [ ] OS-enforced workload isolation.
- [ ] Tenant/workspace boundaries and scoped data access.
- [ ] Signed agent updates and software bill of materials.
- [ ] Central policy versioning and audit events.
- [ ] Incident response, key revocation and recovery tests.

## Phase 4 — production readiness
- [ ] Independent penetration test and threat-model review.
- [ ] High availability, backup and disaster recovery.
- [ ] Compliance mapping based on target customer requirements.
- [ ] Operational runbooks, SLAs and support processes.
- [ ] Transparent energy, utilisation and cost methodology.

## Later
- [ ] Multi-site scheduling and data locality constraints.
- [ ] Kubernetes / batch-system integrations where appropriate.
- [ ] Optional edge and mobile-class device adapters, subject to policy and platform limits.
- [ ] Enterprise SDK and integrations.

## Release gates

Do not claim secure isolation, guaranteed savings, compliance or production readiness without implementation evidence, reproducible tests and independent review.


## Operator dashboard implementation sequence (added 2026-11-07)
- [ ] P1: Complete trusted enrollment, key custody/rotation/revocation and authenticated lease control plane (issue #20); this blocks live fleet telemetry and every privileged action.
- [ ] Build a read-only dashboard shell using synthetic fixtures, always marked DEMO DATA.
- [ ] Add server-authorized live inventory using `schemas/fleet-inventory-v1.schema.json`; display source and freshness, preserving unknown/stale states.
- [ ] Add site/subnet grouping, health alerts, workload/lease status and audit search/export.
- [ ] Add maintenance and rollout visibility; keep actions disabled until receiver-side authorization, scoped approvals, audit and rollback are verified.
- [ ] Complete independent threat review and tenant-isolation/IDOR tests before production deployment.

See [docs/OPERATOR-WORKFLOWS.md](docs/OPERATOR-WORKFLOWS.md). The dashboard design and schema are contracts only; they do not represent an implemented web UI, agent or live control plane.


## Device trust persistence update — 2026-11-07

- [x] Add HMAC-authenticated durable device registry snapshots using an integrity key injected by a trusted host, never loaded from the writable registry directory.
- [x] Persist tenant binding, device public keys/key IDs/key generations, enrollment/revocation state, administrator nonces and device-request replay nonces.
- [x] Serialize cross-process operations with OS advisory locking; use bounded parsing and fail closed on malformed, oversized, duplicate or MAC-invalid state.
- [x] Test restart persistence, request replay after restart, tamper detection and concurrent registry handles.
- [ ] Integrate a production KMS/HSM/TPM-backed integrity-key provider, key rotation and disaster recovery.
- [x] Add the `MonotonicSnapshotAnchor` compare-and-set interface and anchored registry mode, including rollback-to-older-valid-HMAC tests (in-memory test provider only; no production anchor service).
- [ ] Integrate a production KMS/HSM/TPM-backed or separately hosted linearizable anchor provider with authenticated tenant scoping, recovery and outage tests; do not use a local sidecar file as the anchor.
- [ ] Expose authenticated enrollment/request/lease endpoints with tenant RBAC, replay/clock-skew enforcement and durable authorization audit.
- [ ] Keep dispatch and worker execution disabled until receiver-side authorization, encrypted mutual-authenticated transport, quotas and OS-enforced isolation are independently verified.

The merged device-trust implementation is a policy and persistence primitive, not a production control plane. See [docs/DURABLE_DEVICE_TRUST.md](docs/DURABLE_DEVICE_TRUST.md) for its trust boundary and limitations.


## Energy-aware distributed compute — 2026-11-07

- [x] Define energy-first placement order and strict no-wake/consent/interactive/AC/thermal gates.
- [x] Implement pure Rust comparison helper with overflow checks and measured/estimated provenance.
- [ ] Add independent benchmark harness and cross-platform tests against central/local/distributed baselines.
- [ ] Add read-only authenticated capability/availability agent and owner-visible pause/opt-out.
- [ ] Implement live scheduler only after OS-enforced isolation, trusted inventory, durable reservations, signed jobs and verified receipts.
- [ ] Pilot on two or three lab devices with external energy meters; publish negative as well as positive results.
- [ ] Public peer network only after independent security review and reproducible net-energy advantage.

See [energy-aware distributed compute](docs/ENERGY-AWARE-DISTRIBUTED-COMPUTE.md). The comparison helper is a policy primitive, not a meter, estimator, scheduler or execution gateway.


## Collective cyber-defence foundation — 2026-11-08

- [x] Define a versioned, privacy-minimised endpoint security event schema (v1).
- [x] Document authentication, replay protection, tenant isolation, retention, poisoning resistance and read-only response boundaries.
- [x] Add dependency-free schema contract regression checks to CI (valid/invalid fixtures, strict unknown-field rejection and privacy/response-field guardrails).
- [x] Add deterministic property checks to the CI validator for numeric boundaries, seeded in-range values, boolean-vs-number typing and every declared enum value; this supplements but does not replace full JSON Schema conformance.
- [x] Add an in-memory Collective Defence consent-authority reference backend with typed records, tenant/individual generation CAS, idempotent decisions and a hash-linked audit chain; reference-only, not durable or rollback-resistant.
- [ ] Add full JSON Schema conformance and fuzz/property tests in the policy crate.
- [ ] Implement an opt-in read-only sensor prototype with local bounded queue; no remote response.
- [ ] Implement authenticated tenant-scoped ingestion using existing device-trust primitives.
- [ ] Add durable event storage, deduplication, sequence enforcement and retention.
- [ ] Add deterministic cross-device correlation with explainable evidence and confidence.
- [ ] Build analyst incident timeline and alert dashboard.
- [ ] Add approval-gated, reversible containment only after receiver-side authorization and independent security review.
- [ ] Consider cross-tenant indicator sharing only with explicit governance and opt-in.

See [the collective-defence event contract](docs/COLLECTIVE-DEFENCE-EVENTS.md). The schema and documentation are contracts only; they do not represent a live endpoint sensor, ingestion service, detection engine or response capability.


## Enterprise Intelligence Orchestration Layer — proposed shared foundation

The architecture contract is in [docs/ENTERPRISE-INTELLIGENCE-ORCHESTRATION.md](docs/ENTERPRISE-INTELLIGENCE-ORCHESTRATION.md). This is a reusable Enterprise-wide layer, not a security-only wrapper.

- [ ] Define versioned schemas for capability descriptors, connector health, normalised evidence and workflow state.
- [ ] Add strict schema, bounds, compatibility and tenant-isolation tests.
- [ ] Implement a local mock-backed capability registry with demo-only fixtures.
- [ ] Define a read-only connector SDK with health, cancellation, timeout, rate-limit and circuit-breaker contracts.
- [ ] Implement one mock adapter and one real read-only adapter after upstream API and licence review.
- [ ] Add provenance-preserving event normalisation, deduplication, bounded retention and tenant-scoped caching.
- [ ] Add deterministic workflow routing, partial-failure handling and resource budgets.
- [ ] Build the unified read-only operator experience with evidence, freshness, provider drill-down and visible DEMO DATA states.
- [ ] Add preview-digest approvals, receiver-side revalidation, audit and rollback metadata before enabling any state-changing adapter.
- [ ] Reuse the same contracts for Infrastructure Shield, compute, document/search and future enterprise integrations.

**Release gate:** no remote execution, autonomous containment, firewall modification or inline enforcement until receiver-side identity, tenant isolation, exact-scope approval, replay protection, rollback, integration tests and independent security review are complete.
