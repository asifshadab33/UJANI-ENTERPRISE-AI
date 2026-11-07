# UJANI Enterprise AI — roadmap

This roadmap is a statement of intended work, not a claim that these capabilities exist today.

## Phase 0 — architecture and policy foundations (current)
- [x] Define organisation-owned/authorised hardware scope.
- [x] Document enrolment, policy, security and threat boundaries.
- [x] Add initial Rust policy types and admission tests.
- [ ] Agree a versioned task/capability protocol with UJANI Public AI.

## Phase 1 — trusted lab prototype
- [ ] Admin-created device enrolment with explicit approval.
- [ ] Short-lived device credentials, rotation and revocation.
- [ ] Read-only CPU/RAM/GPU/NPU/runtime inventory.
- [ ] Device heartbeat and availability reporting.
- [x] Policy-library verification of dual-signed worker telemetry and administrator scheduling decisions bound to the exact workload manifest and a single-use dispatch challenge (trusted enrollment registry remains external).
- [ ] Admin UI showing enrolled devices and policy state.
- [ ] No workload execution until identity and policy checks pass.

## Phase 2 — safe scheduling
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
