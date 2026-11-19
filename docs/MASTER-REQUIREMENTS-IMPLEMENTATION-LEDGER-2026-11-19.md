# UJANI Enterprise AI — Master Requirements & Implementation Ledger (2026-11-19 evening)

This is a time-qualified evidence snapshot for the Enterprise default branch as observed on 2026-11-19 evening. Recheck live refs and workflow results before acting; open PRs are not counted as merged. It does not certify production readiness.

## Product invariants

- Primary mission: use idle resources on enrolled organisation-owned devices to reduce dependence on central AI data centres.
- Enterprise remains standalone; Public AI is not a runtime dependency.
- Device inventory is limited to enrolled/authorised devices and privacy-minimised capability/resource metadata. No prompts, file contents, paths, credentials, conversation history or employee activity.
- Device-owner consent and organisation administrator policy are independent requirements. Inventory consent is not compute consent.
- No stranger-device marketplace, silent compute or waking sleeping devices.
- Remote dispatch/execution and automated containment remain disabled until all production trust, consent, replay, lease, isolation, receipt and recovery gates pass.

## Requirements and status at the recorded main snapshot

| ID | Requirement | Status | Remaining evidence |
|---|---|---|---|
| ENT-001 | Fleet/resource manager | Partial foundations | Production tenant-scoped fleet service and deployment |
| ENT-002 | Device enrollment/trust | Partial primitives and tests | Authenticated HTTP/OIDC, device agent, key custody and revocation service |
| ENT-003 | Administrator + owner consent | Partial primitives and denial tests | Durable production authority, UI, expiry and revocation-at-use |
| ENT-004 | Device/model/runtime inventory | V2 schema, signed intake/preflight and atomic PostgreSQL admission | Full-schema HTTP adapter, repository wiring and authenticated v2 operator read projection |
| ENT-005 | Approved model catalogue | Shared catalogue and parity guard | Artifact digest, publisher, licence, size and administrator approval before distribution |
| ENT-006 | Model compatibility/task matching | Bounded advisory contracts and v2 projection schema/validator | Live authenticated evidence-backed API/GUI; never dispatch from a match |
| ENT-007 | Model distribution | Not operational | Secure allowlist, owner consent, transfer integrity, rollback and audit |
| ENT-008 | CPU/RAM/GPU/NPU capacity | Policy foundation and bounded metadata | Fresh authenticated telemetry and admission enforcement |
| ENT-009 | Idle/interactive/power/thermal | Policy foundation | Live signals, owner control and enforcement |
| ENT-010 | Energy-aware placement | Policy implemented | Measured energy and scheduler integration |
| ENT-011 | Queues/priorities/deadlines | Not operational | Production scheduler and fairness/back-pressure tests |
| ENT-012 | Admission/reservations/leases | Durable primitives and bounded-body/replay/concurrency regressions | Production authenticated transaction service, renewal/release/cancel and recovery |
| ENT-013 | Manifest/signed scheduling | Contract foundation | Production identity/consent/task adapter |
| ENT-014 | Distributed execution | Disabled | All P0 gates and independent security review |
| ENT-015 | Trust/consent revocation | Partial; denial and withdrawal tests merged | Live service, race and device-agent validation |
| ENT-016 | Durable ledger/audit | Partial foundations | Production source of truth, protected keys, retention and recovery |
| ENT-017 | Tenant isolation/RBAC/auth | PostgreSQL and policy tests | Production OIDC/HTTP, deployment and independent tenant testing |
| ENT-018 | Operator dashboard | Read-only demo/static console with accessibility improvements | Authenticated tenant-scoped API and real v2 projection feed |
| ENT-019 | Fleet health/site/workload UI | Partial contracts | Live service and operational UX |
| ENT-020 | Maintenance/update rollout | Planned | Signed staged update, rollback and recovery |
| ENT-021 | Security Centre | Partial | Validated provider adapters, freshness and unified UX |
| ENT-022 | Firewall/AV freshness | Partial prototypes | Live read-only integrations and stale/unverified warnings |
| ENT-023 | Optional IDS/network integrations | Partial probes/importers | Supported customer-selected adapters and lab evidence |
| ENT-024 | Collective Defence | Schema/reference foundation | Independent tenant and owner opt-in, ingestion/correlation/UI |
| ENT-025 | Event/incident pipeline | Partial | Canonical tenant/consent pipeline and durable lifecycle |
| ENT-026 | Containment/remediation | Disabled | Separate approval, reversibility, deployment and review |
| ENT-027 | Shared contracts | Byte-identical schema/fixture parity | Authenticated task adapter and end-to-end cross-language interoperability |
| ENT-028 | Deployment/release readiness | Not achieved | KMS/HSM/TPM, production deployment, operations, backup/DR and independent review |

## Deduplication rules

1. Keep one canonical model catalogue with generated mirrors and CI parity; do not create another catalogue source.
2. Keep inventory v1 and v2 separate and versioned; never infer v2 evidence from v1 fields.
3. Device trust, owner consent, administrator policy, telemetry consent, replay and leases must converge on one authoritative admission lifecycle; do not create competing registries.
4. Resource eligibility, energy comparison, task match, admission, reservation and lease remain distinct roles but must converge on one production admission decision.
5. Security-provider adapters feed one canonical tenant/consent validation pipeline; do not duplicate provider-specific policy engines.
6. Demo data remains visibly synthetic and separate from authenticated live data.

## Ordered implementation backlog

### P0 — remote-worker safety; execution remains disabled

1. Deploy an authenticated tenant-scoped OIDC/HTTP control plane and device agent; wire device trust, owner consent and administrator policy to current authoritative state.
2. Bind exact task digest, privacy class, capabilities, resource/time/output limits, expiry, nonce/sequence and both consent proofs into one atomic replay-resistant admission/lease/audit transaction.
3. Complete protected KMS/HSM/TPM key custody, rotation/recovery and an independently protected monotonic anti-rollback anchor.
4. Enforce receiver-side authorization and OS-level process/filesystem/network isolation, CPU/RAM/GPU/time/output quotas, cancellation and revocation.
5. Emit and verify signed receipts bound to task/input digest and exact output bytes; test monotonic state, crash, partition, lease expiry and recovery.
6. Complete customer-hosted backup/restore, deployment, independent threat modelling and penetration testing.

### P1 — useful features can proceed without remote execution

1. Connect the authenticated model-inventory v2 intake to full Draft 2020-12 validation, tenant-scoped persistence and the bounded v2 operator projection/API/GUI. Show evidence source, confidence, freshness and uncertainty; expose no prompts or private content.
2. Keep model/task matching advisory; complete live capability/resource evidence, catalogue parity and measured CPU/RAM/GPU/NPU/energy views.
3. Continue read-only Security Centre provider freshness and consented event ingestion; no automatic remediation or containment.
4. Improve operator accessibility, setup, troubleshooting and customer-hosted deployment documentation.

### P2 — after the foundations

1. Multi-site scheduling, queue fairness and advanced resource/energy optimisation.
2. Optional customer-selected IDS/network and security integrations with controlled-lab validation.

## Repository evidence at snapshot time

- Enterprise `main` at snapshot: `9603c9c5f52d8ac176f7d48f50b1a11037b96175`.
- Today's earlier merges: #281 catalogue parity/master ledger; #288 concurrent telemetry/lease admission regression; #290 bounded operator projection semantic consistency. This run merged #289 inventory-v2 preflight boundary tests, #293 oversized authenticated lease-body rejection tests, and #292 keyboard-accessible responsive operator inventory tables.
- Post-merge CI [44579377651](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44579377651) is pending, RustSec [44579377690](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44579377690) is in progress and CodeQL [44579377596](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44579377596) is queued on this exact SHA. The immediately preceding main SHA `bf5128372caf6901479cc0ac2c195efec848b5dc` passed CI, CodeQL and RustSec; do not transfer that green state to the new SHA.
- Open PR #291 (CSS interaction/reduced-motion validation) has head `6e38357f1cc995a3ee5ee8187880088c82ffb903`; its exact-head CI, CodeQL, RustSec and security-watch checks are pending after the validator was hardened to ignore comments and inspect the actual reduced-motion block.
- At snapshot time, documentation PR #295 was open for cross-repository status reconciliation; verify its live state before acting.

## Completion rule

A requirement is complete only when code is on main, exact post-merge CI/security checks are green and the evidence scope is explicit. Schema parity, policy primitives, static UI and synthetic fixtures do not prove live production services. No release, remote execution or automated containment is enabled by this ledger.
