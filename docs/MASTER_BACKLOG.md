# UJANI Consolidated Master Backlog — Enterprise AI

**Snapshot:** 2026-11-19 evening. Current main: `9603c9c5f52d8ac176f7d48f50b1a11037b96175`. Post-merge CI/security checks are still running; this is not a production-readiness claim.

## Product boundary

- Enterprise is standalone; Public AI is not a dependency.
- Primary purpose is authorised organisation resource utilisation, not a replacement security product.
- Inventory is limited to enrolled/authorised devices and privacy-minimised capability/resource metadata. No prompts, file contents, paths, credentials, history or employee activity.
- Owner consent and organisation policy are separate. Inventory consent is not compute consent.
- Remote dispatch/execution and automated containment remain disabled.

## P0 — complete before any worker pilot

1. Production authenticated OIDC/HTTP control plane, tenant isolation and authenticated device agent.
2. One atomic admission path binding device trust, owner + administrator consent, exact task digest/privacy class/capabilities, bounded CPU/RAM/time/output, expiry and replay claim to a durable lease and audit record.
3. Protected KMS/HSM/TPM key custody, rotation/recovery and independent monotonic anti-rollback anchoring.
4. Receiver-side authorization and OS-enforced process/filesystem/network isolation, quotas, cancellation and revocation.
5. Signed, verifiable receipts bound to exact task/input/output bytes; monotonic task states and crash/partition/lease recovery.
6. Customer-hosted deployment, backup/restore and independent security review.

## P1 — useful work continues without remote execution

1. Wire the existing authenticated model-inventory v2 intake and PostgreSQL admission to a full-schema-validating hosting adapter and tenant-scoped repository.
2. Implement the bounded v2 operator read projection/API/GUI. Preserve evidence source/confidence/freshness/unknown states; never expose prompts or infer execution authority.
3. Keep model/task matching advisory; improve catalogue parity, fresh resource evidence and measured CPU/RAM/GPU/NPU/energy views.
4. Continue read-only Security Centre provider freshness and consented event ingestion; no automated remediation.
5. Continue operator accessibility, deployment, setup and troubleshooting.

## P2 — after foundations

1. Multi-site scheduling, fairness, priorities and energy-aware optimisation.
2. Optional customer-selected IDS/network/security integrations with controlled-lab validation.

## Current evidence and PR state

- Today's earlier merges: #281 catalogue parity/master ledger, #288 concurrent telemetry/lease admission regression and #290 bounded projection semantics.
- This run merged #289 inventory-v2 preflight boundary tests, #293 oversized authenticated lease-body rejection tests and #292 accessible responsive operator inventory tables.
- Current main CI is pending, RustSec is in progress and CodeQL is queued on `9603c9c5...`; previous main `bf512837...` passed those checks but does not prove the new SHA.
- PR #291 remains open for CSS hover/focus/reduced-motion validation; its latest head is `6e38357f...` and exact-head checks are pending.
- Remote execution and automated containment remain disabled. Physical-device, production KMS, deployment, rollback, backup/DR and independent penetration tests require external infrastructure and access.

**Completion rule:** no contract, fixture, demo view or policy primitive is counted as a live production service. Merge only exact-head, current-base PRs with all required checks and review blockers resolved.
