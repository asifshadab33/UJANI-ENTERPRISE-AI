# UJANI Consolidated Master Backlog — Enterprise AI

**Snapshot:** 20 November 2026. Enterprise main after tenant-isolation PR #309: `b556baba6afea8d939c023cc43afd1706376cab2`. This is an implementation/evidence snapshot, not a production-readiness claim.

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

## Evidence snapshot (verify live GitHub refs before acting)

- Today's earlier merges: #304 canonical API-v1 route alignment; #307 generation-bound authenticated telemetry v3 admission (including PostgreSQL fixture-collision and digest-decoding corrections); #308 fail-closed model-match audit-outage regression. This pass merged #309 tenant-isolation coverage for operator model matching.
- Post-merge main checks for `b556baba...` were queued/in progress at the time of this snapshot; do not transfer the previous `f48bf4ab...` green CI/CodeQL/RustSec state to the new main SHA.
- PR #310 clarifies model-inventory v2 runtime-provider and capability-name semantics. Its exact head `f8b8c8b9...` passed Enterprise CI, CodeQL, RustSec and security-watch checks, but it is one commit behind main after #309 and must be revalidated against the current base before merge.
- Enterprise model-inventory v2 remains a database admission primitive plus authenticated request/preflight boundary, not a deployed hosting adapter or live operator read API. The operator projection is still draft/read-only.
- Remote execution and automated containment remain disabled. Physical-device, production KMS/HSM/TPM custody, external anti-rollback, deployment, rollback, backup/DR and independent penetration tests require external infrastructure and access.

**Completion rule:** no contract, fixture, demo view or policy primitive is counted as a live production service. Merge only exact-head, current-base PRs with all required checks and review blockers resolved.
