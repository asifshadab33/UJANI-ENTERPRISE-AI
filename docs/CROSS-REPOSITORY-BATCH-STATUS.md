# Cross-repository batch status — Enterprise AI

**Evidence snapshot: 22 November 2026 (integration refresh).** This is the Enterprise-specific status pointer for the coordinated 14-day plan. The canonical deduplicated backlog and release evidence register is [Public AI's cross-repository register](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/blob/main/docs/CROSS-REPOSITORY-BATCH-STATUS.md); detailed Enterprise issue tracking remains in [MASTER_BACKLOG.md](MASTER_BACKLOG.md) and the [requirements ledger](MASTER-REQUIREMENTS-IMPLEMENTATION-LEDGER-2026-11-19.md). This file is not a security certification.

## Live refresh — 22 November 2026 (supersedes stale rows above)

- **Enterprise main:** `5b99a290468938661f69bc6444010550e6b147c5` (PR #315 documentation-only merge). **Public main:** `d4567ee6843799dae118a64e2b417d59bac1b4f2` (PR #413 merge).
- PR #315 is merged; Enterprise has no open code PRs. Documentation-refresh PR #316 is the current pointer update and remains open pending exact-head checks. Public documentation-refresh PR #414 is also open pending checks. PR #413 is merged on Public after exact-head CI, CodeQL, Android compatibility, security-sensitive change watch and installer-size audit passed. Preview installers were skipped. No post-merge workflow evidence is available for either current main SHA.
- The latest independent shared-contract/schema parity check remains 21 Nov. The intervening merges were docs/status-only (#315, #411) and a Public cache implementation (#413); none changed shared contract/catalogue/schema/vector artifacts. This is not a new parity run or protocol interoperability proof.
- Day 2 Public IPC audit found 45 default commands and 7 feature-gated peer-preview commands represented in the existing security map; the parity guard remains inventory-only. Public #120 remains open for runtime authorization/denial-before-side-effect proof. Public #408 remains a filesystem identity race blocker; Public PR #396 is draft, stale-base and not mergeable.

**Release posture unchanged:** Enterprise is pre-alpha and remote worker execution remains disabled until authenticated enrollment/trust, live dual consent/revocation, replay-resistant transactional leases, protected key custody, isolation, signed receipts and recovery are verified end-to-end. No signing/deployment or physical-device evidence is claimed.


## Current main and exact evidence

- **Enterprise main:** `864b0a029637eba320ef99649685f2ea812e8989` (PR #314 merge commit). No post-merge workflow runs were returned in this audit.
- **PR #314 head:** `2ffb17cf706e41d1089f7b0c857519fbcffc9ebe`. Exact-head CI [#44896423107](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44896423107), CodeQL [#44896423072](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44896423072), RustSec [#44896423039](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44896423039), and security watch [#44896423064](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/44896423064) passed before merge. The change is test-only duplicate-field rejection coverage; it does not deploy the authenticated HTTP host, production key provider, service integration, or worker dispatch.
- **Public main:** `6ec7f950b4e41c4061d356a762e0858829f1d379`; #410 is a documentation-only merge atop functional code `baf75d0f57bd0d85e61d9df946a077f64a80feab`. PR-head checks passed, but post-merge runs for `6ec7f950...` are pending/not returned.
- **Open PRs:** Enterprise #315 is a documentation-only status refresh with CI/Rust audit queued; Public #396 remains draft and blocked by root/descendant filesystem TOCTOU issue #408, and #411 is a documentation-only evidence correction with security-watch in progress.
- **Shared artifacts:** Independently fetched the manifest plus seven listed schema/catalogue/vector artifacts from both current mains; every Git blob SHA matches. The task contract and inventory v2 are schema-compatible, not production-interoperable.

## Cross-product boundary

Public legacy peer protocol v2 and Enterprise legacy `WorkloadManifest` v1 remain incompatible in envelope shape and signature/approval domains. Shared task-contract v1 is a separate, strict schema with envelope, status and receipt shapes; it does not translate legacy formats or establish transport/authorization.

Remaining end-to-end gaps are tracked in [Public issue #412](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/issues/412): authenticated sender/tenant/worker identity binding; server-side owner consent plus organisation approval checked live and revocably; one transactional task-digest/nonce/expiry/replay/lease admission; common state/cancellation acknowledgement; signed receipt ingestion binding task/input/output and consent to durable lease/ledger outcomes; isolation/egress, protected key custody, rollback and recovery. Keep remote execution disabled.

## Model/runtime inventory

Inventory v2 parity is verified. It carries runtime/model identity/version, evidence-qualified capabilities, context/tool-use/vision/embedding metadata, resource estimates, platform/accelerator compatibility, freshness and privacy/consent context. Public's live producer is currently Ollama-based and personal-local-only; Enterprise's parser/preflight/matching is not a live authenticated fleet feed or operator projection. Catalogue licence/provenance claims are advisory; exact artifact licence/digest and storage facts remain unverified. Inventory must never grant trust or execution permission.

## Priorities and release posture

1. **P0:** Enterprise #20/#90 trusted enrollment, current-state revocation, tenant RBAC, authenticated service, protected key custody and transactional replay/lease lifecycle; production integration is incomplete.
2. **P1:** real enrolled-device inventory/telemetry and service-backed operator workflows; keep synthetic data clearly labelled.
3. **P0 before execution:** OS isolation, signed verifiable receipts, exact output binding, recovery and independent security review.
4. Continue the scheduled sequence without duplicating the canonical backlog: Day 2 Public #120 authorization matrix; Day 3 Public #408 handle-relative filesystem safety; Day 4 Public model catalogue; Day 5 Enterprise trust/dual-consent/lease lifecycle; Day 6 Enterprise resource admission/recovery; Day 7 cross-repository contract tests in Public #412.

Enterprise remains pre-alpha. No live worker execution, autonomous containment, release signing or deployment is authorized by this evidence. Physical-device, KMS/HSM/TPM, production service, rollback/backup and independent penetration testing remain external/manual gates.
