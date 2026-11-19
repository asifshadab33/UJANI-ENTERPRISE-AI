# UJANI Consolidated Master Backlog — Enterprise AI

**Snapshot:** 2026-11-19, live repository check. This is a run snapshot, not a promise of background work.

## Product boundary
- Enterprise standalone; Public AI optional and never a dependency.
- Inventory limited to enrolled/authorised devices, metadata minimised. No prompts/files/paths/credentials/history.
- Remote execution and automated containment remain disabled; no release without explicit instruction.

## Ordered work

### P0 — Enterprise remote execution safety
1. Authenticated production control plane and tenant isolation; device enrollment/identity, revocation and rotation.
2. Owner + administrator consent bound to task digest, policy generation and expiry; revocation rechecked at admission and before execution.
3. Replay-resistant atomic nonce/sequence claim, admission, lease/reservation; durable transactions, concurrency, cancellation and crash rollback.
4. Protected key custody (OS/KMS/HSM/TPM), rotation/recovery and external anti-rollback anchor.
5. OS-enforced worker isolation and bounded process/filesystem/network/CPU/RAM/GPU/time/output.
6. Verifiable signed receipts bound to task/input digest and exact output bytes; monotonic state transitions, lease expiry/recovery and durable audit.
7. Deployment: production HTTP/OIDC, PostgreSQL backup/restore, external KMS, network partition tests, independent threat review/penetration tests.

### Useful feature work — proceed without waiting for remote execution
1. Operator console improvements and admin workflows remain read-only until authenticated APIs and permission/approval gates exist.
2. Model/task matching (merged PR #266) remains advisory: display capability evidence, resource estimates, freshness, conflicts and explanations; never reserve/dispatch.
3. Model-runtime inventory v2: schema parity, enrolled-device authorization, privacy minimisation, freshness/unknown evidence, no-model/unsupported-runtime cases.
4. Security-provider inventory: update freshness and stale/unverified states; no remote remediation or containment without opt-in and validated tooling.
5. Control-plane service core, tenant-safe persistence, admission and lease transactions: continue isolated tests and architecture work, but do not expose worker execution.
6. UI, accessibility, handbook, setup, operator troubleshooting and reproducible local testing.

### Cross-repository
- Task Contract v1 remains a draft/specification. Existing Public peer envelope v2 and Enterprise WorkloadManifest v1 are incompatible across identity/audience, consent, privacy class, capabilities/access scopes, resource units, expiry, replay, task states and receipts. No production adapter.
- Shared model/runtime inventory descriptor is not authentication or execution authority. Public local model selection is owner-controlled; Enterprise inventory only from enrolled/authorised devices with current consent.

## Live evidence
- Enterprise main: `197bf007411b3c4aab10e9ed620a9b6e0f3671be`; PR #266 model/task matcher merged.
- Main post-merge exact SHA `197bf007411b3c4aab10e9ed620a9b6e0f3671be`: CI #44451175579 passed Linux/Windows/macOS policy tests and customer-hosted PostgreSQL tenant isolation; RustSec #44451175518 and CodeQL #44451175833 passed.
- #267 closed as superseded by current-main PR #268; original branch retained.
- #268: current-main backlog snapshot PR; CI jobs were cancelled, CodeQL is in progress, RustSec/security watch queued; rerun of cancelled jobs initiated. Draft.
- Remote execution remains disabled.

## External gates
Production identity/OIDC, KMS/HSM/TPM, device physical trust, OS sandbox enforcement, signing, backup/restore, rollback, deployment and independent penetration tests require external access/manual validation.

**Verified shared-schema evidence (2026-11-19):** Public and Enterprise main contain byte-identical `schemas/shared-contract-manifest-v1.json` (Git blob SHA `5c41a57411453145f0d80a470f9985375b6e3ca4`). It pins the same inventory v1/v2 schemas, task-contract v1 schema, consent-binding vector, and inventory v1/v2 vectors. Schema parity is established; authenticated inventory ingestion and task transport are not.