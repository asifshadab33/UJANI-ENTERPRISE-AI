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
3. Model-runtime inventory v2: schema parity, enrolled-device authorization, privacy minimisation, freshness/unknown evidence, no-model/unsupported-runtime cases. Next feature: add a versioned v2 operator projection and console evidence display; never infer fit from v1-only facts.
4. Security-provider inventory: update freshness and stale/unverified states; no remote remediation or containment without opt-in and validated tooling.
5. Control-plane service core, tenant-safe persistence, admission and lease transactions: continue isolated tests and architecture work, but do not expose worker execution.
6. UI, accessibility, handbook, setup, operator troubleshooting and reproducible local testing.

### Cross-repository
- Task Contract v1 remains a draft/specification. Existing Public peer envelope v2 and Enterprise WorkloadManifest v1 are incompatible across identity/audience, consent, privacy class, capabilities/access scopes, resource units, expiry, replay, task states and receipts. No production adapter.
- Shared model/runtime inventory descriptor is not authentication or execution authority. Public local model selection is owner-controlled; Enterprise inventory only from enrolled/authorised devices with current consent.

## Live evidence

- Enterprise main: `6c8b905855144e6b654a5f2f70852f405dbca6ff`; PR #268 backlog refresh merged. Current-main CI (Linux/Windows/macOS and customer-hosted PostgreSQL tenant-isolation), RustSec and CodeQL all passed.
- Public main: `585330e094f415d4d0cf3ec42ac0e009516d8bb0`. PR #340 history/cache consent protections and PR #348 hash-bound file-scan evidence are merged. Post-merge CI and CodeQL are currently running on this exact main head; do not claim post-merge validation until those runs finish.
- Public PR #347 clock reliability is on corrected exact head `880b79953c02494438d60b65568deea52c0b2bc5`; it restores the Android-only command delimiter removed in the original patch. CI/native tests, Android compile, installers and CodeQL are running. The earlier failed head had a syntax error; only the corrected head is eligible for merge.
- Public PR #344 Ollama non-streaming cancellation is rebased onto current main. Desktop CI passed on its inspected head; Android compatibility failed at Gradle dependency resolution (Kotlin artifacts unavailable), so this remains unresolved and requires a clean rerun/diagnosis.
- Public PR #349 was closed as an unnecessary duplicate after confirming main already had the closing delimiter. PRs #345 and #346 were closed as stale backlog snapshots after main advanced; no code branches were deleted.
- Enterprise PR #269 adds a bounded, versioned JSON response contract for the existing evidence-qualified model/task matcher. It is still draft and all exact-head checks are pending. It does not create an HTTP listener, UI or execution pathway.
- Enterprise model/task matching remains advisory; remote execution, dispatch and automated containment remain disabled.

## Current dependency evidence
- Public frontend dependency audit reports 0 vulnerabilities on the newer exact-head PR #349 workflow; post-merge main audit is still running.
- Public Rust dependency audit has not yet been verified clean; do not conflate a successful job with allowed RustSec warnings until the full log is reviewed.
- Enterprise current-main CI, CodeQL and RustSec pass on `6c8b905855144e6b654a5f2f70852f405dbca6ff`.


## External gates
Production identity/OIDC, KMS/HSM/TPM, device physical trust, OS sandbox enforcement, signing, backup/restore, rollback, deployment and independent penetration tests require external access/manual validation.

**Verified shared-schema evidence (2026-11-19):** Public and Enterprise main contain byte-identical `schemas/shared-contract-manifest-v1.json` (Git blob SHA `5c41a57411453145f0d80a470f9985375b6e3ca4`). It pins the same inventory v1/v2 schemas, task-contract v1 schema, consent-binding vector, and inventory v1/v2 vectors. Schema parity is established; authenticated inventory ingestion and task transport are not.