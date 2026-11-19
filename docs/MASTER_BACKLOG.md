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

- Enterprise main: `fbf4a3735dc233e6fff92ebb518dbe5cc012166d`. PR #269 (bounded/versioned operator model-task-match JSON response) and PR #272 (pre-serialization identifier/reason-count bounds) are merged. PR #272 exact-head CI on Linux/macOS/Windows, PostgreSQL tenant-isolation, CodeQL, RustSec and security-sensitive change watch all passed. Post-merge CI, CodeQL and dependency audit are running on this main SHA; no post-merge result is claimed yet.
- Public main: `d34c47e2e9dc52c544a33626db9bb46caeea2712`. PR #336 freshness warning, #338 release gates, #340 history/cache consent, #348 hash-bound scan evidence and #347 clock reliability are merged. PR #347 exact-head CI, CodeQL, Android compile, native tests on Linux/macOS/Windows and all three installer-size jobs passed; unsigned previews were skipped.
- Public post-merge main CI and CodeQL on `d34c47e2e9dc52c544a33626db9bb46caeea2712`: **passed**.
- Public PR #351 (`ef4b98d5c0a2ac16f09ccf057a689758dc76ff55`) is the current-main Ollama non-streaming cancellation regression. Rust lint/core tests, frontend/Rust dependency audits, TypeScript build, workflow lint, both CodeQL analyses, Android compile, security watch and macOS installer passed; Linux/Windows/macOS native tests and Linux/Windows installers were still in progress at the last poll. Exact-head checks required.
- Public PR #350 was closed as stale/superseded by #351; #344 and #324 were closed as stale. PRs #345/#346/#349 were closed as outdated docs or unnecessary duplicate; branches retained.
- Enterprise PR #269/#272 establishes bounded, versioned, read-only task-match response contracts. This is still **not** an authenticated HTTP listener, UI integration, task dispatch or remote execution pathway. The authenticated adapter remains backlog work.
- Remote execution, automated containment and production public release remain disabled pending their separate evidence gates.

## Current dependency evidence
- Public main CI and CodeQL after #347 passed. PR #351 exact-head dependency audits passed.
- Enterprise PR #272 exact-head RustSec audit and CodeQL passed. Post-merge main dependency audit/CI/CodeQL are running.
- Physical-device behaviour, production signing/updater rollback and independent external security review remain unverified release gates.

## External gates
Production identity/OIDC, KMS/HSM/TPM, device physical trust, OS sandbox enforcement, signing, backup/restore, rollback, deployment and independent penetration tests require external access/manual validation.

**Verified shared-schema evidence (2026-11-19):** Public and Enterprise main contain byte-identical `schemas/shared-contract-manifest-v1.json` (Git blob SHA `5c41a57411453145f0d80a470f9985375b6e3ca4`). It pins the same inventory v1/v2 schemas, task-contract v1 schema, consent-binding vector, and inventory v1/v2 vectors. Schema parity is established; authenticated inventory ingestion and task transport are not.