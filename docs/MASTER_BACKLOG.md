# UJANI Consolidated Master Backlog

**Snapshot:** 2026-11-19. This is a status snapshot, not a claim that work continues between runs. Update it from live repository and exact-head CI evidence during each development pass.

## Product boundary

- Public AI remains standalone, local-first, privacy-focused and owner-controlled. Local model discovery must not transmit prompts, files, credentials, paths or model inventory to Enterprise.
- Enterprise AI remains standalone for organisation policy, device trust, fleet planning and approved internal workloads. Inventory is limited to enrolled/authorised devices and privacy-minimised capability/resource metadata.
- The shared Task Contract v1 is a protocol specification, not a dependency between products. Existing Public peer-envelope and Enterprise WorkloadManifest formats are not wire-compatible; no production authenticated adapter is complete.
- Remote execution and automated containment remain disabled. Do not publish releases without explicit release instruction and signing credentials.

## Verified branch baselines

- Public main: `7142e045927b116d101209779292701259021dd6` — local-chat IPC preflight.
- Enterprise main: `197bf007411b3c4aab10e9ed620a9b6e0f3671be` — advisory evidence-based model/task matching PR #266 merged; remote execution remains disabled.
- Main-branch CI status could not be independently queried through the available Actions endpoint in this run (PR-triggered workflow runs only; commit statuses returned no entries). Do not mark main CI green from PR runs alone.

## Ordered backlog

### P0 — Public AI first-release blockers

1. **PR consolidation and branch freshness:** safely reconcile overlapping PRs; update/rebase stale branches before merging. Current PR #324 and #328 are behind main; #332 is behind main and received follow-up digest-integrity fixes; #336 is based on current main.
2. **Ollama/model inventory integrity:** metadata must be joined only to a valid matching SHA-256 model digest. Reject empty/malformed/mismatched digest evidence; unknown claims remain unknown. PR #332 contains a new regression fix, but its exact-head CI is pending.
3. **Persistent-history/cache consent and recovery:** verify native consent before enabling persistence; test encrypted history/cache rollback, backup, restore, vault-key recovery and rotation.
4. **Filesystem/PDF isolation:** no-follow filesystem boundaries, PDF parser resource limits, deny-by-default worker filesystem/network egress, cancellation and malformed/oversized-file tests. Current worker controls are not full OS sandboxing.
5. **Ollama reliability:** loopback-only transport, no redirects/proxy leakage, bounded responses, timeouts/cancellation, invalid model handling and frozen-UI regression tests.
6. **Native IPC and policy:** preflight before side effects; test direct IPC denial, consent decline/timeout, cancellation and receipt ordering.
7. **Release integrity:** signed update manifests/feed, approved release identity, download verification, user-controlled install, rollback/recovery, installer validation and reproducible build evidence.
8. **Dependency advisories:** resolve the current Public dependency audit findings with compatible upstream migrations; never suppress or force an unreviewed downgrade. Track through Public issue #73.

### P0 — Enterprise remote-execution safety (disabled until complete)

1. **Authenticated control plane and device trust:** production enrollment, identity binding, key rotation/revocation and tenant isolation.
2. **Dual-consent binding:** bind user consent, worker-owner opt-in and administrator approval to the exact task digest and policy generations; recheck revocation immediately before admission/execution.
3. **Replay-resistant transactional admission:** atomic durable nonce/sequence claim, policy checks and reservation/lease creation; concurrency, timeout, cancellation and rollback tests.
4. **Protected key custody:** OS/KMS/HSM/TPM-backed keys, external anti-rollback anchor and rotation/recovery tests. Existing persistence primitives do not establish production key custody.
5. **Worker isolation and bounded execution:** OS-enforced filesystem/network/process isolation, CPU/memory/time/output limits and safe failure behaviour.
6. **Verifiable receipts and recovery:** worker-authorised signatures, input/output digest and exact output-byte verification, monotonic task states, crash/power-loss recovery, lease release and durable audit.
7. **Deployment validation:** production HTTP/OIDC, PostgreSQL backup/restore, external KMS, network partition, penetration and independent security testing.

### Cross-repository integration and Model Intelligence

1. Preserve the shared language-neutral Task Contract v1; do not create a duplicate schema or third repository. Document/implement a narrow authenticated adapter only after mapping identity, consent, privacy, capabilities, resource units, expiry, nonce, state and receipt semantics.
2. Verify shared model/runtime inventory v2 schema, fixture and manifest parity. The descriptor distinguishes OS-observed facts, runtime-reported facts, catalogue claims and estimates; records evidence confidence/freshness; includes per-model platform/accelerator compatibility; and remains metadata-only.
3. Public: discover installed local models through bounded OS/runtime observations and present explicit user model choice; no silent fallback/install/upload.
4. Enterprise: authenticated inventory for enrolled devices only, owner/admin policy checks and revocation; operator view exposes only pseudonymous metadata. Current matcher is advisory and does not dispatch/reserve.
5. Test schema compatibility/unknown fields, stale evidence, unsupported runtimes, empty inventory, resource mismatch, policy conflicts, consent revocation and explicit selection. Never treat inventory as trust or execution authority.

## PR status at this snapshot

### Public AI

- **#336** `295de047a9257536ac27b52db289ef847039e689`: Linux/Windows, Rust tests/lint, React build, dependency audits, CodeQL, Android and installer audit passed; macOS native test was cancelled and has been rerun (in progress). Mergeable; draft.
- **#332** `1866b8f413efda4ca6f6fd9cc2990bd3a35fb1d0`: added valid SHA-256 identity matching and regressions for malformed digests plus valid capability-selection fixtures. Exact-head CI queued; Android compatibility in progress, CodeQL pending, installer audit queued. Branch is 2 commits behind main; draft.
- **#324** `1469cdecdc650c740d2496ee6148000b4a54dfb4`: earlier exact-head checks passed; branch is 3 commits behind main. Revalidate after update; draft.
- **#328** `27116be457a564fd9f69db9e2479d8d1ea436558`: earlier exact-head checks passed; branch is 3 commits behind main. Revalidate after update; draft.
- **#326, #327, #333, #334, #337:** open; exact-head checks/review status not established in this pass. Do not merge on the basis of this snapshot.

### Enterprise AI

- **#266** `26b74e69424a846df13fcf8f1f248f6963cf9b06`: merged by squash as `197bf007411b3c4aab10e9ed620a9b6e0f3671be` after Linux/Windows/macOS policy tests, PostgreSQL tenant isolation, CodeQL, RustSec, security-sensitive checks passed and review threads were resolved. Post-merge main CI is not visible through the available Actions endpoint.
- **Main:** current SHA above. No production remote execution or release.
- **#267** `3701f7f38bb0bc5ebc2348b7180ffaf4ef11deef`: master-backlog documentation PR; CI, CodeQL, RustSec and security-sensitive check queued. Draft.
- **#267** `cd39dcd7f2a567baa2def2554101ceb534c4fdb6`: backlog snapshot documentation PR; CI, CodeQL, RustSec and security-sensitive check queued. Draft.

## Evidence discipline

Mark work complete only when implementation and relevant exact-head checks pass. Rerun cancelled jobs; fix failures; review new comments; verify the unchanged head before merging; verify main CI after merge. Pending/absent checks, unsigned preview packages, physical-device tests, production signing, KMS/HSM, rollback and deployment tests are blockers—not successes.
