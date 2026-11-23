# Cross-repository batch status — Enterprise AI

**Evidence snapshot: 23 November 2026.** This is the Enterprise-specific status pointer for the coordinated 14-day programme. The canonical deduplicated priority/evidence register is [Public AI's cross-repository status document](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/blob/main/docs/CROSS-REPOSITORY-BATCH-STATUS.md). Enterprise detail remains in [MASTER_BACKLOG.md](MASTER_BACKLOG.md) and the [requirements ledger](MASTER-REQUIREMENTS-IMPLEMENTATION-LEDGER-2026-11-19.md). This is not a security certification.

## Current main and checks

- **Enterprise main:** `6d9305f6e671ab15c21acfa3ced10829adf625c2`. Post-merge CI [#45095411466](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/45095411466) and CodeQL [#45109771902](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/45109771902) passed. Prior exact-main RustSec audit [#45043397407](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/45043397407) passed.
- **Merged PR #318** at `81c406121021db99da0ab33b6f31aaab744048b5`: PostgreSQL is the single production authority; the Rust file ledger cannot become a split-brain authorization authority.
- **Merged PR #319** at `682c0ce83fbe0ebca9a168429f736bfaee6c67f`: read-only device inventory search/filter/pagination, bounded to 50 rows/page and reset on new snapshot. Exact-head policy tests on Ubuntu/Windows/macOS, PostgreSQL tenant-isolation, Rust analysis, CodeQL, RustSec and sensitive-change inspection passed. It does not change trust, admission, policy or execution.
- **Merged PR #320** at `6d9305f6e671ab15c21acfa3ced10829adf625c2`: cross-platform device-agent architecture/packaging contract, documentation only. Checks passed; duplicate authority ADR was removed in favour of existing `ARCHITECTURE.md`.
- **Open Enterprise PR #321:** documentation-only evidence refresh, still draft and under review. Its current snapshot is being corrected to reflect the verified checks and open-PR inventory. No implementation/release gate changes.
- **Public main:** `bc31ddbf5c874dd651ff4303a595424de398c1c5`. Public PR #418 is open for the patched `url 2.5.9` lockfile update; exact-head CI, RustSec (no vulnerabilities), CodeQL, Android compatibility, installer checks and Ubuntu/macOS/Windows native checks passed. Seven allowed advisories remain tracked in Public #73. Public PR #396 (empty-folder finder) remains draft/blocked by filesystem race #408; PR #417 is a draft docs refresh.

## Cross-product and model-inventory boundary

- Public legacy peer envelope v2 and Enterprise legacy `WorkloadManifest` v1 remain incompatible; neither is relabelled as shared task-contract v1.
- Shared task-contract v1 schema, model/runtime inventory v2 schema, consent vector, inventory vector and model catalogue are byte-identical on both current main branches. This is artifact parity only: no real cross-language JCS/Ed25519 vector, live sender/tenant/consent/revocation, transactional replay/lease admission, cancellation/state acknowledgement or signed-receipt-to-ledger interoperability is proven.
- Public's model inventory is personal-local-only, currently Ollama-based and not transmitted by default. Enterprise requires an enrolled-device context, current owner consent and administrator authorization. Enterprise inventory intake/preflight and PostgreSQL admission tests exist, but there is no deployed authenticated HTTP service, live inventory feed or service-backed operator projection. Catalogue licence/provenance claims remain advisory; exact artifact licence/digest and storage facts require verification.

## Ordered Enterprise priorities

1. **P0 — #20 trust/enrollment/lease lifecycle:** authoritative tenant/device identity, key provisioning/rotation/revocation/recovery, owner opt-in AND administrator policy, replay/freshness, authenticated lease admission, transactional reservations/audit and adversarial restart/revocation/concurrency tests.
2. **P0 — #90 authenticated control-plane host:** HTTPS/TLS identity, OIDC or mTLS, tenant RBAC, bounded requests, CSRF/origin protections, live tenant-scoped repositories and audit; no demo/live mixing.
3. **P0 before execution:** OS-enforced isolation/egress/resource limits, signed task/output receipts, protected anti-rollback, backup/restore, crash/partition reconciliation and independent security review.
4. **P1 — read-only operator/resource intelligence:** real service-backed inventory, evidence freshness/confidence, unknown/unsupported states, resource/capacity and reservations. Merged filters are presentation-only and operate on the current snapshot.
5. **Day 5–6 targets:** trust/dual-consent/lease lifecycle then resource admission/concurrency/recovery. Do not pre-empt Public #408 filesystem safety or enable dispatch.

**Release posture:** Enterprise remains pre-alpha, not production worker-ready. Remote execution, model distribution and autonomous containment remain disabled. No production HTTP service, endpoint agent, KMS/HSM/TPM integration, physical-device test, signed release or deployment is claimed.
