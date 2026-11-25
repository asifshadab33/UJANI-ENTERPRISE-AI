# Enterprise AI implementation register — 25 November 2026

This register is an execution aid, not a production-readiness claim. It preserves incomplete implementation slices for later integration into the Enterprise foundation. Update statuses only with linked evidence and exact commit SHA.

## Evidence labels

- **Implemented**: code exists; no test claim implied.
- **Unit-tested**: relevant focused tests pass locally or in a named workflow.
- **CI-verified**: exact current commit SHA has passing required hosted checks.
- **Integration-verified**: complete cross-component workflow has passed.
- **Device-verified**: real enrolled endpoint and protected host have passed.
- **Blocked**: identity, key provider, platform capability, infrastructure or independent review is missing.
- **Release-ready**: all applicable gates have evidence; not currently asserted.

## Current baseline

- Default branch: `main`
- Baseline SHA at register creation: `adfb12f04083026dd0652185784d98eec3a937a5`
- Product status: pre-alpha policy/control-plane prototype.
- Public AI remains independently usable; Enterprise must not become its runtime dependency.
- Remote worker execution, endpoint containment and autonomous response remain disabled.

## Ordered implementation batches

| Order | Work slice | Existing tracking | Current evidence/status | Acceptance evidence still required |
|---|---|---|---|---|
| E0-1 | Device enrollment, identity/key lifecycle and revocation | #20 | Signed enrollment/proof/rotation/revocation primitives and durable registry exist | Production protected key provider, tenant/IdP binding, rotation/revocation drill, device loss/recovery |
| E0-2 | Dual consent and withdrawal | #39 | Persisted owner opt-in/opt-out and administrator schedule checks exist; recent admission/withdrawal concurrency fix is in main | Real owner device agent, authenticated consent API, revocation propagation and race/failure tests across service boundary |
| E0-3 | Authenticated HTTP/OIDC service and tenant RBAC | #90 | Transport-independent authenticated service core exists; no production listener/IdP/database repository | HTTPS listener, OIDC validation, tenant membership/role provisioning, CSRF/rate limits, tenant isolation and audit integration |
| E0-4 | Transactional replay/telemetry/lease/audit admission | #20, #90 | PostgreSQL migrations and local durable primitives exist; file registry and ledger remain separate stores | One authoritative transaction for replay, monotonic telemetry, lease and audit; multi-host concurrency and failure-injection tests |
| E0-5 | Protected key custody and anti-rollback | #20 | Provider interfaces and encrypted envelope foundations exist; no production KMS/HSM/TPM provider or external monotonic anchor | Real protected provider, purpose separation, rotation/recovery, anchor outage/rollback tests |
| E0-6 | OS isolation and resource enforcement | #20, release gates | Policy admission checks include consent, freshness, activity, power, thermal and resource constraints | OS-enforced CPU/memory/storage/time/network/filesystem isolation and platform escape/stress review |
| E1-1 | Authenticated resource inventory and capacity admission | #21, #23 | Resource/capacity policy and telemetry evidence primitives exist | Real agent data, freshness/confidence labels, OS reserve/active lease accounting, concurrent reservations and recovery |
| E1-2 | Operator Control Plane service-backed overview | #21, #90 | Tenant-bound read-only service core and overview contract exist; no live HTTP/DB/OIDC deployment | Production repository, durable audit sink, live route and UI, clear stale/offline/untrusted states |
| E1-3 | Model/runtime intelligence for enrolled devices | #257 | Evidence-qualified model matcher and provenance catalogue foundations exist | Privacy-minimised descriptor ingestion, observed/runtime/catalogue/estimate provenance, freshness, policy conflict and revocation tests |
| E1-4 | Model-to-task operator workflow | #21, #257 | Advisory match service method exists; route/UI not wired end-to-end | Authenticated API route, selected device/model display, resource-fit explanation; no implicit reservation/dispatch |
| E2-1 | Read-only endpoint security sensor | #38 | Importer/health probe foundations exist; no authenticated production agent ingestion | Minimal sensor, signed bounded events, tenant/device binding, replay/freshness/revocation and privacy tests |
| E2-2 | Collective Defence correlation | #35 | Design/policy foundations only | Explicit organisation AND participant opt-in, bounded event sharing, false-positive review, response approval and audit |
| E2-3 | Security Centre integrations | #50 | Not a complete live product workflow | Customer-selected AV/firewall/IDS adapters, least privilege, read-only first, no autonomous writes |
| E2-4 | Infrastructure Shield profiles | #65 | Design-level scope | Customer-selected deployment profiles, clear support/liability boundaries and reproducible installation |
| E2-5 | Enterprise Planner and notifications | #53, #95 | Not complete | Consent-based calendar/task integrations, tenant controls, event provenance and verified delivery |
| E2-6 | Tenant-isolated cache | #26 | Not complete | Tenant-keyed storage, retention/expiry, deletion and cross-tenant isolation tests |

## Execution rules

1. Keep remote execution disabled until identity, dual consent, replay, transactional lease, key custody, isolation, receipts and failure recovery pass end-to-end.
2. Never treat a signed device measurement as proof of physical truth; label source and confidence.
3. Never pool RAM across devices as if it were one machine. A model must fit on one selected device unless a separately reviewed sharding runtime is introduced.
4. Device inventory exposes only privacy-minimised operational metadata. Never expose prompts, file paths, personal content, employee activity or raw logs to the operator.
5. A registered device is not automatically trusted, online or schedulable. Require fresh authenticated telemetry and both consent authorities.
6. Missing, stale, estimated or contradictory evidence fails closed for admission.
7. Keep operator model matching advisory. It must not install a model, reserve resources or dispatch a workload.
8. Use real service data in the Control Plane; label all fixtures and simulations.

## Next implementation owner/order

1. Complete E0-1/E0-2 service boundary and define revocation behavior before exposing enrollment UI.
2. Implement E0-4 transaction coupling using the existing PostgreSQL migration path; do not add another independent ledger.
3. In parallel, advance E1-1 real resource inventory and E1-3 model descriptor provenance without exposing sensitive data.
4. Wire E1-2 read-only operator overview only after the authenticated repository and durable audit sink are available.
5. Keep endpoint sensing read-only until event authentication and tenant isolation are verified.

## Current safety decision

**Not production-ready for remote worker execution.** No job dispatch, remote execution, autonomous containment or endpoint-control actions are authorized by this register.
