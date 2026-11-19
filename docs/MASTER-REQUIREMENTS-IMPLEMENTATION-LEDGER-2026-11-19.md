# UJANI Enterprise AI — Master Requirements & Implementation Ledger (2026-11-19)

Reconciles retrieved project discussions and repository evidence. Historical chat coverage is not claimed exhaustive. Status describes current main; open PRs are not counted as merged.

## Product invariants
- Primary mission: coordinate authorised organisation devices to use idle resources for AI and reduce dependence on central data centres.
- Security coordination is secondary and optional, not the product's sole purpose.
- Administrator authority and individual device-owner consent are required where applicable; compute consent and security telemetry consent are separate.
- No stranger-device marketplace, waking sleeping devices or silent compute.
- Remote dispatch/execution remains disabled until authenticated control plane, tenant isolation, durable trust/consent, receiver authorization, encrypted transport, quotas, OS isolation, audit and review pass.
- Optional security integrations coordinate selected existing tools; not mandatory replacements.

## Requirements and status (current main)
| ID | Requirement | Status | Remaining/evidence |
|---|---|---|---|
| ENT-001 | Fleet/resource manager | Partial foundations | Production fleet service |
| ENT-002 | Device enrolment/trust | Partial primitives | Authenticated endpoints/key custody |
| ENT-003 | Admin + owner consent | Partial primitives | Durable authority and UI |
| ENT-004 | Device/model/runtime inventory | Partial contracts | Authenticated collection/persistence/UI |
| ENT-005 | Approved model catalogue | Shared foundation | Verified artifacts/admin policy |
| ENT-006 | Model compatibility/task matching | Advisory partial | Live evidence-backed UI |
| ENT-007 | Model distribution | Not operational | Secure approval/transfer/integrity/rollback |
| ENT-008 | CPU/RAM/GPU/NPU capacity | Policy foundation | Live telemetry |
| ENT-009 | Idle/interactive/power/thermal | Policy foundation | Signals and enforcement |
| ENT-010 | Energy-aware placement | Policy implemented | Measurement/scheduler integration |
| ENT-011 | Queues/priorities/deadlines | Not operational | Scheduler service |
| ENT-012 | Admission/reservations/leases | Partial foundations | Production transactional authority |
| ENT-013 | Manifest/signed scheduling | Contract foundation | Service integration |
| ENT-014 | Distributed execution | Disabled | Security gates; keep disabled |
| ENT-015 | Trust/consent revocation | Partial; tests in PRs | Live service validation |
| ENT-016 | Durable ledger/audit | Partial | Production source of truth |
| ENT-017 | Tenant isolation/RBAC/auth | Partial | Live identity and independent tests |
| ENT-018 | Operator dashboard | Demo/static | Live authenticated data |
| ENT-019 | Fleet health/site/workload UI | Partial contracts | Live service and UX |
| ENT-020 | Maintenance/update rollout | Planned | Signed staged update/rollback |
| ENT-021 | Security Centre | Partial | Provider status/unified UX |
| ENT-022 | Firewall/AV freshness | Partial prototypes | Validated provider adapters/warnings |
| ENT-023 | Optional IDS/network integrations | Partial probes/importers | Live supported adapters |
| ENT-024 | Collective Defence | Schema/reference foundation | Opt-in sensor/ingestion/correlation/UI |
| ENT-025 | Event/incident pipeline | Partial | Canonical pipeline/durable lifecycle |
| ENT-026 | Containment/remediation | Disabled | Separate approval/review/reversibility |
| ENT-027 | Shared contracts | Partial | Versioned parity/interoperability |
| ENT-028 | Deployment/release readiness | Not achieved | KMS, deployment, ops, review, backup/DR |

## Deduplication findings
1. Catalogue copies are identical; add parity guard and establish canonical source.
2. Inventory v1/v2/projection share normalized internal types, with separate serializers and boundary validation.
3. Trust, owner consent, telemetry consent, leases and revocation use one authoritative lifecycle; do not create competing registries.
4. Resource eligibility, energy comparison, admission, ledger and lease are distinct roles but must converge on one production admission decision and durable reservation authority.
5. Security events use one canonical schema/normalizer; provider adapters feed common tenant/consent validation.
6. Demo UI remains clearly labelled; never represent demo data as live.

## Implementation order
- P0: authenticated tenant-scoped trust/consent/control plane; transactional admission/leases/audit; receiver authorization/isolation design; keep dispatch disabled.
- P1: live inventory/operator UI; catalogue parity; model-task matching; capacity/energy measurement; Security Centre freshness; consented event pipeline.
- P2: multi-site scheduling, advanced connectors, incident correlation UI and optional monitoring.

## Completion rule
Complete only when code is on main, exact merged SHA CI is green and evidence scope is explicit. Contracts/demo projections do not prove live production functionality.
