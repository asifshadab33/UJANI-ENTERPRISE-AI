# UJANI Enterprise AI — release-readiness and liability audit

**Audit date:** 2026-11-10  
**Repository:** `asifshadab33/UJANI-ENTERPRISE-AI`  
**Scope:** repository metadata, main-branch architecture/security documentation, selected Rust trust/ledger/control-plane code, merged PR records and hosted CI.  
**Limit:** this is a maintainer-level code/documentation review, not an independent penetration test, legal opinion, compliance assessment or exhaustive line-by-line audit.

## Verified repository and CI state

- PR #67 (signed telemetry admission and reservation reconciliation), #88 (dry-run fleet capacity summary) and #89 (read-only operator console and authenticated service core) are merged.
- Current main at audit time: `d114556386d21583e28ad2b7d8e77666c7c23fbc`.
- Main-branch Enterprise CI, CodeQL and Rust dependency-audit workflows all passed on that SHA.
- No open PRs were present at the time of the repository check.

## Implemented foundations inspected

- `device_trust/durable.rs`: HMAC-authenticated cross-process registry persistence, administrator-signed trust lifecycle primitives and an external monotonic-anchor interface.
- `durable_ledger.rs`: HMAC-authenticated V4 reservation snapshots, lease capability digests, OS file locking, crash recovery, migration from V2/V3, telemetry watermarks and reservation revisions.
- `operator_control_plane.rs`: short-lived tenant/subject/role-bound HMAC sessions, tenant-scoped read-only overview contract validation and fail-closed audit-sink interface.
- `collective_defence_authority.rs`: in-memory reference implementation of dual-consent generation/CAS/audit semantics. It is not a durable production consent service.
- `fleet_capacity.rs` and `scheduling_evidence.rs`: policy-level capacity/admission and signed-evidence primitives; not a live telemetry collector or scheduler.

## Critical production gaps

| Priority | Finding | Required before production or pilot |
|---|---|---|
| P0 | No deployed authenticated HTTP control plane or real OIDC/SAML identity adapter. | Implement HTTPS service, verified IdP tokens, tenant RBAC, secure cookies/CSRF, rate limits and server-side authorization. |
| P0 | No production worker agent or workload dispatch/execution service. | Build a least-privilege agent with signed assignment validation, authenticated transport, cancellation and durable lifecycle. Keep dispatch disabled until reviewed. |
| P0 | No OS-enforced workload sandbox or quota enforcement. | Implement platform-specific isolation and test filesystem, network egress, process, CPU, memory, device and cleanup boundaries. |
| P0 | Protected key custody and external anti-rollback anchor are interfaces/contracts, not deployed services. | Integrate KMS/HSM/TPM or equivalent protected provider, rotation/revocation and a separately hosted linearizable monotonic anchor. |
| P0 | Registry, reservation ledger and audit state are not one atomic cross-store transaction. | Use a transactional authoritative service/database and prove crash, concurrency, restore and revocation consistency. |
| P0 | Collective Defence consent backend is in-memory only. | Implement durable dual-consent persistence, transactional audit/idempotency, revocation and external rollback protection before ingesting or sharing events. |
| P1 | Signed worker telemetry authenticates the enrolled key's assertion, not the physical truth of reported measurements. | Build a hardened trusted agent, protect sensor/agent integrity, independently measure where possible and test spoofing/compromise. |
| P1 | The operator console is read-only and displays unavailable state without a deployed service. | Integrate a real tenant-isolated repository, durable audit sink, live authenticated API and browser security tests. |
| P1 | Network-security imports/probes are limited adapters, not a complete detection/response platform. | Validate source authenticity, parser limits, event retention, false positives and customer-owned sensor integrations; keep containment disabled. |
| P1 | No independent security review or production recovery exercise. | Conduct third-party threat review, penetration testing, key-loss/revocation drills and Windows/Linux/macOS crash/power-loss recovery tests. |

## Privacy, governance and liability controls

- The primary objective remains organisation-controlled use of already-powered, underutilised authorised hardware—not employee surveillance or a public device marketplace.
- Require both explicit organisation approval and individual device-owner opt-in for participation. Make pause, revocation and resource use visible.
- Never wake sleeping devices. Do not run batch workloads during interactive use or outside approved power, thermal, time and resource budgets.
- Minimise telemetry and audit data. Do not collect prompts, file contents, employee activity or raw endpoint logs unless a separately approved, necessary and documented security workflow requires a narrowly scoped record.
- Do not claim compliance, malware prevention, ransomware containment, energy savings or secure isolation based only on policy code or green CI.
- Preserve GPL-3.0 notices. Legal disclaimers are informational; obtain qualified counsel for privacy, employment, data residency, incident-response, export and product-liability obligations in each deployment jurisdiction.

## Execution boundary

**Remote dispatch, remote execution, autonomous containment and broad endpoint monitoring remain disabled.** A signed policy or lease is not a sandbox and does not make a worker production-trusted. Do not enable a pilot until the P0 controls above are implemented and independently tested.

## Release decision

**Pre-alpha policy and control-plane prototype only.** Hosted tests validate the current Rust policy workspace; they do not establish live identity integration, durable multi-tenant service behavior, real device connectivity, OS isolation or production readiness.

## Evidence links

- [PR #67](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/67)
- [PR #88](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/88)
- [PR #89](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/89)
- [Enterprise CI](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/42814116955)
- [Enterprise CodeQL](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/42814116908)
- [Enterprise dependency audit](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/actions/runs/42814116949)
