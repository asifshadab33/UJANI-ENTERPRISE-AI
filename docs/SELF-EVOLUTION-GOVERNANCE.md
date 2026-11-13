# UJANI Enterprise AI — Governed Self-Evolution

**Status: approved architectural direction; implementation not yet enabled.**  
**Scope:** Enterprise control-plane governance for proposed software/module updates. This is not authorization for remote code execution or an autonomous fleet updater.

## 1. Product intent

Allow an authorized administrator to use an approved AI model to analyse Enterprise application modules, prepare versioned improvement proposals and distribute approved, signed artifacts through a governed release process. Enterprise must preserve tenant boundaries, device trust, individual consent where applicable, and the primary objective of safe utilization of authorized organizational compute.

The AI model is a proposal author, not a trusted administrator, release authority, scheduler or endpoint agent.

## 1A. Source availability and endpoint boundary

The enrolled fleet endpoint is not a development workstation and must not rewrite its own executable or run generated code. The Enterprise Self-Evolution workflow belongs in the authenticated organization control plane and an organization-managed source/build environment.

For a later implementation:
- An authorized administrator selects a tenant-scoped source repository and approved release line. The control plane receives only bounded source paths; production tenant data, device secrets and customer content are excluded.
- Generated patches are created in an isolated workspace and validated in CI. They are proposals until reviewed and approved.
- Trusted organization release infrastructure builds and signs the artifact using organization-controlled KMS/HSM keys. The model never receives signing authority.
- Enrolled devices accept only verified signed artifacts through the existing trusted update channel; no model-generated code is executed on worker devices.
- If the organization has not configured a trusted source/build/signing environment, UJANI may prepare an analysis report but must not claim it can deploy a self-modification.

## 2. Trust boundaries

### Protected control-plane authority
The model must not modify or bypass:
- tenant isolation, RBAC, administrator identity and session authentication;
- device enrollment, device identity, key rotation/revocation and owner consent;
- workload authorization, leases, replay protection, quotas and policy evaluation;
- audit integrity, durable ledger controls and external monotonic anchors;
- update-signing keys, artifact verification, recovery and rollback trust roots;
- the policy governing the Self-Evolution workflow.

Changes to these areas require separate human-led security engineering, independent review and explicit release approval. No model or generated module can grant itself authority.

### Governed upgrade surfaces
Subject to policy and review:
- operator-console UI and help content;
- non-security-critical reporting and read-only views;
- independently versioned modules and adapters;
- capability/model catalogue metadata;
- administrative workflow improvements that do not change authorization semantics.

### Isolated extension surfaces
New plugins and connectors require signed manifests, tenant-scoped capabilities, explicit data classification, resource budgets, network allow-lists and revocation. Generated extensions must not gain ambient access to fleet devices or customer data.

## 3. Governed lifecycle

1. An authenticated administrator initiates an improvement request and selects the target repository, release line and permitted scope.
2. The control plane supplies a bounded read-only source manifest. Tenant data, device secrets, production credentials and customer content are excluded.
3. An organization-approved model creates structured findings and a proposed patch in an isolated workspace.
4. Trusted policy code validates path scope, protected-path exclusions, dependency policy, tenant boundary and resource limits.
5. CI builds and validates the proposal in a disposable environment. No generated code is executed on enrolled employee devices.
6. Reviewers receive the full diff, affected components, permission changes, dependency/license changes, validation evidence, risk classification and rollback plan.
7. An authorized release approver explicitly approves the artifact. Separation of duties should be enforced for changes to sensitive control-plane components.
8. Trusted release infrastructure signs the artifact. Signing keys remain in an organization-controlled KMS/HSM or equivalent protected service and are never exposed to the model.
9. Devices verify artifact signature, version, policy compatibility and rollout authorization before installation. Initial rollout should be staged and reversible.
10. The fleet records artifact digest, target cohort, approval, device outcome and rollback status in the durable audit system.

## 4. Enterprise policy requirements

- Tenant-scoped repository/source access and proposal records.
- Explicit administrator initiation; no autonomous fleet-wide changes.
- Model allow-list, version pinning and local/external processing disclosure.
- External code-assistance data transfer requires organization policy approval and disclosure of exact source scope.
- Device updates require authenticated device identity and current authorization.
- No update may weaken device trust, owner consent, workload isolation or audit requirements.
- Staged rollout, maintenance windows, health gates, cancellation and rollback.
- No hidden use of employee devices for code generation, builds or tests.
- Any optional use of internal compute for builds must be a separately declared workload with owner consent, administrator authorization, resource budgets, isolation and audit.
- The self-evolution feature must not depend on the live scheduler or dispatch system being production-ready.

## 5. Model and artifact governance

Reuse the existing model runtime inventory and onboarding contracts. Administrators may define approved model families, versions, hardware profiles and data-handling policies. Display model licence, storage/download size, RAM/CPU/GPU needs, coding capability, limitations and whether inference is local or external.

Every proposal and artifact should bind:
- tenant and repository identity;
- source commit and target release;
- model/provider/version and policy version;
- proposal ID and changed-file manifest;
- dependency and SBOM digest;
- validation evidence and reviewer decisions;
- artifact digest, signing identity and expiry;
- rollout cohort, device results and rollback record.

The AI must not create or hold signing keys, modify audit records, bypass tenant authorization or suppress failed validation.

## 6. Initial implementation slices

- **EE-0:** threat model, authority map, protected-path inventory and tenant-isolation acceptance criteria.
- **EE-1:** tenant-scoped, read-only source inventory and proposal contract.
- **EE-2:** protected-path policy, change classification and diff/review evidence.
- **EE-3:** isolated build/validation pipeline with SBOM, dependency and secret scanning.
- **EE-4:** authenticated administrator approval and separation-of-duties policy.
- **EE-5:** KMS/HSM-backed signing integration and artifact verification contract.
- **EE-6:** staged rollout, health gates, cancellation and rollback contract.
- **EE-7:** durable tenant-scoped evolution audit records and operator-console visibility.

Each slice must be independently reviewable. Do not enable remote execution, agent deployment or fleet-wide automatic installation in this workstream.

## 7. Release gates and non-goals

The MVP is a proposal-and-review workflow, not autonomous production deployment. Before any device rollout, require independent threat review, tenant-isolation/IDOR tests, signer custody review, artifact provenance verification, staged rollout and rollback tests, authorization/revocation race tests, and an operational recovery plan.

The AI must never:
- change its own policy or approval requirements;
- modify identity, trust, lease, isolation or audit enforcement;
- run generated code on production devices;
- approve, sign or deploy its own changes;
- access customer data or production secrets by default;
- claim that CI success proves physical-device or production safety.

Real customer-lab, physical-device and end-user testing remain a separate acceptance activity.
