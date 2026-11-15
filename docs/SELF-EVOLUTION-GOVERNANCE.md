# UJANI Enterprise AI — Governed Self-Evolution

**Status: proposal validation, signed approval, durable replay and exact patch-bundle validation are implemented in code; staging, application, build/signing and fleet rollout remain disabled.**  
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

## 2A. Host-owned authority envelope

The model-authored proposal body contains only a schema version, summary, findings and proposed file changes. It must not contain or choose the repository, source revision, approved write scope, proposal ID, model identity, permissions, reviewer decisions or signing authority. The authenticated control plane binds the proposal to a tenant-scoped source checkout and administrator-approved path scope, generates the proposal ID, and records model/provider/version and approval metadata in a separate trusted audit envelope. The host rejects unknown model fields rather than accepting model-supplied authority.

## 2B. Current implementation boundary

The repositories now contain:
- A host-owned proposal contract with protected-path and approved-scope validation.
- A signed, short-lived administrator approval bound to the exact proposal, repository revision and approved scope.
- Durable single-use approval nonce consumption with expiry and concurrency protection.
- A pure patch-bundle validator that binds each changed path, operation, base-file digest and replacement content to the approved proposal; it rejects stale workspace snapshots, path/scope mismatches, malformed content and oversized bundles.

The patch validator has no filesystem access. It does not create an isolated workspace, write or replace source files, create backups, commit a branch, run tests, install an update or roll back. The action gate therefore continues to deny review submission, staging and application until the host-side staging store and atomic install/rollback workflow are implemented and reviewed. No generated code is executed.

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

## 6. Implementation slices and current status

- **EE-0 — threat model and authority map:** policy boundaries and protected-path inventory exist; independent threat review remains required.
- **EE-1 — source/proposal contract:** proposal schema, trusted target binding and protected-scope validation are implemented; a live read-only source inventory service is not.
- **EE-2 — patch validation:** exact patch digests, base-file snapshot matching, size limits and protected-path checks are implemented as a pure validator; diff presentation and isolated staging are not.
- **EE-3 — isolated build/validation:** not implemented. Generated code is not executed.
- **EE-4 — administrator approval:** signed approval verification, operator-session checks, owner opt-in and durable single-use nonce consumption are implemented; a complete review-submission workflow is not.
- **EE-5 — KMS/HSM signing:** not implemented; no model or application component receives signing authority.
- **EE-6 — staged rollout and rollback:** not implemented; no fleet update or remote execution is enabled.
- **EE-7 — audit:** approval/replay metadata and existing audit foundations exist; artifact lifecycle, rollout and rollback audit events are not integrated.

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
