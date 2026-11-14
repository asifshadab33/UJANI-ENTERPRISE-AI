# Enterprise AI — administrator feature enablement and risk register

**Status:** administrator governance contract and implementation inventory; not a production security certification.

UJANI Enterprise AI is intended to coordinate organisation-owned and explicitly enrolled compute resources. Enabling a feature must never imply that a device owner has consented, that a service is deployed, or that a remote action is safe.

## Two independent authorities

- **Organisation administrator:** configures tenant policy, allowed feature set, provider allowlists, data classes, retention, budgets and permitted operating windows.
- **Device owner / participating user:** separately consents to use of their device and to any personal-data or telemetry scope that affects them.

Both are required where a feature uses employee devices or shares their telemetry. An administrator cannot override individual opt-out. Consent revocation must stop future collection/transmission and invalidate affected participation credentials or leases.

## Required administrator feature card

Every feature in the future Enterprise Feature & Risk Centre must show:

- Purpose and concrete example.
- Implementation state: Available, Contract only, Administrator configurable, Blocked pending prerequisites, or Not implemented.
- Risk rating and plain-language reason.
- Tenant/device/data scope and permitted recipients.
- Resource, network, retention and operating-window budgets.
- Required administrator role and separate device-owner consent.
- Dependencies, platform support, limitations and rollback/revocation.
- Audit evidence and the exact tests/customer-lab evidence still missing.

The UI is informational and administrative only. The authenticated service must re-authorize every operation; a client-side toggle is never sufficient.

## Current capability inventory

| Feature | Current state | Risk / enablement rule |
|---|---|---|
| Trusted device enrollment and signed approval primitives | Implemented foundations; production identity hosting/key custody remain incomplete | High. Production enablement requires authenticated OIDC/HTTPS service, protected key custody, authoritative revocation and customer deployment validation. |
| Authenticated lease and reservation primitives | Implemented local/durable foundations; ledger snapshots are HMAC-authenticated for integrity, **not encrypted at rest**; not a distributed scheduler | High. HMAC does not provide confidentiality. If ledger contents require at-rest confidentiality, add versioned AEAD storage with separately protected keys and an audited migration. Do not dispatch work until production service-side authorization, receiver-side validation, isolation and cancellation exist. |
| Operator console | Read-only preview; intentionally shows no fake fleet data | Medium. Keep read-only until authenticated tenant-scoped APIs, RBAC and durable audit are deployed. |
| Model/runtime catalogue | Candidate information only; no tenant distribution | Medium–High. Admin allowlist and device-owner consent must precede any future distribution. Verify immutable digest, licence, size, storage, hardware fit and rollback. |
| Workload admission / resource policy | Policy and contract foundations only | High. Fresh telemetry, owner opt-in, admin schedule, interactive-use pause, power/thermal and data-classification gates must be rechecked by the worker. |
| Collective Defence | Dual-consent policy primitive and event contract; participation default-off | High. Tenant admin opt-in **and** individual device/user opt-in are independently required. Only allowlisted, minimised event metadata; no contents or remote control. |
| Read-only endpoint sensors / event ingestion | Prototype/contract and selected local adapters; not a deployed fleet sensor service | High. Require signed device identity, tenant binding, schema/size limits, privacy review, rate limits, retention and revocation tests before pilot. |
| Security Centre provider orchestration | Read-only adapter foundations and deployment plans | High. Customer-selected firewall/AV/EDR tools remain authoritative. No firewall edits, quarantine, process termination or file deletion in the initial phase. |
| Infrastructure Shield profiles | Deployment design / customer-selectable profiles | High. Do not install or reconfigure customer network/security services until signed deployment, rollback, least privilege and lab evidence exist. |
| Enterprise Intelligence planner/connectors | Contract/design work; production provider connectors not established | High. Require tenant policy plus per-user OAuth consent; read-only data first; no message sending or calendar mutation in MVP. |
| Remote Worker / Partner dispatch and execution | Disabled / not implemented as production capability | Critical. No administrator override. Requires production identity, authenticated transport, receiver-side policy, OS-enforced sandboxing, resource quotas, cancellation, audit and independent security review. |
| Arbitrary shell, stealth monitoring or unrestricted endpoint control | Not an approved feature | Critical. No global enable switch or tenant-admin bypass. |

## Enablement state machine

Use these states in the UI and service model:

1. `available_by_default` — low-risk, tenant-scoped read-only metadata only.
2. `requires_admin_and_owner_consent` — both independent approvals are required.
3. `administrator_configurable` — production service-side enforcement, RBAC, audit and revocation are already deployed and tested.
4. `blocked_pending_safety_gate` — code or contract exists but production dependencies or evidence are missing.
5. `contract_only` — schema/policy/API shape exists without a working production service.
6. `not_implemented` — no functional implementation exists; no enable switch is shown.

A tenant administrator may configure only capabilities in the first three states and only within the documented policy envelope. UI state cannot authorize an operation. Unknown, stale, mismatched or unavailable consent/policy must fail closed.

## Minimum acceptance tests for administrator enablement

- Tenant A cannot enable, inspect or change Tenant B features or devices.
- Non-admin users cannot change tenant policy; UI-only or caller-supplied role claims are rejected.
- Tenant enablement without device-owner consent causes no sensor activation or event transmission.
- User/device revocation stops queued and future sharing and invalidates participation credentials/leases.
- Stale telemetry, expired leases, replayed requests, missing policy and failed audit writes deny the action.
- High-impact actions require separate design, explicit scoped approval, idempotency, rollback/expiry and immutable audit.
- No remote execution, arbitrary shell, autonomous containment or destructive remediation is activated by a global switch.
- Cross-tenant, concurrency, failure-recovery and customer-hosted lab tests pass before production rollout.

## Release boundary

Issue #20 remains the production control-plane gate. The repository currently has no deployed OIDC/HTTP service, production KMS/HSM/TPM key custody, external linearizable anti-rollback anchor, durable tenant-scoped service repository or production workload dispatch. Contract tests and in-memory reference providers must not be presented as production infrastructure.
