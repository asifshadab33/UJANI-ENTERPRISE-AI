# Enterprise local-model choices and customer onboarding

## Product decision

UJANI Enterprise AI uses the same descriptive candidate catalogue as Public AI at `catalogs/local-model-catalog-v1.json`, while adding organisation governance. The catalogue is not a download manifest, an installation instruction or a workload authorization.

Enterprise customers must be able to choose which models are approved for their tenant, which devices may receive them, and whether distribution is central, internal-network or user-requested. Device-owner consent and organisation policy remain separate requirements.

## Customer and operator setup

1. Detect and report device OS/architecture, available and total RAM, free storage, CPU/GPU/NPU and installed runtimes using supported native inventory sources.
2. Show model descriptions in plain language: what work each model does, limitations, exact artifact size, installed-size estimate, RAM guidance, runtime/platform support and licence.
3. Offer tenant-wide choices: **Approved basic models**, **Approved advanced models**, **Custom allowlist**, or **No model distribution yet**.
4. Let administrators approve exact model IDs, publisher, immutable version/digest, quantisation, licence and runtime compatibility—not just a friendly model name.
5. Define eligible device groups, storage ceilings, download windows, network source/mirror, update/rollback policy and whether users may request additional approved models.
6. Require separate device-owner opt-in where a device is contributing compute or receiving organisation-managed workloads, consistent with existing trust and consent controls.
7. Show operators installed versus merely approved/available models, inventory freshness and evidence confidence. Stale or unknown inventory must remain unknown.
8. Never interpret model approval or model presence as authorization to execute a workload. Existing enrollment, owner consent, administrator approval, leases, admission and isolation gates remain mandatory.

## Enterprise controls

- Tenant-scoped approved and denied model lists.
- Exact version/digest pinning and licence acceptance.
- Per-device-group eligibility and resource limits.
- Optional internal artifact mirror; no UJANI-operated central model hosting requirement.
- User request workflow for models outside the approved set.
- Download scheduling that respects interactive use, power, thermal and network policy.
- Rollback and revocation when a model is withdrawn or a digest changes.
- Audit metadata for approval, distribution, cancellation and removal; never log prompts or document contents.
- Read-only inventory by default; inventory metadata is not hardware attestation.
- No model-triggered remote execution, arbitrary shell, or unapproved device-to-device transfer.

## Size and compatibility reporting

The exact quantized artifact manifest must supply download bytes, installed-size estimate, immutable identity and licence reference before a distribution plan is approved. Catalogue RAM bands are advisory only. Use the existing model/runtime inventory v1 contract and typed capability matcher. Do not convert estimated memory fit into verified admission. Missing, stale or contradictory telemetry must fail closed for workload admission.

## Distribution profiles

- **Local only:** administrator approves a model; an individual device owner chooses whether to install it.
- **Managed distribution:** administrator schedules a verified artifact to an explicitly enrolled and eligible device group, subject to tenant policy and device-owner permissions.
- **Internal mirror:** customer hosts approved artifacts internally; UJANI verifies the pinned digest before use.
- **No distribution:** fleet inventory can still report installed runtimes/models where separately consented and supported; no model download occurs.

## Acceptance criteria

- Public and Enterprise catalogue JSON remains byte-identical.
- Tenant policy is stored separately from descriptive catalogue metadata.
- No model download or distribution occurs from catalogue visibility alone.
- Exact artifact version, digest, quantisation, licence and sizes are pinned before approval.
- Admin approval and device-owner consent are never conflated.
- Inventory is read-only and freshness/evidence confidence are visible.
- Model presence/approval does not bypass existing workload admission, lease, trust or isolation controls.
- Audit events are metadata-only and tenant-scoped.
- Customer can select no models and still use non-model features.
- Runtime/platform support is reported only after exact platform validation.
