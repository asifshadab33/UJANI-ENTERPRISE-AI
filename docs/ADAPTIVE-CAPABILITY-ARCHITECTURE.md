# UJANI Enterprise Adaptive Capability Architecture

**Status:** Proposed architecture and delivery contract  
**Applies to:** UJANI Enterprise AI  
**Related policy:** [OS-first capability reuse](OS-FIRST-CAPABILITY-REUSE.md), [adaptive resource allocation](ADAPTIVE-RESOURCE-ALLOCATION.md), [resource efficiency strategy](RESOURCE-EFFICIENCY-STRATEGY.md)  
**Implementation status:** This document defines a target contract. It does not claim that external software discovery, package distribution, installation, provider authentication or remote worker execution is implemented.

## 1. Purpose and separation

Enterprise AI should let an organisation extend its approved capability set without installing every tool on every workstation. It must remain an organisation-controlled resource and policy manager, not a consumer plugin marketplace and not an unrestricted remote-execution system.

The same principle applies as in Public AI—small core, optional capabilities—but Enterprise controls are different: administrators curate and approve the catalogue, define tenant policy and distribution rings, and enforce quotas. Device owners retain visibility and any required local consent. Public AI and Enterprise AI remain separate applications, repositories, settings stores and release tracks.

## 2. Three layers

### Enterprise control-plane core

Keep the operator console, tenant policy, trusted-device registry, authenticated inventory/lease contracts, capability catalogue metadata, approvals, audit records and resource admission in the core. Do not make optional third-party utilities or AI model weights prerequisites for the control plane.

### Approved capability packages

An administrator may approve optional, version-pinned capability packages for a tenant or device group. Examples include media conversion, OCR, image enhancement and document processing. Prefer OS facilities and already-installed customer-managed software. Packages are distributed only through an approved, authenticated source and only to eligible devices.

### Model runtimes and model artifacts

Keep model runtimes and weights independently optional. Administrators can define approved model families, versions, licences, resource envelopes and distribution policy. Users must see what will be installed and the expected storage/hardware requirements. Enterprise policy may prohibit a model or require admin approval, but must not misrepresent unknown capabilities as supported.

## 3. Catalogue and manifest contract

Each package/capability descriptor is versioned and tenant-scoped. Required fields:

- tenant, capability, provider and package identifiers;
- manifest schema, package and adapter versions;
- supported OS/architecture and runtime dependencies;
- publisher identity, authenticated source, immutable artifact digest and verified signature;
- licence and redistribution constraints;
- download/installed-size bounds;
- operation class (read-only, preview, state-changing);
- permissions, data classification, filesystem scope and network/egress declaration;
- CPU, memory, storage, timeout, request/response and concurrency limits;
- invocation, cancellation, cleanup, update, rollback and uninstall contracts.

A catalogue entry is metadata, not proof of trust or authorization. Reject malformed, stale, unsupported, cross-tenant or unverifiable descriptors. The package digest establishes artifact identity; publisher signatures and trust roots establish provenance. Unknown or missing evidence fails closed for installation and execution.

## 4. Governance and rollout

1. Administrator discovers/reviews a candidate and records source, licence, security review, supported platforms and data-flow assessment.
2. Tenant policy approves or rejects the package and declares permitted operation classes, data classifications, network access and resource budgets.
3. Distribution policy assigns an exact version to a test ring before wider deployment. Pin artifacts; do not track floating latest versions.
4. Device owner receives a clear notice of package purpose, publisher, version, size, permissions, data scope, resource use and whether the package can communicate externally.
5. Installation is separately authorized under the tenant policy and any required device-owner consent. Admin approval alone must not bypass OS privilege boundaries.
6. Health, version and installed state are reported using authenticated evidence. Stale or missing state is Unknown, not compliant.
7. Updates require a reviewed new version, digest/signature validation, rollout policy and rollback plan. Removal must preserve user data and leave an auditable result.

No background installation, silent update, device wake-up or remote arbitrary command is permitted by this architecture. If a platform cannot enforce required controls, mark it unsupported for that package.

## 5. Invocation and workload boundary

A capability is invoked only through a registered typed adapter. The adapter must validate the tenant, device identity, package version, operation, approved data scope, consent/approval references, resource budget and cancellation deadline before any side effect.

Do not turn package invocation into a general shell, arbitrary script runner, remote desktop or unrestricted process API. Never execute model-generated code or commands returned by a catalogue. Network access is denied unless declared, tenant-approved and required by the specific task. External data egress requires data-classification approval and a named destination.

For work delegated to another enrolled device, retain all existing Enterprise gates: authenticated trusted device, owner opt-in, administrator authorisation, fresh signed telemetry, atomic bounded reservation/lease, worker-side revalidation and OS-enforced isolation. Capability availability does not grant a worker execution lease. Remote execution remains disabled until its separate release gates are met.

## 6. Resource and storage policy

Optional packages must not consume resident memory when idle unless a separately approved always-on service has a documented reason and budget. Start on demand, enforce CPU/RAM/storage/time/concurrency ceilings, cancel safely, and stop/release resources after completion.

The operator console should report per tenant/device:
- core, optional package, runtime and model storage separately;
- package version, provenance, installation state and rollout ring;
- declared resource budget versus measured usage;
- idle/running/failed/unsupported state;
- quota, reservation and current headroom;
- last authenticated observation and evidence freshness.

Do not equate advertised capacity with available capacity. Reuse the existing authenticated, fresh, measured resource-admission contracts. Unknown, estimated or stale capacity must not be admitted as available. Do not wake sleeping devices or take resources from interactive workloads.

## 7. Resource tiers and compatibility

The following are product planning targets for the optional endpoint application, not validated Enterprise server/control-plane requirements:

| Profile | Planning target | Expected use |
|---|---:|---|
| Core compatibility | 4 GB RAM | Basic console/endpoint management and light OS-assisted tasks, subject to OS overhead |
| Everyday | 8 GB RAM | Recommended endpoint baseline |
| Local AI | 16 GB RAM or more | Selected small/medium models, depending on model/context/VRAM |
| Advanced AI | 32 GB RAM or more | Larger models and heavier workloads, still model-dependent |

A fleet operator must be able to set stricter minimums and per-package resource ceilings. A 4 GB device is not expected to run every package or model. Model runtime, context size, quantization, concurrency and accelerator memory determine actual requirements.

A proposed 150–300 MB core installed-size target may be evaluated for a lightweight endpoint client, but must not be applied to the Enterprise control plane or represented as measured. Measure installers and idle resource use per OS, architecture and packaging format before publishing requirements.

## 8. Audit, privacy and tenant isolation

Every approval, install, update, invocation, reservation and removal must be tenant-scoped and attributable. Receipts should contain operation ID, tenant/device, package/version/digest, policy and approval references, data classification, resource budget, timestamps, outcome and cancellation reason. Do not record prompts, document contents, credentials or unrelated user activity.

Catalogue entries, manifests, device telemetry and operator-provided values are untrusted until validated. Tenant boundaries must be enforced server-side; never trust tenant identifiers supplied only by a client. Retention, export and access to audit records remain governed by tenant policy.

## 9. Phased implementation and gates

1. **Inventory and parity:** map existing capability registry, resource contracts and OS reuse; do not create a parallel registry.
2. **Manifest schema:** add versioned tenant-scoped package metadata and strict validation tests.
3. **Admin catalogue:** read-only review/approval UI, with no package execution.
4. **Policy and rollout:** approved version pins, test rings, owner notice/consent and revocation.
5. **One low-risk package:** prove install/verify/invoke/cancel/update/rollback/remove on supported platforms.
6. **Resource reporting:** measured idle and task resource use, quota enforcement and lifecycle cleanup.
7. **Expansion:** only after tenant isolation, provenance, policy, OS enforcement and independent security review.

Acceptance requires cross-tenant negative tests; malformed/oversized/stale manifest tests; signature/digest verification; approval and owner-consent denial-before-side-effect tests; package allowlist and version-pin tests; invocation scope/resource/cancellation tests; rollback/removal tests; audit receipt coverage; and platform-specific installer/idle-resource measurements.

## 10. Invariants

- The Enterprise control plane remains independent from Public AI.
- Capability metadata never grants authorization by itself.
- No package is installed or updated silently.
- No device is awakened for work.
- No arbitrary shell, model-generated code execution or unrestricted remote execution.
- No external data egress without tenant policy and task-scoped approval.
- No estimated or stale telemetry is treated as available capacity.
- Optional components remain removable and separately accounted for.

The governing principle is: **tenant-approved capabilities, bounded execution, trusted evidence, device-owner visibility, and no expansion of remote-execution authority by implication.**
