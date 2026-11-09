# Local-first organisational execution and automatic model selection

Product defaults (2026-11-10): local-first execution and automatic model selection.

UJANI Enterprise AI applies local-first at organisation scope while remaining an administrator-controlled resource/fleet coordinator. Local means an authorised resource inside the organisation's approved trust and data boundary; enrolment alone does not make a device eligible for every workload.

## Placement hierarchy

For each bounded workload segment, evaluate: (1) the submitting device or its explicitly approved local runtime when inside the workload data boundary; (2) other authorised, trusted, currently available organisation-owned devices/servers satisfying data residency, owner consent, isolation, resource, energy and policy constraints; (3) an explicitly configured external provider only when organisation policy permits it and the exact segment is approved under applicable administrator and data-owner consent; otherwise report unsupported or queued. Never silently relax policy.

Enrolment alone is insufficient. Fresh authenticated telemetry, valid trust state, owner consent, live lease, resource admission, isolation readiness, policy approval and revocation checks remain prerequisites. Sleeping or interactively busy devices must not be awakened or commandeered.

## Automatic model selection

Automatic selection is the default for workload placement and model choice. Select only from models/runtimes discovered through trusted inventory and confirmed available on eligible resources. Filter by workload modality/operation requirements; runtime compatibility/context; data classification/residency/tenant policy; trusted device identity, consent and lease; isolation readiness; positively measured CPU, memory, GPU/VRAM and other resources; thermal, power, interactive-user and energy constraints; administrator quotas, priority and deadline. Only then rank eligible candidates by estimated completion, energy/cost and load. Unknown capability is not available capability. Do not infer GPU/NPU support from CPU/RAM inventory alone or assume the largest model is best.

Automatic placement never authorises remote execution. The remote dispatch boundary remains disabled until trust, isolation, lease, approval, audit, revocation and rollback controls are implemented and independently validated.

## Partial workload execution

Represent workloads as bounded graphs of registered operations with explicit input/output references and data classifications. Keep operations on authorised internal resources whenever feasible. If one segment requires an unavailable capability, preserve supported internal segments and isolate only the missing segment for a possible external route. Before transfer, show exact provider, model, purpose, data class, selected segment/content scope and policy basis. Require relevant administrator approval and any required individual/data-owner approval. Return approved results to the internal workflow. Never forward a whole job, document set or tenant dataset merely because one step needs external help.

## Shared contracts and separation

Public AI and Enterprise AI may share versioned task, capability, model-metadata and provenance schemas, but not authority boundaries. Public selects resources controlled by the individual user on that device. Enterprise selects only organisation-authorised resources and applies tenant, device-owner and administrator policy. Enterprise must not assume Public AI is installed; Public AI must not depend on Enterprise. Capability claims and execution receipts retain provenance/evidence quality; a reported model or accelerator capability is not proof of successful execution.

## Implementation sequence

1. Finalise versioned workload-segment and model-capability contracts.
2. Complete authenticated runtime inventory and freshness/attestation evidence.
3. Implement a dry-run local-first placement planner with deterministic tests.
4. Reconcile reservations transactionally with newer telemetry samples.
5. Prove lease lifecycle, concurrency, cancellation, revocation and crash recovery.
6. Add operator-visible reasons for candidate selection/rejection.
7. Keep dispatch disabled until OS isolation and independent security review pass.
8. Add external partial-segment routing only after policy/consent and provenance are end-to-end enforced.

## Acceptance criteria

- Eligible internal resources are preferred over external providers.
- Ineligible or unverified devices are never selected to improve a score.
- Only the segment requiring unavailable capability is considered for external assistance.
- Unknown telemetry, stale trust, missing consent, missing lease or missing isolation fails closed.
- Automatic choices are explainable and auditable; administrators retain policy controls.
- No silent device wake, background compute, model installation or remote execution.
- Scheduling respects interactive use, thermal state, power and energy budgets.
