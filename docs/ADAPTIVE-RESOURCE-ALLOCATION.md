# Adaptive resource allocation

UJANI Enterprise AI does not impose a fixed percentage split between a user's device, other enrolled organisational devices, or an explicitly approved external service. Placement is decided per workload and, where a workload contract supports it, per bounded task segment.

## Placement order

1. Keep deterministic OS-native work on the originating device when it is capable and policy permits it.
2. Prefer an already-running, explicitly enrolled organisational worker when the task needs more compute and the worker has fresh authenticated telemetry, sufficient reserved headroom, required isolation, and an allowed data boundary.
3. Keep work on the originating device when moving it would cost more in data movement, latency, energy, or operational risk than it saves.
4. Use an external provider only when the organisation has explicitly configured that route, the workload's data classification permits it, and the required approval has been recorded. External cloud execution is not an implicit fallback.
5. If no permitted placement exists, defer or reject the workload with an actionable reason; never wake a sleeping device or silently exceed a resource budget.

## Inputs to each placement decision

The scheduler should evaluate policy and data classification first, then capability and quality fit, fresh device health and capacity, interactive-user presence, power and thermal state, OS-isolation readiness, network/data-transfer cost, latency, reliability, energy impact, and administrator quotas. A larger model or nominally faster device is not automatically the best placement.

A workload may be partitioned only at declared, versioned boundaries. Each segment must carry its required capabilities, input/output limits, data classification, dependency information, and cancellation semantics. Keep supported segments where they are; move only a segment that needs another permitted capability. Do not send an entire document or conversation to solve one unsupported operation.

## Consent, trust and accounting

- Device-owner opt-in and administrator authorisation are both required before a device contributes resources.
- Only authenticated, enrolled devices and fresh, signed evidence may influence admission.
- Admission and resource reservation must be atomic and bounded by the device budget and protected system headroom.
- Refreshed telemetry must distinguish reservations already reflected in the sample from reservations that still need to be charged. Replaying or reusing a sample must not create additional capacity.
- Every lease is bounded, authenticated, attributable and cancellable. A worker must independently enforce the approved workload limits and isolation before execution.
- Workload data stays within the approved organisation boundary unless a separate external route is explicitly authorised by policy and the data owner.
- No remote shell, arbitrary command execution, silent background compute, or automatic containment is enabled by this placement policy.

## Execution receipts

Record the workload and segment identifiers, policy and manifest versions, selected device/provider, capability and telemetry evidence references, resource reservation, data classification, approval reference, start/end status, cancellation reason, and measured transfer/compute information where available. Distinguish measured facts from estimates and unknown values.

## Implementation status

This document defines the intended placement contract; it does not claim that a distributed scheduler or worker execution engine exists. The current repository contains policy, signed-evidence, inventory, and reservation-ledger prototypes. Production telemetry sequencing, correct reconciliation of refreshed samples with active reservations, trusted key provisioning, worker-side isolation/enforcement, authenticated dispatch, and independent security review remain prerequisites. Remote execution remains disabled until those controls are implemented and tested.
