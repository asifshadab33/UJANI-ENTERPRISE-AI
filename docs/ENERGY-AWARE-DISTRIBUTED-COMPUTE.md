# UJANI Enterprise AI — energy-aware distributed compute

## Primary objective

Use existing, already-powered, underutilised organisation-owned compute to complete legitimate AI and non-AI workloads, reducing avoidable dependence on central AI data centres and their electricity demand. Do not create workloads merely to consume spare capacity. The scheduler must be allowed to leave capacity unused.

This is a workload-level optimisation objective, not a promise that every distributed job saves energy or that moving a job automatically reduces a data centre's metered electricity.

## Placement order

1. Use deterministic local processing when it meets the task's correctness, quality and privacy requirements.
2. Use a compatible local model/runtime when it meets the required quality, latency, data-classification and resource budgets.
3. Consider an enrolled enterprise worker only when it is already running, explicitly owner-opted-in and administrator-approved, inside its approved schedule, on AC power, thermally safe, not in interactive use, and reporting fresh authenticated telemetry.
4. Consider an approved central/cloud service only when local/distributed options are unsuitable and the applicable user/admin approval, data classification, egress and residency policies allow it.
5. If no route meets safety, quality, availability and energy requirements, defer or decline the task rather than forcing execution.

Never wake, power-on or power-cycle a sleeping/off device. Never silently use employee hardware. A device's GPU/NPU presence is not proof of usable model/runtime compatibility.

## Energy decision contract

For the same successful workload and output-quality target, compare:

- Central baseline energy attributable to the workload, including a consistent facility-overhead boundary.
- Incremental worker-device energy above its normal idle/owner-use baseline.
- Network transfer energy.
- Retry, failure and checkpoint overhead.
- Additional cooling/facility energy where attributable.

The Rust energy policy module compares these components in milliwatt-hours and prefers distributed placement only when the complete distributed total is strictly lower than the central baseline. A tie prefers central execution. It refuses comparison when equivalent work has not been verified, when the central baseline is missing, or when arithmetic overflows. Each input records whether it is directly measured or estimated; the result exposes whether any component is estimated.

The helper is intentionally not a meter, energy estimator, scheduler or execution authorisation. Its caller must provide defensible readings and provenance. Report measured and estimated values separately, with time window, hardware/runtime, workload, quality checks and uncertainty. A positive comparison is not proof that a data centre actually reduced metered consumption.

## Admission and trust gates

Energy preference is evaluated only after the security and resource admission gates. It must never override:

- enrolled, non-revoked device identity and current owner consent;
- administrator approval, schedule, class policy and tenant boundary;
- fresh authenticated telemetry and one-time dispatch challenge;
- already-running state, AC power, interactive-use pause and safe thermals;
- capability/runtime compatibility, CPU/RAM/GPU/NPU capacity and quota;
- workload data classification, residency and network-egress policy;
- verified isolation, cancellation, bounded runtime and auditable receipts.

The current policy crate contains some signed telemetry, approval, lease and reservation primitives. It does not yet provide a live agent, control plane, production scheduler, OS-enforced sandbox, physical energy meter or worker execution gateway. Those are explicit release blockers.

## Public AI relationship

UJANI Public AI remains independently useful and local-first. The mode names below describe intended policy profiles, not guarantees that every control is currently enforced: **Fortress** aims to keep processing local, but the desktop app does not enforce OS-level network isolation and must not be treated as a sandbox; **Smart** aims to prefer local execution and use cloud assistance only after applicable approval; **Worker** is intended for explicitly trusted compute delegation, but peer worker execution is not implemented; **Partner** describes a future bounded local/cloud collaboration profile, not a currently available remote execution capability. Until the corresponding controls, isolation boundaries, and end-to-end tests exist, users and administrators must not rely on these names as security guarantees.

Enterprise adds organisation identity, fleet policy, trusted capacity, scheduling and audit. A future shared versioned task/capability/result protocol must preserve end-user consent, exact payload binding, data classification, audience binding, authenticated transport, durable replay protection and verifiable receipts. The existing Public and Enterprise signed contracts are not yet wire-compatible; do not connect them by assuming otherwise.

## Collective defence relationship

The collective-defence network and distributed compute network are related but separate planes:

- Security intelligence may share privacy-minimised, signed indicators and advisories under explicit governance.
- Compute participation must be separately enrolled, consented, scheduled and authorised.
- A security-event report never grants compute access.
- A compute worker never gains access to another tenant's security events or systems.
- Threat intelligence cannot issue arbitrary worker commands or bypass local execution policy.

## Safe pilot sequence

1. Synthetic offline policy tests and energy-comparison tests.
2. Two or three explicitly enrolled lab devices; no employee endpoints or anonymous public peers.
3. Read-only capability/availability collection with owner-visible pause and opt-out.
4. Deterministic non-sensitive CPU workloads, then low-risk local inference.
5. Verify equivalent output and quality; compare central, local and distributed energy with external meters where possible.
6. Include network, retries, failed attempts and additional cooling; publish uncertainty and negative results.
7. Stop on consent, identity, isolation, privacy, resource, measurement-integrity or unexplained-energy failures.

Do not enable public peer execution until independent isolation review, abuse controls, anti-Sybil protections, key lifecycle, data governance, incident response and reproducible net-energy advantage have passed.
