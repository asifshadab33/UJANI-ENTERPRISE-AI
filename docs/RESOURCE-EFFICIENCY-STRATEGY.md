# UJANI Enterprise AI — resource efficiency and responsible scheduling strategy

**Status:** product direction and engineering gates for the pre-alpha project. This is not a production deployment specification.

## Mission

Help organisations make better use of computing capacity they already own, reducing unnecessary purchases and avoidable dependence on centralised compute where internal resources can safely and efficiently complete the workload.

The objective is not to keep every computer busy. The objective is to complete the required work with the least practical combination of cost, energy, risk and disruption.

## Principles

1. **Authorised assets only.** Enrolment requires an administrator-controlled process, a unique device identity and transparent device-owner notice. IP addresses and network discovery are never proof of authority.
2. **Interactive work wins.** Employee activity, calls, presentations, accessibility needs and foreground applications take priority over batch workloads.
3. **Explicit policy windows.** Administrators define permitted hours, device groups, workload classes and quotas. A schedule is permission to consider a device, not a guarantee it is idle.
4. **Local data locality.** Prefer jobs near their data and enforce classification, residency and egress rules. Do not move sensitive data merely to fill spare capacity.
5. **Least privilege and isolation.** The scheduler is not a sandbox. Workers validate signed assignments and enforce OS-level isolation and limits.
6. **Interruptible execution.** Jobs need cancellation, checkpoints where supported, cleanup and recovery. Non-interruptible tasks must be scheduled only on suitable dedicated resources.
7. **Verified capacity.** Match using runtime/driver compatibility, available memory, thermal/power state and current load, not hardware presence alone.
8. **Measured sustainability.** Compare equivalent completed work and include energy, network, cooling, failed jobs and hardware lifecycle assumptions.
9. **Transparent governance.** Provide administrator audit and a visible device participation indicator, pause controls and revocation paths.
10. **No hidden monetisation.** The product mission is shared resource efficiency and access for small organisations, not extracting profit from employee devices.

## Multi-resource admission contract — preview

The policy crate now exposes `resource_capacity::evaluate_extended_resource_placement` as a side-effect-free admission contract layered over the existing authenticated CPU/RAM worker snapshot. It can additionally evaluate requested GPU memory/compute units, NPU memory/compute units, scratch-storage bytes and network bandwidth/egress policy.

- Optional measurements are explicitly unknown when absent; a request that needs an unknown resource is rejected.
- Accelerator, storage and network readings must be authenticated, fresh and marked measured. Estimated values are not accepted as admission evidence.
- CPU/RAM, already-running state, AC power, owner consent, interactive-use priority, thermal safety and OS-isolation checks continue through the existing CPU admission gate.
- A successful result is a policy estimate only. It does not collect telemetry, reserve resources, acquire a lease, start a worker, enforce quotas or prove a device's driver/runtime can execute a model.

This contract closes part of the resource-dimension modelling gap, but it is not yet wired to an authenticated device-agent telemetry intake, durable lease admission, operator-console inventory or worker-side OS quota enforcement. Those integration and real-device checks remain release gates. Never infer GPU/NPU capability from hardware presence alone, and never wake sleeping or powered-off devices.

## Implementation status — current repository

The target model above is broader than the current executable code. Keep these distinctions visible in operator-facing material; a policy helper or database migration is not a deployed scheduler.

| Capability | Present in the repository | Not yet delivered |
|---|---|---|
| CPU and RAM placement | Deterministic CPU/RAM admission and local-first placement policy helpers; PostgreSQL reference lease-admission work is under review | A production scheduler service, live capacity collector, worker-side quota enforcement and end-to-end dispatch |
| GPU and NPU | Merged PR #218 adds a side-effect-free, fail-closed policy contract for requested accelerator memory and compute units; missing, stale, estimated or unauthenticated measurements are rejected | Production accelerator inventory/identity, driver-runtime-model compatibility probes, trusted sensor collection, durable lease integration and OS quota enforcement |
| Storage and network | Merged PR #218 adds measured scratch-storage and bandwidth/egress admission fields | Trusted live storage/network telemetry collectors, durable quota reservation and worker-side enforcement |
| Power and thermal | Fail-closed policy inputs for AC power and thermal safety; an energy comparison helper accepts measured or estimated inputs | Trusted cross-platform sensor collection, calibrated energy measurement and automatic thermal/power throttling |
| Device telemetry | Monotonic telemetry and read-only Suricata/Zeek evidence-ingestion prototypes with bounded validation; the multi-resource policy consumes measurements supplied by its caller | A production endpoint agent, authenticated live telemetry transport for all resource dimensions, durable tenant operations and fleet-wide health service |
| Trust, consent and leases | Device-owner binding, consent-generation, approval and atomic reservation reference logic with PostgreSQL regression fixtures | Production identity-provider integration, selected database topology, protected key custody, independent anti-rollback anchor and operator workflow |
| Worker execution | Explicit execution gates and policy contracts | Authenticated worker dispatch, OS isolation, result verification and production remote execution; these remain disabled |

**Important:** the current placement and capacity modules are advisory policy components. They do not collect hardware telemetry, reserve resources by themselves or execute work. The PostgreSQL migration is a reference implementation, not a final production database choice. No device may be awakened for work, and no remote execution or automatic containment may be inferred from these prototypes.

The next accelerator implementation must extend the merged preview policy contract without duplicating it. It must be versioned and evidence-backed: enumerate GPU/NPU vendor and device identity, driver/runtime and model compatibility, usable accelerator memory, current reservations, power/thermal state and owner/admin policy. It must fail closed when a field is unknown and must not claim that CPU/RAM capacity can substitute for accelerator memory. Integrate this with the selected workload and telemetry contracts after the control-plane architecture is approved.

## Scheduler decision model

A device is eligible only if all hard constraints pass:
- enrolled, authenticated, not revoked and policy version current;
- device and workload classifications compatible;
- approved execution window active;
- no interactive-use or user opt-out signal;
- required runtime/driver/model and resource headroom verified;
- CPU/RAM/GPU/network/power quotas available;
- data locality and egress policy satisfied;
- worker isolation and signed workload requirements satisfied.

Among eligible devices, rank by a policy-configurable score considering locality, expected completion time, incremental energy, existing load, reliability, thermal/power state and deadline. Do not use a single simplistic "idle CPU percentage" threshold.

## Suggested first workload classes

Start with deterministic, low-risk, interruptible internal workloads:
- approved document conversion and indexing;
- checksums, deduplication and data validation;
- internal batch preprocessing on non-sensitive or explicitly approved data;
- reproducible CPU/GPU batch inference using approved models and datasets.

Defer arbitrary customer code, privileged workloads, unrestricted network access, multi-tenant GPU sharing and sensitive personal data until the isolation and governance model has been independently reviewed.

## Reliability and security controls

- Device-bound identities, short-lived credentials, rotation and revocation.
- Signed, expiring job assignments with unique nonces and policy versions.
- Worker-side policy revalidation before execution.
- Mutual authentication and encrypted transport.
- OS-enforced sandbox or VM boundary appropriate to workload risk.
- Filesystem mounts and network egress allow-listed per job.
- CPU, memory, GPU, process, disk, wall-clock and bandwidth quotas.
- Heartbeats, leases, bounded retries and idempotent job design.
- Checkpoint integrity and output verification.
- Append-only security audit events with controlled access.
- Signed agent updates, SBOM, vulnerability response and incident runbooks.

A container alone is not sufficient protection against every hostile workload or multi-tenant threat. Higher-risk workloads may require virtual machines or dedicated hosts.

## Environmental and cost measurement

Do not claim a carbon or data-centre reduction merely because a workstation was used. Compare a baseline and UJANI execution for the same completed workload and quality level. Record, where measurable:
- incremental device energy, not just peak power;
- idle power and whether the device would otherwise be asleep/off;
- cooling and facility overhead where known;
- network transfer and storage;
- failed attempts, retries and checkpoint overhead;
- centralised alternative utilisation and efficiency assumptions;
- hardware wear and replacement implications.

Sometimes leaving a device asleep and using an efficient central service is better. The scheduler must be allowed to choose no local device.

## Phased deployment gates

### Lab only
- Explicit test-device enrolment and revocation.
- Read-only inventory and heartbeat.
- No remote workload execution.
- Validate policy and telemetry accuracy.

### Controlled internal pilot
- Low-risk signed workloads.
- Single organisation and isolated test data.
- OS-enforced sandbox, quotas, egress controls and kill switch.
- Interactive-use protection and visible participation status.
- Failure injection, recovery and security review.

### Production readiness
- Independent penetration test and threat-model review.
- Signed update and rollback testing, SBOM and incident response.
- High availability, audit retention, backups and disaster recovery.
- Documented customer data classifications and compliance requirements.
- Reproducible performance/energy benchmark and support processes.

## Relationship to UJANI Public AI

Share only versioned task, capability and provenance contracts. Enterprise owns organisation identity, fleet enrolment, policy, scheduling and audit. Public AI must remain independently usable and must never silently become an enterprise worker.
