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
