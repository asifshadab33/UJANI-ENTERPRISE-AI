# UJANI Enterprise AI — architecture

## Scope

Coordinate compute inside one organisation across explicitly enrolled and authorised hardware. This is not a public peer-to-peer compute network. Every participating device has an accountable owner, identity, policy and revocation path.

## Logical planes

### Control plane
- Organisation identity and role-based access control.
- Device enrolment, approval, inventory and revocation.
- Workload submission and policy evaluation.
- Scheduling, quotas, maintenance windows and priorities.
- Audit, monitoring and administrative reporting.

### Device/worker plane
- Authenticated agent with least privilege.
- Capability and availability reporting.
- Local policy validation before accepting work.
- Isolated workload runner.
- Resource enforcement and telemetry.
- Signed update and rollback mechanism.

### Data plane
- Explicitly scoped input/output transfer.
- Data classification and residency constraints.
- Encryption in transit and at rest where stored.
- No broad shared filesystem or ambient credentials.
- Retention and deletion policies.

## Workload lifecycle

1. An authorised user or service submits a typed workload.
2. The control plane authenticates the requester and evaluates organisation policy.
3. The scheduler selects only enrolled devices that meet capability, locality, availability and quota constraints.
4. The worker validates the signed assignment and local execution policy.
5. The workload runs inside an OS-enforced isolation boundary.
6. Resource usage, status and audit events are reported.
7. Results are returned to an authorised destination and verified.
8. Temporary data and credentials are cleaned up according to policy.

## Scheduling signals

Candidate signals include CPU availability, memory headroom, GPU model/VRAM/runtime, NPU support, current interactive activity, power/thermal state, network locality, maintenance window, data classification, workload deadline and administrator quotas.

Hardware presence is not equivalent to usable capacity. Drivers, runtime versions, memory, thermal throttling and competing workloads must be considered.

## Device enrolment and identity

- Admin invitation or managed deployment; never auto-enrol by network discovery alone.
- Device owner/administrator approval and clear disclosure of resource use.
- Unique device identity with short-lived credentials.
- Mutual authentication and signed workload assignments.
- Revocation, key rotation and lost-device procedures.
- Least-privilege service account and narrowly scoped permissions.

## Workload isolation

The scheduler is not a security boundary. Enforce isolation on the worker using suitable OS primitives (for example, containers, namespaces, job objects, sandbox profiles or virtual machines depending on platform and threat model). Restrict filesystem, network, process, device and resource access. Do not rely on application-level promises alone.

## Governance

Administrators configure:
- allowed device groups and workload classes;
- CPU/GPU/memory budgets and concurrency;
- operating windows and interactive-use protections;
- approved model/runtime registries;
- data classification, residency and retention;
- network egress and destination allow-lists;
- user roles, approval gates and audit retention.

Employees should be able to see when a device is participating and how to pause or opt out where organisational policy permits. Do not conceal resource consumption.

## Integration with UJANI Public AI

Share versioned task schemas, capability vocabulary and result/provenance formats. Enterprise adds identity, organisation policy, scheduling and audit. Personal UJANI must not depend on the enterprise control plane.


## Production authority and admission boundary

The production control plane has one authoritative persistence and transaction boundary: PostgreSQL. Tenant identity, operator/device ownership, consent generations, replay state, reservation revisions, lease admission/lifecycle and their audit records must be evaluated and committed through the same authenticated tenant-scoped transaction boundary.

The Rust ledger is not a second production authority and must never independently authorize a production lease. It may be used as a development/test adapter or for a separately scoped local purpose, provided that it cannot issue or validate production dispatch authority. Do not dual-write independent authoritative state or accept disagreement between two stores as a valid state.

The HTTP/service adapter is responsible for authenticating the caller and verifying signed requests and administrator approval before invoking database admission functions. Tenant and subject identifiers must come from the authenticated server-side identity context, not caller-controlled request fields. Database functions recheck mutable tenant, device, owner-binding, consent, approval, freshness, capacity and reservation facts transactionally. Audit failure, missing identity, stale consent, replay, revoked trust, or an inconsistent reservation must fail closed.

## Remote-execution release gate

Remote execution and dispatch remain disabled until all of the following are implemented and independently verified:

- Production HTTP hosting with TLS/server identity and a real OIDC or mTLS authentication boundary, including issuer/audience/state/nonce validation where OIDC is used.
- Server-side tenant membership and role resolution; tenant identity is never trusted from browser input.
- Protected device-key provisioning, custody, rotation, revocation, backup and recovery, with anti-rollback protection.
- Owner-bound enrollment and current owner opt-in, plus explicit organisation administrator approval.
- Single-transaction replay protection, lease admission, reservation updates and durable audit using PostgreSQL as the only production authority.
- Worker-side OS-enforced isolation, least privilege, resource limits and explicit network-egress policy. Scheduler selection alone is not a security boundary.
- Integration tests for restart, replay, clock skew, stale/revoked keys, owner-consent changes, cross-tenant access, concurrency, audit failure and recovery.
- Operational evidence for backup/restore, monitoring, incident response and key recovery.

Until that gate is met, the control plane may develop and test authenticated read-only inventory and overview workflows, but it must not dispatch workloads, enable remote execution, or represent demo/fixture data as live tenant data.

## Evidence and release terminology

Use these terms precisely in implementation reports:

- **Implemented:** code exists on a named branch or commit.
- **Tested:** the relevant test suite passed against that exact commit; identify platform and test scope.
- **Security reviewed:** threat cases and negative tests for the relevant boundary were examined; passing general CI is insufficient.
- **Release ready:** integration, supported-platform, packaging, operational recovery, documentation and acceptance gates are all satisfied.

A green CI result is evidence for the checks that actually ran; it is not by itself a security review or release approval.
