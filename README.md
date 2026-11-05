# UJANI Enterprise AI

**Make authorised organisational hardware work smarter — safely, transparently and under administrator control.**

UJANI Enterprise AI is an open-source project concept for coordinating an organisation's own enrolled and authorised compute resources: office PCs, workstations, GPU workstations, internal servers, GPU servers and compatible edge devices.

It is designed for controlled internal use, not a public marketplace for strangers' devices.

> **Project status: early prototype / pre-alpha.** This repository currently provides architecture, policy contracts and a small illustrative Rust policy crate. It is not a production fleet manager, scheduler, endpoint agent or security product.

## Product principles

- Only explicitly enrolled, organisation-authorised devices participate.
- No silent use of employee devices. Device owners and administrators must receive clear disclosure and control.
- Administrators define workloads, data boundaries, operating windows, quotas and permitted resource types.
- Local execution and data locality are preferred where feasible.
- Workloads are isolated, attributable, cancellable and auditable.
- Resource use respects interactive user activity, thermal state, power and administrator budgets.
- Personal UJANI Public AI remains independently usable without an enterprise control plane.

## Intended capabilities

1. Device enrolment and identity lifecycle.
2. Hardware/runtime inventory and health reporting.
3. Availability-aware CPU/GPU/NPU scheduling.
4. Workload isolation, quotas and priority classes.
5. Organisation policy and data residency enforcement.
6. Monitoring, audit events and cost/energy reporting.
7. Integration with UJANI Public AI through versioned task and capability contracts.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [ROADMAP.md](ROADMAP.md).

## Initial prototype

The Rust crate in `crates/ujani-enterprise-policy` contains basic device/workload policy types and a conservative admission decision. It does not communicate with devices, schedule real jobs, create sandboxes or enforce operating-system security controls.

Run tests:

```sh
cargo test --workspace
```

## Deployment boundary

Start with a trusted internal lab and explicitly enrolled test machines. Do not deploy to employee endpoints or production servers until identity, agent security, isolation, resource enforcement, incident response and independent security review are complete.

## Relationship to UJANI Public AI

[UJANI Public AI](https://github.com/asifshadab33/UJANI-PUBLIC-AI-) is the personal local-first AI project. Enterprise AI adds organisation-controlled fleet management and scheduling. Shared task/capability contracts should be versioned and reused; enterprise policy and fleet control remain separate.
