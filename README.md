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

The Rust crate in `crates/ujani-enterprise-policy` contains device/workload policy types, signed administrator approvals, dual-signed worker/admin scheduling evidence, a file-backed reservation ledger with OS advisory locking and crash-recovery snapshots, token-bound lease renewal/release, persistent single-use dispatch challenges, and a strict versioned workload-manifest contract. These are local policy/storage prototypes, not a production control plane or distributed scheduler. The ledger checksum detects accidental corruption but is not a MAC; the ledger is not encrypted at rest and cannot protect against a local attacker who can modify its files. Enrollment keys and device inventory must come from a trusted, non-caller-controlled control plane. The project still does not communicate with devices, dispatch or execute real jobs, create sandboxes or enforce operating-system security controls.

See [the workload manifest contract](docs/WORKLOAD-MANIFEST.md), [the durable reservation ledger boundary](docs/DURABLE_RESERVATION_LEDGER.md) and [the Personal-to-Enterprise integration draft](docs/INTEGRATION_CONTRACT_DRAFT.md).

Run tests:

```sh
cargo test --workspace --locked
```

## Collective Defence security boundary

The Collective Defence work is currently a versioned, privacy-minimised event contract plus a side-effect-free dual-consent policy primitive. Participation is intended to require both an authorised tenant administrator's opt-in and a separate individual user's opt-in for the exact device and principal. See [the consent policy and production integration requirements](docs/COLLECTIVE-DEFENCE-CONSENT.md) and [the event contract](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/blob/fix/collective-defence-event-contract-mainline-2026-11-08/docs/COLLECTIVE-DEFENCE-EVENTS.md).

This is not yet a live sensor, ingestion service, detection/correlation engine, or dashboard. Consent/revocation persistence and authenticated transport are not implemented. Threat-intelligence exchange does not grant remote access or remote execution; automated containment and remote execution remain disabled.

## Deployment boundary

Start with a trusted internal lab and explicitly enrolled test machines. Do not deploy to employee endpoints or production servers until identity, agent security, isolation, resource enforcement, incident response and independent security review are complete.

## Relationship to UJANI Public AI

[UJANI Public AI](https://github.com/asifshadab33/UJANI-PUBLIC-AI-) is the personal local-first AI project. Enterprise AI adds organisation-controlled fleet management and scheduling. Shared task/capability contracts should be versioned and reused; enterprise policy and fleet control remain separate.


## Inventory timestamp validation update

The read-only inventory contract now rejects heartbeat and telemetry timestamps more than 30 seconds in the future, and rejects telemetry timestamps that are materially newer than the associated device heartbeat. A small clock skew remains tolerated; stale records continue to fail closed. This is a policy-library validation only: it does not establish an authenticated live agent heartbeat or server-side clock synchronisation.
