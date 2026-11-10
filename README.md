# UJANI Enterprise AI

**Make authorised organisational hardware work smarter — safely, transparently and under administrator control.**

UJANI Enterprise AI is an open-source project concept for coordinating an organisation's own enrolled and authorised compute resources: office PCs, workstations, GPU workstations, internal servers, GPU servers and compatible edge devices.

It is designed for controlled internal use, not a public marketplace for strangers' devices.

> **Project status: early prototype / pre-alpha.** This repository currently provides architecture, policy contracts and a small illustrative Rust policy crate. It is not a production fleet manager, scheduler, endpoint agent or security product.

## Product principles

- Only explicitly enrolled, organisation-authorised devices participate.
- No silent use of employee devices. Device owners and administrators must receive clear disclosure and control.
- Administrators define workloads, data boundaries, operating windows, quotas and permitted resource types.
- **Primary objective:** use already-powered, underutilised authorised hardware to reduce avoidable central AI data-centre dependence and energy use.
- Distributed work is considered only after consent, trust, availability, isolation, data policy and equivalent-workload energy checks; sleeping devices are never awakened.
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

The intended per-workload placement rules, adaptive resource allocation criteria, and safety prerequisites are documented in [Adaptive Resource Allocation](docs/ADAPTIVE-RESOURCE-ALLOCATION.md). Placement is dynamic rather than a fixed local/remote percentage; this is a design contract, not a claim that distributed execution is production-ready.

See [energy-aware distributed compute](docs/ENERGY-AWARE-DISTRIBUTED-COMPUTE.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [ROADMAP.md](ROADMAP.md).

## Initial prototype

The Rust crate in `crates/ujani-enterprise-policy` contains device/workload policy types, signed administrator approvals, dual-signed worker/admin scheduling evidence, a file-backed reservation ledger with OS advisory locking and crash-recovery snapshots, token-bound lease renewal/release, persistent single-use dispatch challenges, a strict versioned workload-manifest contract, an in-memory tenant-scoped capability registry with a bounded read-only connector/evidence contract, and a fail-closed CPU capacity admission helper that checks authenticated/fresh telemetry, owner consent, interactive activity, power/thermal state, OS-isolation readiness, configurable CPU headroom and memory reserve; signed worker telemetry binds the worker-reported CPU/RAM capacity and isolation assertions to the enrolled device signature before admission; this authenticates the assertion, not the physical truth of the sensor values. The repository also includes an offline Suricata EVE / Zeek JSON-lines importer and a read-only Malcolm health probe. These are local policy, contract and adapter prototypes, not a production control plane, live event-ingestion service or distributed scheduler. The current V4 durable-ledger snapshots use HMAC-SHA256 with integrity keys injected by a trusted caller, persist per-device monotonic signed telemetry generations and reservation watermarks, assign revisions to lease creation/renewal/release/expiry, reconcile reservations already reflected in signed capacity samples, and read legacy V2/V3 snapshots for migration; production key provisioning remains external, and only the optional separately protected monotonic-anchor mode detects filesystem rollback. The ledger is not encrypted at rest, and unanchored local storage cannot protect against a privileged attacker or filesystem rollback. Enrollment keys and device inventory must come from a trusted, non-caller-controlled control plane. The project still does not communicate with devices, dispatch or execute real jobs, create sandboxes or enforce operating-system security controls.

See [the workload manifest contract](docs/WORKLOAD-MANIFEST.md), [the durable reservation ledger boundary](docs/DURABLE_RESERVATION_LEDGER.md), [the CPU-only inference integration profile](docs/CPU-ONLY-INFERENCE-ADAPTER.md) and [the Personal-to-Enterprise integration draft](docs/INTEGRATION_CONTRACT_DRAFT.md).

Run tests:

```sh
cargo test --workspace --locked
```

## Collective Defence security boundary

The Collective Defence work currently includes a versioned, privacy-minimised event contract, a side-effect-free dual-consent policy primitive, and an in-memory `MemoryConsentAuthority` reference backend with tenant/individual generation compare-and-set, idempotent decisions and hash-linked audit records. Participation is intended to require both an authorised tenant administrator's opt-in and a separate individual user's opt-in for the exact device and principal. The reference backend is not durable, restart-safe, cross-process linearizable or rollback-resistant; no production consent database, external monotonic anchor, authenticated ingestion service or endpoint sensor exists yet. See [the consent policy and production integration requirements](docs/COLLECTIVE-DEFENCE-CONSENT.md), [the durable consent authority design](docs/COLLECTIVE-DEFENCE-DURABLE-AUTHORITY.md) and [the event contract](docs/COLLECTIVE-DEFENCE-EVENTS.md).

This is not yet a live sensor, ingestion service, detection/correlation engine, or dashboard. Consent/revocation persistence and authenticated transport are not implemented. Threat-intelligence exchange does not grant remote access or remote execution; automated containment and remote execution remain disabled.

## Deployment boundary

Start with a trusted internal lab and explicitly enrolled test machines. Do not deploy to employee endpoints or production servers until identity, agent security, isolation, resource enforcement, incident response and independent security review are complete.

## Relationship to UJANI Public AI

[UJANI Public AI](https://github.com/asifshadab33/UJANI-PUBLIC-AI-) is the personal local-first AI project. Enterprise AI adds organisation-controlled fleet management and scheduling. Shared task/capability contracts should be versioned and reused; enterprise policy and fleet control remain separate.


## Inventory timestamp validation update

The read-only inventory contract now rejects heartbeat and telemetry timestamps more than 30 seconds in the future, and rejects telemetry timestamps that are materially newer than the associated device heartbeat. A small clock skew remains tolerated; stale records continue to fail closed. This is a policy-library validation only: it does not establish an authenticated live agent heartbeat or server-side clock synchronisation.


## Enterprise Intelligence Orchestration

UJANI's proposed shared coordination architecture is documented in [Enterprise Intelligence Orchestration Layer](docs/ENTERPRISE-INTELLIGENCE-ORCHESTRATION.md). This is an architecture proposal; the registry, connectors, event pipeline, workflow coordinator and unified dashboard remain implementation work. Provider-specific implementation status and safety gates are tracked in [Connector Integration Status](docs/CONNECTOR-INTEGRATION-STATUS.md).

## Legal and operational notice

Read [the legal and operational notice](docs/LEGAL-DISCLAIMER.md) together with the [GNU GPL v3.0 licence](LICENSE). The notice is informational and does not replace qualified legal review or applicable law.
