# OS-First Capability Reuse for Enterprise AI

**Status:** approved architecture policy and implementation contract. This document does not claim a production agent, scheduler or live OS integration exists.

## Product objective

UJANI Enterprise AI should coordinate existing organisational compute and approved software instead of rebuilding operating-system facilities or installing a heavy parallel stack. Its role is to provide identity, policy, resource coordination, audit and safe workload admission. The operating system and customer-selected infrastructure should provide the underlying mechanisms wherever they are reliable and supportable.

The objective is not to keep every endpoint busy. Preserve interactive user experience, device-owner consent, energy efficiency, data locality and operational safety.

## Reuse-first decision rule

Before implementing a capability, record:
1. Whether the OS exposes a supported API or enforcement primitive.
2. Whether the organisation already operates an approved service or agent.
3. Whether an existing open-source component can be integrated safely.
4. What UJANI-specific policy or audit boundary is still missing.
5. Compatibility, deployment, maintenance, resource and security costs.
6. Why a new implementation is necessary if reuse is unsuitable.

Do not bundle a competing endpoint security product, full device-management suite, model-serving stack or monitoring platform merely to provide a control-plane checkbox.

## Responsibilities

| Capability | Reuse where possible | Enterprise must own |
|---|---|---|
| Device inventory | OS APIs and customer-approved management agents | Authenticated identity, provenance, freshness, consent and tenant scoping |
| CPU/RAM/GPU/NPU telemetry | Supported OS and vendor runtime APIs | Signature verification, conservative admission, stale/unknown handling |
| Resource enforcement | Windows Job Objects, Linux cgroups/namespaces, macOS-supported sandbox/process facilities | Policy, quota request, capability checks and evidence that enforcement is active |
| Model/runtime discovery | Existing installed runtime APIs, approved model registries and device reports | Allow-lists, capability evidence, model provenance and workload compatibility |
| Credentials | OS credential stores, TPM/Secure Enclave or customer KMS/HSM where available | Key lifecycle, rotation, revocation, access policy and audit |
| Networking | Existing customer network, firewall, VPN and identity infrastructure | Explicit destinations, workload egress policy and authenticated control-plane channels |
| Endpoint security | Customer-selected Microsoft Defender/Firewall or approved third-party tools | Optional integration, status provenance and policy mapping—not a replacement engine |
| Scheduling | Existing organisation scheduler where suitable | UJANI resource placement policy, consent, admission and auditable reservations |
| Notifications | Native OS notification services or existing IT service desk | Operator approval, delivery policy and sensitive-content minimisation |

OS facilities are mechanisms, not authorisation. Enterprise must not treat a process sandbox, container, firewall or device-management agent as a substitute for trust, signed workload approval, tenant isolation or audit.

## Model and workload compatibility

Use the shared versioned model/runtime inventory contract as a metadata boundary. Device reports are assertions from an authenticated enrolled device, not proof of physical hardware or model capability. Preserve evidence source, confidence and freshness. Unknown remains unknown.

Match a workload only when:
- required model/runtime and driver compatibility are supported;
- memory and compute headroom are sufficient;
- interactive activity, power, thermal and owner-pause signals permit participation;
- device trust, organisation approval and individual consent remain valid;
- data classification, locality and egress policy are satisfied;
- the workload has an approved isolation and resource-enforcement plan.

Do not automatically download models, start runtimes, wake devices, dispatch jobs or expose services merely because inventory reports a compatible model.

## Lightweight integration strategy

Prefer a read-only capability connector or an official customer-service link over a new always-on agent when that satisfies the operator need. Integrations should be optional, modular, lazy and independently versioned. An absent Defender, third-party firewall, Linux indexer, GPU runtime or customer scheduler must not prevent the control plane from starting.

For each connector, show:
- vendor/service and version;
- whether it is detected, connected, stale, unavailable or unknown;
- source and timestamp of the observation;
- exact data collected and permissions required;
- whether the integration is read-only or can request an action;
- customer ownership, support and failure behaviour.

Never scrape a private admin UI, collect user credentials, silently install software or assume a paid service subscription grants API access.

## Privacy and operational controls

- Collect only organisation-approved inventory and operational metadata.
- Never collect employee prompts, personal documents, browsing history or private application content for resource scheduling.
- Require administrator authorisation and device-owner opt-in for participation and inventory use.
- Honour pause and revocation; stop new collection and assignments when consent or trust is withdrawn.
- Do not use network reachability as proof of enrolment.
- All provider operations need bounded timeouts, cancellation and explicit failure states.
- Keep remote execution disabled until authenticated leases, transactional reservations, protected key lifecycle, receiver-side policy, OS-enforced isolation, audit, rollback and independent security review are complete.

## Performance and deployment budgets

- No continuous polling when the control plane is idle unless required by an approved heartbeat policy.
- Use event-driven or scheduled inventory refresh with bounded frequency and freshness labels.
- Do not wake sleeping devices just to improve inventory completeness.
- Reuse already-running customer agents and security services rather than duplicating them.
- Measure agent idle CPU/RAM, telemetry bytes, battery/energy impact, control-plane memory and per-device overhead.
- A connector that materially increases endpoint load or maintenance burden should be replaced by a link, read-only import or deferred integration.

## Acceptance criteria

- Inventory is authenticated, tenant-scoped, consented and provenance-labelled.
- Unknown/stale values never become available capacity.
- Missing optional customer software does not break the service.
- No prompts, private user files or credentials enter inventory or scheduler telemetry.
- Resource admission is fail-closed when isolation or enforcement cannot be verified.
- Tests cover unsupported OS/provider, stale telemetry, revocation, permission denial, timeout, partial inventory and conflicting policy.
- Remote execution remains disabled until all documented gates are proven.
