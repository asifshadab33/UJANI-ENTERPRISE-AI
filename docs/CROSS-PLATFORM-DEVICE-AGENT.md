# UJANI Enterprise AI — cross-platform device-agent contract

Status: architecture contract for a future endpoint agent. This document does **not** declare Windows, Linux or macOS endpoint agents implemented, production-supported or physically verified. The current repository is a pre-alpha policy/control-plane prototype; cross-platform Rust CI validates the shared policy workspace, not a deployed agent or OS-enforced worker isolation.

## Design decision

Use one organisation-controlled control plane and one versioned, OS-neutral device protocol, with a small native adapter for each supported operating system. Do not build three independent Enterprise products or assume one generic binary provides identical OS capabilities everywhere.

The shared Rust policy and contract layer owns identity binding, consent, freshness, replay checks, resource accounting, workload policy and audit semantics. Platform adapters own OS-specific discovery, service lifecycle, protected-key integration and (only after separate release approval) isolation/enforcement mechanisms.

Public AI remains independently usable. Enterprise may consume versioned capability and task contracts from Public AI, but local Public AI use must not depend on an Enterprise control plane.

## Platform deployment profiles

| Area | Windows | Linux | macOS |
|---|---|---|---|
| Agent lifecycle | Windows Service / Service Control Manager | systemd where available; documented alternative for other init systems | launchd LaunchDaemon/LaunchAgent according to deployment scope |
| Resource discovery | Supported Windows system APIs and vendor runtime APIs | Kernel interfaces such as /proc and /sys, cgroups and vendor runtime APIs | Native system frameworks and vendor/runtime APIs; distinguish Apple Silicon from Intel |
| CPU and memory | Normalised CPU capacity and memory measurements, with OS reserve | Normalised CPU quota/headroom and memory measurements, including cgroup limits | Normalised CPU and memory measurements, accounting for OS pressure and process limits where available |
| GPU/NPU | Detect vendor, device, driver and usable runtime separately | Detect vendor, device, driver, permissions and usable runtime separately | Detect supported hardware/runtime combinations; do not assume discrete GPU or generic NPU access |
| Isolation candidates | Restricted tokens, Job Objects, AppContainer or separately managed VM/container boundary, selected by threat model | Namespaces, cgroups, seccomp and available LSM policy; container runtime only when configured and verified | Supported sandbox/entitlement and VM boundaries; validate current macOS APIs and avoid deprecated interfaces |
| Protected key candidates | Windows CNG/DPAPI and TPM-backed providers where available | OS secret service, TPM2 or PKCS#11 provider where deployed | Keychain and Secure Enclave-backed facilities where the required key operation is supported |
| Agent installation/update | Signed installer and service update/rollback procedure | Signed package/repository or customer-managed deployment, with rollback | Signed/notarised package and customer-managed deployment, with rollback |

These are integration candidates, not promises that every facility exists on every edition, hardware model, distribution or customer configuration. The agent must report capability availability and failure explicitly; it must never silently downgrade to weaker isolation or key custody.


## Modular packaging and optional platform integration

Cross-platform support must not make every Enterprise installation carry or install every operating-system integration. The control plane and endpoint agent are separate deployment roles. Platform-specific adapters are optional, separately versioned packages, selected by the organisation.

### Installation choices

The organisation administrator chooses one of three explicit modes during deployment:

1. **Core only:** install the control plane/operator components or the minimal shared endpoint bootstrap, as applicable. Do not install platform adapters, hardware SDKs, model runtimes or optional isolation backends.
2. **Select packages:** choose Windows, Linux and/or macOS agent packages. The installer presents package purpose, download size, dependencies, supported OS/architecture, privileges, service behaviour and update channel before installation.
3. **Discover and offer:** the installer may detect the host OS and architecture and preselect the matching signed package, but it must show the selection and obtain administrator confirmation. It must not silently download or install other platform packages. Fleet deployment tools may explicitly enable unattended installation under organisation policy.

A small bootstrap/installer may retrieve the selected package on demand from an organisation-approved source. Alternatively, administrators can download packages separately and provide them through an offline repository, internal mirror, MDM or software-distribution system. Network retrieval is never mandatory for offline or restricted environments.

### Package boundaries

- The **control-plane package** contains service/API, policy, database integration and operator UI dependencies. It does not bundle endpoint-specific native agents.
- The **shared endpoint core** contains the versioned protocol client, device identity integration points, consent UX/state handling, policy evaluation needed locally and bounded telemetry transport. Keep it small and transport/protocol compatible.
- Each **platform adapter package** contains only that OS's discovery and service-lifecycle implementation, plus its declared dependencies. A Windows-only fleet need not download Linux or macOS adapters.
- **Capability extensions** (GPU/NPU vendor integrations, optional runtime detectors and isolation backends) are separate opt-in packages. Do not bundle large vendor SDKs or model runtimes into the base agent.
- Model weights and model downloads are not part of Enterprise agent installation. Model installation remains an explicit device-owner action subject to organisation policy.

Where technically practical, the installer should support a shared signed package manifest and a thin OS-specific installer. The manifest records package ID, semantic version, protocol compatibility range, supported OS releases and architectures, dependency constraints, size, publisher/signing identity, cryptographic digest, release channel and revocation status. The package manager verifies signature and digest before installation and rejects incompatible or revoked packages. A digest alone is not publisher authentication.

### Fleet rollout, updates and removal

- Administrators may deploy only the platform package matching an enrolled endpoint's OS/architecture. A homogeneous fleet receives one platform package; a mixed fleet receives only the packages represented in its approved inventory.
- Do not install an adapter on a device merely because the control plane can see that OS family in the organisation. Enrollment, administrator policy and endpoint-owner consent remain separate gates.
- Package installation, service enablement, upgrades, rollback and removal must be explicit, auditable and reversible. Never change firewall rules or enable remote execution as an installer side effect.
- Use signed, versioned releases, staged rollout rings, compatibility checks, health checks and rollback to the last known-good package. Do not auto-upgrade across a protocol-breaking boundary.
- Support administrator-managed update windows, pinned versions, offline mirrors and package revocation. Report update status and failure without collecting unrelated endpoint activity.
- Uninstalling or disabling an agent must stop participation, revoke or invalidate its device credentials through the authenticated lifecycle, release/reconcile outstanding reservations and leases server-side, and preserve required audit records under retention policy.
- A missing or failed optional extension must reduce reported capability to unavailable/unknown; it must not prevent the base OS or local Public AI runtime from working.

This packaging model keeps the default installation small, avoids shipping irrelevant OS dependencies, and lets an organisation opt into only the platform integrations it actually operates. The package boundary does not weaken shared authentication, consent, replay protection, admission or release gates.

## Common device protocol

Every platform adapter emits the same bounded, versioned inventory and telemetry contracts. Platform-specific detail belongs in explicitly versioned capability extensions, not ambiguous free-form strings.

Minimum device envelope:

- Stable enrolled device identity and tenant binding from authenticated enrollment, not guessed from hostname or MAC address.
- OS family, release/build, architecture and agent version.
- Schema version, monotonic device generation and sequence, sample timestamp, server receipt timestamp and evidence freshness.
- CPU topology/capacity, effective quota and available headroom.
- Memory total/available/reserved and applicable OS/container limits.
- Storage capacity only where needed for a declared workload; do not enumerate user files or paths.
- GPU/NPU vendor, device family, driver/runtime versions, usable memory and supported execution capabilities, distinguishing detected hardware from verified usable capability.
- Installed runtime identifiers and versions, model identifiers/versions, bounded capability declarations and resource requirements, with provenance and freshness.
- Owner participation state, administrator approval state, power/thermal/interactive-use state and explicit unknown values where unavailable.

The agent reports only operational metadata needed for resource eligibility. It must not collect prompts, model weights or contents, personal files, browsing history, keystrokes, screen contents or unrelated employee activity.

## Capability and admission semantics

Hardware or runtime presence is not proof that a workload can run. Preserve separate states such as `detected`, `available`, `verified`, `unsupported`, `stale` and `unknown`. Unknown or stale evidence cannot satisfy a hard workload requirement.

A candidate device is eligible only when all conditions are true at the authoritative service boundary:

1. The device is enrolled, authenticated, current and not revoked.
2. Organisation policy explicitly approves the device/workload class.
3. The device owner has independently opted in for the current device identity and consent generation.
4. Telemetry generation/sequence is monotonic and fresh; replayed, future-dated, stale or superseded evidence is rejected.
5. Verified runtime/model capabilities and resource headroom meet task requirements.
6. Power, thermal, interactive-use, network/data-locality and quota policies permit participation.
7. Reservation and lease capacity are committed atomically by the single production authority.

The operator may see eligible capability/resource metadata and set permitted model families/workload policies. The operator must not silently replace a user's local model choice or inspect private prompts. Fleet-wide RAM is not pooled memory for one model.

## Key custody and trust

Use a provider boundary with deployment-appropriate protected custody. Windows, Linux and macOS adapters may use native protected stores when they meet documented key-purpose, access-control, backup and recovery requirements. Organisations may instead supply an approved KMS/HSM/TPM or PKCS#11-backed provider.

Do not create a UJANI-generated trust root or store production keys beside writable application state. A local HMAC/checksum or encrypted file does not independently prevent rollback. Critical trust and lease state needs a separately protected, linearizable monotonic anchor or equivalent externally enforced anti-rollback control. If a platform lacks an acceptable provider, protected operations remain unavailable and admission fails closed.

## Service and privacy boundaries

- The endpoint agent runs with least privilege; discovery must not require administrator/root privileges unless a specific documented capability requires them.
- Discovery is bounded, cancellable and rate-limited. A failed sensor produces explicit unknown/unavailable data, not a fabricated zero or stale value presented as current.
- No agent runs shell commands or downloads models merely because a server requests them.
- No remote execution, worker dispatch, autonomous firewall changes or containment actions are enabled by this contract.
- Owner pause/withdrawal and administrator revocation must be honoured before every future admission; cached eligibility is never authority.
- Transport uses authenticated TLS and device-bound request signatures with bounded request bodies, strict timeouts and replay protection.
- Server-side tenant identity and policy remain authoritative. A device-supplied tenant, role, approval or trust label is never accepted as authority.

## Verification required for each supported platform

A platform is not release-supported merely because shared Rust code compiles on it. Before enabling an endpoint agent on a platform, provide:

- Native build and signed installer/package on declared minimum OS versions and architectures.
- Physical-device tests for CPU, memory, storage, power, thermal, sleep/wake and interactive-use reporting.
- Hardware-specific GPU/NPU and runtime discovery tests, including absent drivers and unsupported devices.
- Protected key-provider tests for provisioning, access control, rotation, revocation, backup, restore and device replacement.
- Service start/stop, upgrade/rollback, crash restart, network loss, cancellation and uninstall tests.
- Negative tests for forged identity, replay, stale/future telemetry, owner withdrawal, administrator revocation, cross-tenant access and capacity races.
- Isolation and resource-limit tests against the exact supported OS release and configured enforcement backend, independently reviewed for the intended workload class.
- Evidence that telemetry excludes prompts, personal files, secrets and unnecessary user activity.

CI should test shared policy/protocol code on Windows, Linux and macOS, and separately test each native adapter. Fixture tests in CI must never be labelled physical-device verification.

## Rollout strategy

1. Keep shared protocol and policy library transport-independent.
2. Implement read-only, least-privilege discovery adapters one platform at a time, starting with platforms available for physical testing.
3. Add authenticated telemetry ingestion and freshness/replay enforcement at the service boundary.
4. Validate device-owner consent, administrator approval, reservations and lease recovery end to end.
5. Prove protected key custody and OS-enforced isolation on each declared platform.
6. Only then consider a tightly scoped, opt-in lab workload pilot. Remote execution remains disabled until every release gate in [RELEASE-GATES.md](RELEASE-GATES.md) and [ARCHITECTURE.md](ARCHITECTURE.md) is independently satisfied.

A customer may deploy the control plane centrally while enrolling only selected endpoint platforms. Unsupported endpoints remain visible as unsupported or un-enrolled; they are never silently treated as schedulable resources.


## Production authority reference

The accepted production persistence and admission boundary is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md#production-authority-and-admission-boundary). This platform contract does not create a separate authority or service implementation.
