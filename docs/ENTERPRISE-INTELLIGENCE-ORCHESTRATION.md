# UJANI Enterprise Intelligence Orchestration Layer

**Status:** Proposed architecture and implementation contract. This document does not claim that the orchestration runtime, connectors, event pipeline, dashboard, or production control plane are implemented.

## 1. Product decision

UJANI Enterprise AI is the organisation's intelligent coordination and operating layer for independently developed tools, data sources, infrastructure and approved workflows. It is not a replacement for specialist products and is not merely an installer or a thin user-interface wrapper.

Specialist systems retain responsibility for their domain work. For example, a firewall enforces network policy; Suricata performs network IDS/IPS inspection; Zeek produces network telemetry; Malcolm provides a network traffic analysis environment. UJANI discovers and coordinates their supported capabilities, applies organisation policy, correlates evidence, explains results and presents a coherent operator experience.

The same orchestration foundation must be reusable outside cybersecurity: compute scheduling, document systems, search, storage, monitoring and other enterprise capabilities can be added through versioned adapters without hard-coding each vendor into the core.

## 2. Design principles

1. **Independent components:** providers remain separately installable, upgradeable and removable. UJANI must not silently bundle, enable or reconfigure them.
2. **Read-only first:** connector discovery, health, inventory and event retrieval precede any write or enforcement capability.
3. **Local-first and resource-aware:** prefer local processing and existing authorised resources when suitable; disclose external processing and obtain policy/consent before sending data out.
4. **Deterministic execution:** AI may interpret intent, plan, summarise and recommend. Deterministic adapters and specialist engines perform bounded operations. AI is never placed in a packet-by-packet safety or enforcement path.
5. **Policy before action:** permissions, tenant scope, data classification, quotas and approvals are checked by trusted application code, not by model output.
6. **Explainable provenance:** every material result identifies its provider, time, scope, freshness and supporting evidence.
7. **Graceful degradation:** a failed connector or unavailable model must not disable independent providers or silently widen permissions.
8. **No false readiness claims:** demo fixtures, prototypes and unverified connectors are visibly labelled.

## 3. Logical architecture

### A. User intent and experience layer
- Accept natural-language requests and structured workflows.
- Resolve the user's organisation, role, tenant, workspace and selected scope.
- Show one coherent task view with progress, provider status, evidence, confidence and next steps.
- Preserve expert drill-down links into each provider's native interface.
- Clearly distinguish **Observe**, **Explain**, **Recommend**, **Preview** and **Approved action**.

### B. Capability registry
Maintain a versioned registry of available capabilities, not just a static list of installed products. Each descriptor should include:
- stable capability ID and schema version;
- provider ID, provider version and adapter version;
- operation class: read-only, preview, or state-changing;
- typed input/output schema and bounded size/time limits;
- required permissions, roles and approval class;
- tenant and resource scope;
- data classification and egress requirements;
- locality, offline support and external-service dependencies;
- CPU, memory, storage and network budget estimates;
- health, freshness and compatibility state;
- provenance, licence and distribution source.

Registry entries are declarations, not proof of trust. The runtime must validate schemas, authenticate provider identity where supported and enforce the declared permission boundary.

### C. Connector adapter framework
- Use versioned, documented adapter contracts with explicit capability discovery and health checks.
- Keep provider credentials in a protected secret store; never place secrets in prompts, logs or connector descriptions.
- Start with read-only APIs, local sockets or customer-managed endpoints.
- Apply timeouts, response-size limits, rate limits, retries with backoff and circuit breakers.
- Treat all provider output as untrusted data; validate before normalisation or display.
- Isolate provider processes and dependencies where practical.
- Record provider-specific licence and redistribution obligations; do not bundle third-party software by default.

### D. Normalised event and evidence layer
- Convert supported provider output into versioned common envelopes while retaining the original provider event ID and a reference to raw evidence where retention policy permits.
- Include tenant, source, event time, ingestion time, schema version, asset identity confidence, severity, deduplication key and provenance.
- Enforce tenant isolation, bounded retention, replay/deduplication controls and clock-skew handling.
- Do not infer that missing data means a system is safe. Display unknown, stale and unavailable states explicitly.

### E. Correlation and workflow coordinator
- Build a typed task graph with declared dependencies, budgets, timeouts and cancellation.
- Route each step only to a registered capability compatible with the request and policy.
- Correlate observations deterministically where possible; use AI to explain and prioritise, not to invent evidence.
- Preserve per-step provenance and partial-failure state.
- Cache only where the data classification, tenant scope, freshness and user policy permit; key cache entries by tenant, identity/scope, provider, query and schema version.
- Prevent duplicate work through bounded idempotency keys and explicit freshness rules.

### F. Policy, identity and approval plane
- Authenticate users, services and connectors; apply tenant-scoped RBAC.
- Check operation permission, data classification, network egress, quotas and approval requirements before dispatch.
- For consequential changes, produce a human-readable preview containing exact target, change, expected effect, risk, rollback and expiry.
- Require an authorised human approval bound to the exact preview digest, target scope and policy version.
- Revalidate approval and target state at execution time; reject stale, replayed or broadened approvals.
- Emit tamper-evident audit records for decisions, approvals, execution outcomes and failures.

### G. Unified operator experience
Provide a single enterprise workspace with:
- capability/provider catalogue and health;
- asset and resource inventory with freshness indicators;
- unified search and evidence timeline;
- correlated incidents and risk explanations;
- workflow/task progress and partial failures;
- approval queue and change preview;
- audit, retention and export controls;
- provider-native deep links for advanced operations.

The interface must not conceal which provider produced a finding or imply that UJANI itself performed a specialist engine's inspection.

## 4. Security-domain example: Infrastructure Shield

Infrastructure Shield is one capability domain within Enterprise AI, not the definition of the entire orchestration platform.

- Firewall adapters expose supported inventory, policy status and read-only configuration first.
- Suricata adapters expose health, ruleset metadata and alerts; inline IPS is a separate, explicitly validated deployment mode.
- Zeek adapters expose protocol and connection observations; Zeek is not presented as a firewall.
- Malcolm remains an independent analysis stack; its resource needs and lifecycle are not hidden.
- Vulnerability intelligence is versioned and sourced. Findings must include affected asset evidence, matching confidence and source timestamps.
- Passive SPAN/TAP monitoring observes mirrored traffic and cannot block it. Virtual patching requires traffic to traverse a tested inline enforcement point and a validated rule for the relevant traffic.
- OT/industrial networks begin in passive mode. Any enforcement requires a lab, site-specific safety assessment, explicit approval, staged rollout and tested rollback/bypass plan.

No generic network control can guarantee protection for every firmware, management-plane, local, physical or out-of-path vulnerability.

## 5. Action safety model

| Stage | Meaning | Default |
|---|---|---|
| Observe | Read telemetry, status or inventory | Allowed only with connector read permission |
| Explain | Summarise evidence and uncertainty | Allowed; cite sources and freshness |
| Recommend | Suggest next steps | No state change |
| Preview | Calculate exact proposed change and rollback | No state change |
| Approved action | Execute a narrowly scoped change | Disabled until end-to-end controls are verified |

The first implementation milestone must not include remote command execution, autonomous firewall changes, endpoint containment or packet-path enforcement. These remain disabled until authenticated receiver-side authorisation, tenant isolation, replay protection, audit, rollback and independent security review are demonstrated.

## 6. Implementation sequence: smallest useful increments

### Milestone 1 — contract and registry
- Define JSON Schema contracts for capability descriptors, connector health, normalised evidence and workflow state.
- Add strict parsing, unknown-field rejection where appropriate, size limits and schema-version compatibility tests.
- Build a local in-process registry with synthetic fixtures only.
- Acceptance: invalid, oversized, stale-version and cross-tenant inputs are rejected; fixtures are visibly marked DEMO DATA.

### Milestone 2 — read-only connector SDK
- Define adapter lifecycle, health, capability discovery, cancellation and bounded request/response contracts.
- Implement one mock connector and one real read-only connector only after selecting a supported upstream API.
- Acceptance: timeout, malformed response, provider outage, credential failure and cancellation tests pass without affecting other connectors.

### Milestone 3 — evidence pipeline and search
- Add normalisation, provenance, deduplication, bounded retention and tenant-scoped cache keys.
- Acceptance: replay, duplicate, stale, clock-skew, retention and tenant-isolation regression tests pass.

### Milestone 4 — workflow coordinator and UI
- Add typed workflow plans, deterministic routing, progress, partial failure, explainable evidence and provider deep links.
- Acceptance: offline provider, unavailable model, conflicting observations and partial connector outage are handled clearly.

### Milestone 5 — approval-gated action framework
- Add preview digests, exact-scope approval, policy revalidation, rollback metadata and audit.
- Keep actual enforcement disabled until independent security review and integration tests pass.

### Milestone 6 — domain packs
- Add Infrastructure Shield connectors first, then compute, document/search and other enterprise integrations using the same contracts.
- Maintain separate compatibility, licensing and resource profiles for every provider.

## 7. Testing requirements

Every milestone must include:
- unit and property tests for schema and policy boundaries;
- integration tests with deterministic mock providers;
- malformed, oversized, replayed, stale and adversarial provider-output tests;
- tenant-isolation and IDOR tests;
- cancellation, timeout, retry and partial-outage tests;
- cache isolation, expiry and invalidation tests;
- audit/provenance completeness tests;
- resource-budget and bounded-retention tests;
- UI tests for unknown/stale/failed states and approval clarity;
- dependency, licence and SBOM checks.

Security-sensitive changes require threat-model updates and review. Production claims require reproducible evidence and independent assessment.

## 8. Open-source and legal governance

- UJANI source licensing and each third-party component licence are separate obligations.
- Maintain a release-specific SBOM, licence inventory, notices and source/provenance records.
- Do not redistribute a provider, signature feed, ruleset or database until its terms permit that use.
- Keep customer-managed installations as the default for heavyweight or separately licensed systems.
- Publish clear pre-alpha status, known limitations, supported versions, data-flow descriptions and security reporting instructions.
- No SLA, certification, security guarantee or fitness-for-purpose promise is created by this architecture document.

## 9. Explicit non-goals for the first release

- No universal connector compatibility claim.
- No automatic third-party installation or configuration.
- No AI-driven packet inspection or autonomous remediation.
- No remote execution or automatic containment.
- No assumption that all provider data is trustworthy, complete or current.
- No claim that orchestration alone makes the underlying tools secure or compliant.

## 10. Current implementation status

This document is an architecture proposal only. The existing Enterprise repository contains policy and storage prototypes, not this production orchestration runtime. Registry, adapters, event ingestion, correlation, workflow execution, unified dashboard and production approval service remain implementation work. Do not mark a milestone complete until code, automated tests and required review evidence are present.


## 10. Prototype implementation status (8 November 2026)

The current Enterprise policy crate contains an initial in-memory tenant-scoped capability registry and a versioned read-only connector/evidence contract. The registry validates descriptor bounds and tenant binding, tracks provider health separately, and exposes only healthy read-only/preview capabilities for routing. State-changing capability descriptors are rejected by default. The connector contract bounds request filters, pagination, evidence fields and cursors; validates tenant/provider provenance, duplicate record IDs and future timestamps; and labels stale evidence rather than presenting it as current.

A first offline file-import prototype is also present on the capability-registry feature branch: it normalizes allowlisted Suricata EVE JSON and Zeek JSON conn/notice/weird records into a versioned local evidence format. It is not a live connector.

These are policy, contract and offline-import prototypes only. They do not authenticate callers or providers, establish network connections, discover installed tools, store events durably, enforce timeouts in a host runtime, provide a dashboard, or invoke provider actions. See [Connector Integration Status](CONNECTOR-INTEGRATION-STATUS.md) for the planned Suricata, Zeek, Malcolm, firewall and vulnerability-intelligence integration sequence and explicit safety gates.
