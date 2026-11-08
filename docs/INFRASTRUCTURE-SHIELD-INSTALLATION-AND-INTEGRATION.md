# UJANI Infrastructure Shield: deployment profiles and integration boundary

**Status:** Proposed architecture decision; design only. No security engine, installer, firewall rule, Malcolm deployment, or production integration is implemented by this document.

## Decision summary

UJANI Enterprise AI should offer optional, independently deployable network-security profiles during installation and from the administration console later. UJANI is the orchestration, policy, explanation, and unified-UX layer. Third-party firewalls, sensors, packet-analysis engines, and monitoring stacks remain separate processes/services with their own lifecycle, licences, security updates, and failure domains.

The security profiles are optional. Installing or upgrading UJANI Enterprise AI must not silently install, enable, or reconfigure a third-party security engine.

## Customer deployment choices

The installer should present plain-language choices and a hardware compatibility estimate. It must permit a minimal UJANI-only installation and later profile changes.

| Profile | Components / role | Suitable for | Important boundary |
|---|---|---|---|
| Firewall integration | Connect to a supported existing firewall, or offer an explicitly selected compatible firewall backend as a separate install | Customers who need policy visibility and firewall administration | Firewall support is backend-specific. Do not claim a generic firewall can be installed on every OS or hardware platform. |
| Lightweight monitoring | Suricata IDS and selected Zeek functions, with local bounded event storage; firewall integration optional | Small deployments and constrained servers | Passive IDS alerts do not block traffic. Inline IPS requires a separately validated traffic path and explicit enablement. |
| Full monitoring | Zeek + Suricata, asset/event pipeline, searchable local dashboards and optional enrichment | Organisations needing deeper network visibility | Resource estimates must be measured; retention, capture, and indexing are configurable and bounded. |
| Malcolm complete deployment | Deploy or connect to an independently installed Malcolm environment using its documented interfaces | Customers with adequate compute, storage, and operational capacity | Malcolm is a separate third-party project and stack. UJANI must not fork, rebrand, or imply ownership/endorsement. UJANI integration is optional and version-checked. |

A profile may be expanded, reduced, or removed later. The installer should show detected resources, estimated resource requirements, network-interface prerequisites, storage/retention implications, update responsibilities, and any unsupported platform before installation. Do not auto-select the heaviest profile.

### Capability labels shown to customers

Every component and dashboard must distinguish:
- **Observe:** passive telemetry, alerts, inventory, and trends. No packet blocking.
- **Protect:** firewall/IPS enforcement on traffic that actually traverses the configured enforcement point.
- **Recommend:** UJANI explains risks and proposes changes; it does not apply them.
- **Approved action:** an administrator reviews the exact change, scope, impact, and rollback before execution.

Never describe passive monitoring as virtual patching. Virtual patching is a compensating control only for supported traffic paths and validated rules; it does not repair firmware or protect traffic that bypasses the enforcement point.

## Licence, distribution, and legal-risk policy

The product goal is to avoid taking on third-party redistribution and derivative-work obligations unnecessarily. This is a risk-reduction design, not a promise that UJANI or its users have zero legal obligations or liability.

1. **Keep UJANI-owned code separate.** The UJANI connector, profile catalogue, UI, policy model, and orchestration code should have a clearly declared UJANI licence and independent build/release lifecycle.
2. **Do not bundle third-party engines by default.** Do not copy, statically link, modify, repackage, or redistribute Suricata, Zeek, Malcolm, firewall distributions, rulesets, container images, or their dependencies in UJANI installers unless a documented legal review approves the exact version, licence, notices, source-offer obligations, trademarks, and distribution model.
3. **Prefer customer-managed installation or upstream packages.** Where technically supported, UJANI should detect and connect to a customer-installed component, or direct the customer to the official upstream installation route. Any automated installer must fetch from official sources, verify signatures/checksums where provided, display the source and licence, obtain explicit consent, and preserve upstream notices. This must not be treated as a blanket licence exemption.
4. **No hidden dependency.** The UJANI core must remain usable without any optional security component. Optional connectors communicate through documented APIs, sockets, or supported export formats. Avoid embedding or linking third-party engine code into UJANI binaries.
5. **Maintain a release-specific component register.** Record component name, exact version, source URL, licence identifier, copyright/notice location, whether it is bundled or customer-installed, connector method, known obligations, and review approval. Generate and publish an SBOM for every UJANI release and separately identify optional external components. Do not label a release licence-cleared until the inventory and notices are reviewed.
6. **Treat rules and feeds separately.** Suricata rules, threat feeds, vulnerability data, signatures, container images, and plugins can have terms different from the engine. Track their provenance, licence/terms, update channel, and redistribution rights independently.
7. **Avoid Nmap bundling** until its specific licensing and OEM/distribution conditions have been reviewed. Do not assume all open-source projects use permissive licences.
8. **Trademarks and presentation.** Use third-party names only to identify compatibility. State that projects are independent and not affiliated with or endorsed by UJANI. Follow each project's trademark and attribution requirements.
9. **Legal review is a release gate.** Obtain qualified legal review for the actual distribution model and jurisdictions before shipping installers or offering paid support. Customer installation does not eliminate UJANI's own obligations.

Suggested installer wording: “This optional integration uses independently maintained third-party software. It is not part of the UJANI core. Review the component's licence, notices, support policy, resource requirements, and update source before enabling it.” Provide links to the upstream project and exact version/licence information.

## UJANI orchestration and unified experience

UJANI should present one coherent console while preserving independent engines and trust boundaries.

### Connector contract

Define a versioned connector interface for each supported backend. At minimum it should expose:
- component identity, version, health, capabilities, licence/source metadata, and compatibility status;
- read-only asset, alert, event, health, and metrics queries with pagination and bounded time ranges;
- normalised events with source, timestamp, tenant/site, asset identity, severity, confidence, evidence reference, and schema version;
- configuration preview/diff, validation, and explicit capability declaration;
- action proposal, approval requirement, execution result, audit reference, and rollback capability where supported;
- connector heartbeat, timeout, circuit-breaker, and degraded/offline states.

Connectors must use least-privilege service identities, authenticated local IPC or authenticated network transport, strict input validation, bounded payloads, tenant scoping, and auditable access. Do not pass raw packet payloads to the language model by default.

### AI coordination

The AI layer should:
1. Read health and capability state from connectors.
2. Correlate selected security events with asset inventory, approved policy, vulnerability intelligence, and relevant UJANI enterprise context.
3. Explain what happened, why it matters, evidence and confidence, affected assets, known blind spots, and recommended next steps.
4. Generate a human-readable incident summary and a graphical timeline/topology view from structured data.
5. Propose a policy change only when the connected backend declares support and the action is within administrator policy.
6. Require explicit authorised human approval for firewall, IPS, segmentation, quarantine, or other disruptive changes.
7. Record approval, before/after configuration, result, and rollback reference in the audit trail.

AI must not sit in the packet-processing path or make per-packet decisions. Deterministic security engines perform real-time inspection and enforcement. AI is for prioritisation, explanation, correlation, and operator assistance. If the AI service is unavailable, monitoring and approved deterministic firewall policies must continue independently.

### Unified screens

The UJANI console should include:
- **Security overview:** profile selected, engine health, coverage status, last event, resource use, and deployment warnings.
- **Network map:** discovered assets and observed communication relationships, with source/time and confidence.
- **Assets and exposure:** vendor/model where known, observed services, firmware/support status where verified, matched CVEs/KEV entries, and confidence/unknown fields.
- **Alerts and incidents:** event timeline, affected assets, evidence, severity, rule/source, and investigation notes.
- **Protection centre:** observe/protect status, enforcement path, proposed controls, approval queue, active controls, and rollback state.
- **System and licence centre:** installed component versions, upstream source, licence/notice links, update status, SBOM/export, and resource usage.

Do not invent device firmware or vulnerability matches. Show unknown/ambiguous data as unknown and allow an administrator to correct inventory.

## Safety and operational controls

- Default to passive observation. No inline IPS, automatic blocking, quarantine, remote execution, or production firewall edits during initial installation.
- Inline mode requires explicit administrator enablement, a verified topology/traffic path, lab testing, a staged rollout, and a tested rollback/bypass plan.
- For OT/industrial networks, require a site-specific safety assessment. Fail-open versus fail-closed is an explicit operational decision; neither is universally safe.
- Changes must be previewed, scoped, approved by an authorised administrator, logged, and reversible where technically possible.
- A monitoring sensor failure must be visible. A monitoring failure must not silently change firewall policy.
- Clearly disclose coverage gaps: asymmetric routing, encrypted traffic, SPAN/TAP packet loss, traffic bypassing the gateway, unsupported protocols, and management-plane/local attacks.
- Retention, packet capture, sensitive-data handling, and any external threat-intelligence sharing must be configurable and privacy-minimised. No telemetry leaves the customer environment without explicit configuration and consent.

## Delivery sequence and acceptance criteria

This is a product direction, not a five-to-seven-day delivery promise. Work should be split into independently reviewable increments and can proceed in parallel where dependencies permit.

1. **Architecture and governance:** approve profile definitions, component register, licence review workflow, threat model, and connector schema.
2. **Read-only integration foundation:** implement connector discovery, health, version/capability reporting, event normalisation, and tenant-scoped read-only APIs.
3. **Console experience:** build profile selection/status, security overview, alerts, asset view, resource estimates, and licence/source transparency.
4. **Lab integrations:** validate one lightweight sensor path and Malcolm read-only integration against pinned versions; publish reproducible test setup and resource measurements.
5. **Approval workflow:** add preview/diff, approval, audit, and rollback contracts. Keep enforcement disabled until backend-specific tests and safety review pass.
6. **Release qualification:** licence/SBOM review, dependency vulnerability checks, installer/uninstaller tests, upgrade/downgrade tests, isolation tests, performance/resource tests, failure-mode tests, and documented support matrix.

Acceptance requires that UJANI remains functional with no security components installed; each profile can be installed/removed without corrupting UJANI; unsupported versions fail safely; connector loss is visible; no unauthorised enforcement action is possible; customer data remains tenant-scoped; and all third-party components, versions, sources, and licence information are disclosed.

## Current implementation status

This document records a proposed design only. The current Enterprise README describes the repository as early prototype/pre-alpha and does not claim a production fleet control plane, security sensor, monitoring dashboard, or enforcement service. No integration described here should be represented as implemented until code, tests, installer behaviour, and release evidence demonstrate it.

## Legal and customer deployment notice

This is a proposed technical design, not a customer contract, SLA, certification, warranty, security guarantee or professional advice. Deployment decisions, lawful monitoring authority, third-party licence compliance, safety assessment, testing, backups and approvals remain the responsibility of the deploying organisation. Read [the UJANI Enterprise AI legal and operational notice](LEGAL-DISCLAIMER.md) and the applicable [GPLv3 licence](../LICENSE). The notice is informational, does not create a managed-service commitment, and cannot exclude rights or liabilities that applicable law does not permit to be excluded.
