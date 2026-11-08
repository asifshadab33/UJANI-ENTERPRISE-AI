# UJANI Enterprise AI — Security Centre UX and Connection Wizard Specification

**Status:** Proposed implementation specification  
**Product:** UJANI Enterprise AI  
**Default posture:** Customer-configured, opt-in, read-only, tenant-isolated  
**Purpose:** Provide a unified enterprise security experience across customer-selected endpoint, antivirus, firewall, EDR/XDR and network-monitoring products. UJANI coordinates existing engines; it does not replace them.

## 1. Product principles

1. **Customer-owned security stack:** the organisation chooses which vendors, devices, sites and data sources are connected.
2. **Least privilege:** read-only capabilities are separate from preview/action capabilities. This specification enables read-only only.
3. **Two levels of control:** organisation policy authorises the integration; device/user consent and OS permissions govern local collection where applicable.
4. **Tenant isolation:** every provider, device, observation, alert and audit record is tenant-bound and authenticated at the ingestion boundary.
5. **Transparent provenance:** preserve source product, source event ID, timestamps, connector version and evidence freshness.
6. **Lightweight orchestration:** reuse the Enterprise capability registry, connector contract, normalized evidence and policy/approval architecture. Do not build duplicate engines or a second plugin system.
7. **Human authority:** no automatic remediation, firewall changes, quarantine, remote execution or autonomous containment.

## 2. Enterprise navigation

Add **Security Centre** to the Enterprise application shell with these views:

- **Organisation overview:** posture summary, alert trends, provider health and coverage gaps.
- **Devices:** authorised device inventory and per-device security posture.
- **Alerts & investigations:** normalised provider alerts, filters, evidence and correlation.
- **Security providers:** connectors, sites, health, capabilities and permissions.
- **Policies & consent:** tenant policy, individual consent, data scopes and revocation.
- **Approvals:** future action review surface; show “No response actions enabled” until separately approved in a later release.
- **Audit:** provider connection changes, consent decisions, queries, exports and administrative actions.

Navigation visibility is role-based, but hiding a control is not authorization. The service must enforce every permission server-side.

## 3. Roles and permissions

Suggested role capabilities (map to the repository's actual RBAC model; do not invent a parallel identity system):
- **Security viewer:** view permitted posture and alerts.
- **Security analyst:** investigate and annotate evidence; no provider configuration.
- **Integration administrator:** configure connectors and scopes.
- **Organisation security administrator:** approve organisation-wide policies and data-sharing scope.
- **Auditor:** read audit and policy evidence without changing configuration.

Enforce tenant boundary, role, site/device scope, data classification and consent at every read. Individual opt-in cannot be overridden by a tenant-wide toggle for personal/device telemetry where individual consent is required.

## 4. Organisation overview

### Header
- “Security Centre”
- Organisation/site selector (only within authorised tenant scope)
- Overall posture with explicit coverage caveats
- “Connect provider” action visible only to authorised integration administrators

### Summary cards
1. Endpoint protection / antivirus
2. Firewall posture
3. Malware and spyware alerts
4. Ransomware protection signals
5. Network detections
6. Provider health and coverage

Show counts and trends only for the selected authorised scope. Avoid a single green organisation-wide score when coverage is incomplete, evidence is stale or sources conflict. Display “Coverage incomplete” and list missing/stale sources.

### Devices view
- Device identity from authenticated inventory, not arbitrary connector-supplied labels.
- Site/group, last seen, authorised status, connected providers and evidence freshness.
- Per-device posture and provider-reported alerts.
- Consent state and collection scope, visible only to roles permitted to see it.
- No remote command or remediation button.

Unknown/unmanaged devices are not silently treated as protected.

## 5. Enterprise provider connection wizard

Wizard is available only to an authorised integration administrator. Each connector setup is scoped to one tenant and, where appropriate, a site or device group.

### Step 1 — Choose integration type
Categories:
- Endpoint antivirus / EDR / XDR
- Host firewall
- Network firewall
- Malware / spyware / ransomware alert source
- Network IDS / monitoring
- SIEM / security analytics

Display supported read-only capabilities, deployment model, upstream vendor and current connector implementation status. Distinguish implemented, experimental and planned integrations.

### Step 2 — Discover and select provider/deployment
- Offer opt-in discovery of locally installed providers; show detected installations separately from the catalogue of supported adapters.
- Let the administrator select a discovered installation or manually select a supported provider when discovery is unavailable or not desired.
- Provider/product and version
- Local agent, on-premises API or vendor-hosted API
- Site/device group scope
- Required network reachability
- Data residency / region where applicable
- Licensing and deployment prerequisites

Do not silently install agents, engines or appliances. Never imply that a planned adapter is available.

### Step 3 — Authenticate and validate
- Use the provider's documented authentication mechanism.
- Prefer short-lived, least-privilege read-only credentials.
- Store secrets in an approved secret manager / OS credential store; never in source, configuration exports, URLs or logs.
- Verify TLS and hostname; no insecure TLS fallback.
- Validate tenant/provider identity and endpoint allowlist.
- Use bounded timeouts, response sizes, pagination and rate limits.
- Test only documented read-only health/status endpoints during setup.

### Step 4 — Select data scope
Show a field-level data catalogue:
- Device/provider health and protection state
- Signature/intelligence update status
- Scan summaries
- Alert metadata, severity, category and timestamps
- Firewall profile/health status
- Network metadata from selected IDS/SIEM sources

Default to the minimum fields required. Packet payloads, PCAP, file content, credentials, full command lines and personal data are excluded unless a separately reviewed feature and explicit policy authorise them. Do not infer that a provider's API supports a field until verified.

### Step 5 — Consent and policy review
Display:
- Tenant/site/device scope
- Data fields and classifications
- Retention period and storage region
- Whether individual consent is required and its current status
- Who can view the resulting information
- Query frequency, quotas and estimated resource use
- Revocation and deletion behaviour

Require explicit organisation administrator approval. Telemetry processing is local-only by default. Collection requires applicable individual consent where required. Sharing telemetry with the enterprise requires a separate, explicit individual opt-in; administrator approval does not replace that individual choice. Revoking collection consent stops the corresponding collection. Revoking enterprise-sharing consent stops sharing and returns any otherwise-authorised processing to local-only. If collection consent is absent or revoked, collection must not begin or must stop.

### Step 6 — Preview
Show a bounded sample with secrets and personal data redacted. Show source provenance, tenant mapping, normalisation outcome, event-time handling, deduplication key and expected data volume. Do not retain preview samples unless the administrator explicitly confirms the connection.

### Step 7 — Enable read-only connection
Explicit final confirmation. Start in read-only mode. No action-capable permissions are requested or stored. The connector enters a pending/health-check state, then Connected, Degraded, Permission needed or Failed.

### Step 8 — Review
Provide a connection receipt:
- Provider and connector version
- Tenant/site scope
- Granted read-only capabilities
- Data fields and retention
- Consent/policy references
- Health result and last successful check
- Disconnect/revoke control

## 6. Provider catalogue and implementation transparency

Provider catalogue entries must include:
- Provider ID and product family
- Platform/deployment support
- Adapter status: implemented, prototype, planned, unsupported
- Read-only capabilities currently available
- Required permissions and credential type
- Data fields, classification and retention
- Health/freshness semantics
- Rate/resource limits
- Upstream documentation and licence
- Last compatibility verification

Initial integration order:
1. Reuse current Enterprise capability registry and versioned read-only connector/evidence contract.
2. Windows endpoint posture via supported Windows Security Center / Defender / Windows Firewall interfaces, delivered through an authorised local device adapter.
3. Linux/macOS adapters only where documented interfaces are supported.
4. Existing security products such as Wazuh, Suricata, Zeek and Malcolm via separate optional read-only connectors, respecting each product's actual API and current implementation status.
5. Customer firewalls such as OPNsense through documented read-only endpoints before any write-capable scope is considered.

The existing offline Suricata/Zeek log importer and Malcolm health probe are prototypes, not live event streaming or full SIEM integrations. The UI must label them accurately.

## 7. Alerts, investigations and correlation

Alert table fields:
- Severity and category as reported by source
- Provider/product and connector
- Device/site and tenant scope
- Source event ID and normalised event ID
- Event time, ingestion time and freshness
- Evidence summary and permitted source reference
- Correlation status and explanation

Correlation is evidence linkage, not proof of causation. Preserve original provider severity and content separately from UJANI-derived priority or explanation. Handle duplicate, late, missing and conflicting events deterministically. Every AI-generated summary links to the evidence used and identifies uncertainty.

Do not expose cross-tenant data, even in aggregate, without a separately authorised and privacy-reviewed design.

## 8. Consent, audit and revocation

- Record organisation approval and individual consent as separate, versioned decisions.
- Use authenticated ingestion and tenant binding from trusted identity context, not a tenant ID trusted from unverified payload.
- Consent revocation stops future collection promptly and invalidates relevant connector leases/tokens.
- Define retention and deletion for already-ingested evidence; legal hold, if supported, must be explicit and auditable.
- Audit connector creation/update/pause/disconnect, scope changes, credential rotation, data access, export, consent changes and administrative decisions.
- Hash-linked audit records alone are not a substitute for durable storage, authenticated actors and an externally protected integrity anchor.
- Do not claim production-grade consent durability or fleet enforcement until those services are implemented and independently tested.

## 9. Performance, privacy and security constraints

- Reuse existing connector runtime and evidence contracts.
- Optional provider adapters run out-of-process or in isolated modules where practical.
- No bundled security engines, kernel drivers or duplicated detection pipelines.
- Event-driven ingestion where available; otherwise low-frequency polling with per-provider quotas and exponential backoff.
- Bounded request/response sizes, pagination, concurrency, CPU/memory budgets and cancellation.
- No AI in packet-processing or endpoint enforcement paths. Deterministic ingestion/correlation first; AI explanations on demand.
- Encrypt transport; protect secrets; enforce tenant-scoped authentication and authorization at service boundaries.
- Local/on-premises deployment options where provider and product support them.
- No packet payload or full endpoint content by default.

## 10. GUI states and operational semantics

Use explicit states: Healthy, Attention, Alert reported, Stale, Degraded, Unavailable, Unsupported, Not connected, Consent required and Unknown. Show the reason, timestamp and provider source. Incomplete coverage or stale sources must prevent a fully green posture.

For each connector show:
- Health and last successful poll/event
- Last error with safe redaction
- Data lag and ingestion volume
- Rate-limit/quota status
- Scope and consent status
- Pause, disconnect and rotate credentials controls (as permitted)

## 11. Acceptance criteria

1. Security Centre is integrated into existing Enterprise navigation and design system.
2. Tenant isolation and server-side RBAC apply to every API and query.
3. Connector wizard cannot enable a provider without authorised admin approval.
4. Individual consent gates are enforced where required; revocation stops collection.
5. Credentials are never exposed in UI logs, audit payloads or URLs.
6. Only read-only capabilities are enabled; no action tokens or write scopes are requested.
7. Provider status distinguishes implemented from prototype/planned integrations.
8. Stale, conflicting, missing and malformed evidence is shown accurately.
9. Tests cover tenant-crossing attempts, role denial, consent revocation, token expiry, replay/duplicate events, oversized responses, timeout, rate limits, stale data and audit provenance. Windows Security Center discovery, Defender status and Windows Firewall status require mocked contract tests plus supported Windows CI or manual host tests.
10. No new heavyweight core dependency or always-on AI inference is introduced.
11. Existing PR #48/#49 architecture and connector work is reused rather than duplicated.
12. Remote execution, inline IPS, firewall writes and autonomous containment remain disabled.

## 12. Out of scope

- Replacing antivirus, EDR, firewall, SIEM or network detection products.
- Silent installation or configuration of third-party products.
- Automatic quarantine, firewall changes, process termination or endpoint remediation.
- Remote execution, autonomous containment or unreviewed response actions.
- Claims of universal protection, complete ransomware/spyware detection or guaranteed remediation.

## 13. Delivery sequence

**Phase A:** Security Centre navigation, organisation overview, role-gated empty states, provider catalogue and connection wizard UX using mock connectors.  
**Phase B:** authenticated read-only connector lifecycle, tenant-bound ingestion, provider health and audit.  
**Phase C:** device inventory and supported endpoint/firewall/network integrations; consented collection.  
**Phase D:** alert triage, deterministic correlation and evidence-linked AI explanations.  
**Phase E:** independent security review before any separately scoped, preview/approval-based response feature. Such features remain disabled by default.
