# UJANI Enterprise connector integration status

**Status date:** 8 November 2026  
**Overall project status:** pre-alpha. The entries below are integration targets and staged design decisions, not claims that live adapters or production deployments exist.

## Shared integration rule

Every external solution is an independent provider. UJANI Enterprise owns orchestration, policy, evidence provenance, operator experience and approvals. The provider remains responsible for its specialist function. UJANI must not silently install, bundle, reconfigure, or replace it.

The first adapter release is read-only. Each adapter must declare its provider and adapter versions, capability IDs, permissions, data classification, egress behaviour, resource limits, timeout, health and supported contract versions. All returned evidence is untrusted until bounded and validated. Tenant scope and user permissions are enforced by the Enterprise host, not by a model or an adapter's self-description.

The initial Rust prototype now contains:
- a tenant-scoped in-memory capability metadata registry with provider-health gating and default rejection of state-changing capabilities; and
- a versioned read-only connector/evidence contract with bounded pagination and fields, tenant/provider checks, duplicate-ID rejection, clock-skew validation and explicit stale-evidence status.

These are policy/contract primitives. They do not yet provide connector discovery, authentication, network transport, durable event storage, a UI, or live integrations.

## Security and Infrastructure Shield integration targets

| Provider / solution | Intended UJANI role | First integration | Not implemented yet |
|---|---|---|---|
| Suricata | IDS/IPS alert and rule telemetry; optional separately approved enforcement provider | Read-only alert/event ingestion and health | Live adapter, rule management, inline IPS, virtual-patch deployment |
| Zeek | Network metadata, protocol observations and notices | Read-only logs/events and health | Live adapter, parsing pipeline, event store |
| Malcolm | Optional higher-capability network-analysis deployment using its own specialist stack | Read-only status and evidence links; avoid duplicating its engines | Deployment automation, API adapter, indexing or PCAP pipeline |
| Customer firewall (including OPNsense or other supported products) | Existing network policy enforcement point | Read-only inventory, configuration posture and status where supported | Any configuration change, policy push, restart or rule deployment |
| CISA KEV / NVD | External vulnerability intelligence | Fetch and cache public advisories with source, version and retrieval time | Feed scheduler, normalisation and asset matching |
| MISP / OpenCTI | Optional threat-intelligence exchange and knowledge systems | Read-only indicator/context lookup after customer selection | Live connectors, sync, write-back or feed publication |

No universal virtual-patching guarantee is made. A network control can only inspect or block traffic that actually traverses the enforcement point and is covered by a validated rule. Passive monitoring observes; it does not block. Neither approach repairs unsupported firmware or protects management-plane attacks, local access, bypass traffic or vulnerabilities outside the inspected protocols.

## Deployment profiles

1. **Read-only discovery:** inventory, connector health and configuration/evidence views. No inline traffic inspection is implied.
2. **Lightweight monitoring:** customer-managed Suricata and/or Zeek deployments with bounded local ingestion.
3. **Full network analysis:** optional customer-managed Malcolm deployment for organisations that have the compute and storage to operate it.
4. **Firewall integration:** read-only visibility first. Any future change-capable connector must be separately installed, disabled by default, reviewed in a lab and guarded by a target-bound preview, human approval, revalidation and tested rollback.

Profiles are choices, not bundled installers. Customer admins decide which components are installed and where data is stored.

## OT and safety boundary

For industrial/OT environments, start with passive observation and an approved asset/protocol baseline. Do not place AI or a cloud dependency in the packet path. Test parsers, detections and any enforcement rule against representative traffic in an isolated lab. Require operational-owner approval, maintenance windows, documented rollback and a site-specific fail-open/fail-closed decision before any inline deployment. UJANI must not autonomously change PLC, switch, router or firewall configurations.

## Acceptance gates for each real adapter

- Upstream API and licence review; component/SBOM entry and source attribution.
- Threat model, authentication method, secret handling and tenant-isolation tests.
- Schema-version compatibility and malformed/oversized response tests.
- Timeout, cancellation, rate-limit, retry and circuit-breaker tests.
- Provenance, freshness, deduplication, clock-skew and bounded-retention tests.
- Read-only permissions demonstrated at the provider boundary.
- Graceful degradation when provider or AI is unavailable.
- Human acceptance test using a customer-controlled lab instance.

## Explicitly deferred

No remote execution, employee-device workload dispatch, autonomous containment, firewall modification, inline IPS enablement, automatic rule installation, or autonomous OT action is enabled by this integration plan. Such work remains blocked on production identity, protected key custody, authenticated receiver-side authorization, tenant isolation, OS-enforced isolation where applicable, exact-scope approval, replay protection, rollback, independent security review and operational sign-off.
