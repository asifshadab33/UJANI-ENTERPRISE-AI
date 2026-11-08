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
| Suricata | IDS/IPS alert and rule telemetry; optional separately approved enforcement provider | Local EVE JSONL import prototype with an explicit field allowlist | Live service/API adapter, health polling, rule management, inline IPS, virtual-patch deployment |
| Zeek | Network metadata, protocol observations and notices | Local JSON log import prototype for conn, notice and weird streams | Live adapter, health polling, TSV parser, event store |
| Malcolm | Optional higher-capability network-analysis deployment using its own specialist stack | Read-only health adapter prototype using documented GET ping/ready/version endpoints | Event/document search adapter, deployment automation, indexing or PCAP pipeline |
| Customer firewall (including OPNsense or other supported products) | Existing network policy enforcement point | Read-only inventory, configuration posture and status where supported | Any configuration change, policy push, restart or rule deployment |
| CISA KEV / NVD | External vulnerability intelligence | Fetch and cache public advisories with source, version and retrieval time | Feed scheduler, normalisation and asset matching |
| MISP / OpenCTI | Optional threat-intelligence exchange and knowledge systems | Read-only indicator/context lookup after customer selection | Live connectors, sync, write-back or feed publication |

No universal virtual-patching guarantee is made. A network control can only inspect or block traffic that actually traverses the enforcement point and is covered by a validated rule. Passive monitoring observes; it does not block. Neither approach repairs unsupported firmware or protects management-plane attacks, local access, bypass traffic or vulnerabilities outside the inspected protocols.



### Malcolm health adapter prototype

The current feature branch adds `scripts/malcolm_readonly.py`, a read-only health probe for Malcolm's documented `GET /mapi/ping`, `GET /mapi/ready` and `GET /mapi/version` endpoints. It requires HTTPS by default, validates TLS certificates, rejects redirects, uses a five-second timeout and 1 MiB response bound, and can use optional Basic Auth credentials supplied through environment variables. It reports only allowlisted health/version metadata and does not query PCAP, session or document data.

Example:

```sh
MALCOLM_API_USERNAME='read-only-user' MALCOLM_API_PASSWORD='...' \
  python scripts/malcolm_readonly.py --base-url https://malcolm.example
```

Use a dedicated least-privilege account if the Malcolm deployment requires authentication. Do not disable TLS verification. For a private CA, supply `--ca-bundle /path/to/ca.pem`. HTTP is refused except an explicitly enabled loopback test endpoint. The script never follows redirects or sends credentials in the URL.

## First local import prototype

The current feature branch adds `scripts/normalize_network_logs.py`. It reads local JSON-lines files and writes bounded, normalized evidence records. It supports Suricata EVE event types and Zeek JSON `conn`, `notice` and `weird` logs. It is an offline file-import tool, not a daemon, live network connector or SIEM replacement.

Example:

```sh
python scripts/normalize_network_logs.py \
  --provider suricata --tenant-id tenant-a \
  --provider-version 7.0.0 --input /var/log/suricata/eve.json \
  --output ./suricata-normalized.jsonl

python scripts/normalize_network_logs.py \
  --provider zeek --zeek-log-kind conn --tenant-id tenant-a \
  --provider-version 7.0.0 --input ./conn.log \
  --output ./zeek-normalized.jsonl
```

The importer rejects symlink inputs, oversized files/lines/record counts, duplicate JSON keys, invalid timestamps and unsafe output-overwrite paths. It emits only selected metadata fields; packet payloads, credentials and arbitrary application content are not copied. The normalizer does not assign a threat verdict. Every imported record is marked `internal`, and downstream host policy must still enforce tenant, role, retention and freshness requirements.

Official provider format/API references:
- [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) and [EVE JSON format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- [Zeek logging framework](https://docs.zeek.org/en/lts/frameworks/logging.html) and [Zeek JSON logs quickstart](https://github.com/zeek/zeek-docs/blob/master/quickstart.rst)
- [Malcolm REST API overview](https://malcolm.fyi/docs/api.html), [ping](https://malcolm.fyi/docs/api-ping.html), [readiness](https://malcolm.fyi/docs/api-ready.html) and [version](https://malcolm.fyi/docs/api-version.html)
- [OPNsense API reference](https://docs.opnsense.org/development/api.html) and [firewall API](https://docs.opnsense.org/development/api/core/firewall.html)

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
