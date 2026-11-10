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
| Customer firewall (including OPNsense or other supported products) | Existing network policy enforcement point | OPNsense fixed-endpoint read-only posture probe prototype | Authenticated production host integration, real device/version validation, broader inventory; all mutation operations remain excluded |
| CISA KEV / NVD | External vulnerability intelligence | Fetch and cache public advisories with source, version and retrieval time | Feed scheduler, normalisation and asset matching |
| MISP / OpenCTI | Optional threat-intelligence exchange and knowledge systems | Read-only indicator/context lookup after customer selection | Live connectors, sync, write-back or feed publication |

No universal virtual-patching guarantee is made. A network control can only inspect or block traffic that actually traverses the enforcement point and is covered by a validated rule. Passive monitoring observes; it does not block. Neither approach repairs unsupported firmware or protects management-plane attacks, local access, bypass traffic or vulnerabilities outside the inspected protocols.



### Malcolm health adapter prototype

The current `main` contains `scripts/malcolm_readonly.py` and its regression tests. This is a read-only health-probe prototype for Malcolm's documented `GET /mapi/ping`, `GET /mapi/ready` and `GET /mapi/version` endpoints. It requires HTTPS by default, validates TLS certificates, rejects redirects, uses a five-second timeout and 1 MiB response bound, and can use optional Basic Auth credentials supplied through environment variables. It reports only allowlisted health/version metadata and does not query PCAP, session or document data.

Example:

```sh
MALCOLM_API_USERNAME='read-only-user' MALCOLM_API_PASSWORD='...' \
  python scripts/malcolm_readonly.py --base-url https://malcolm.example
```

Use a dedicated least-privilege account if the Malcolm deployment requires authentication. Do not disable TLS verification. For a private CA, supply `--ca-bundle /path/to/ca.pem`. HTTP is refused except an explicitly enabled loopback test endpoint. The script never follows redirects or sends credentials in the URL.

## First local import prototype

The current `main` contains `scripts/normalize_network_logs.py` and its regression tests. The importer reads local JSON-lines files and writes bounded, normalized evidence records. It supports Suricata EVE event types and Zeek JSON `conn`, `notice` and `weird` logs. It is an offline file-import tool, not a daemon, live network connector or SIEM replacement. Safe file opening currently requires the platform's `O_NOFOLLOW` and `O_NONBLOCK` flags; on platforms such as standard Windows Python builds where those primitives are unavailable, the importer deliberately fails closed and does not claim file-import support.

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

1. **Lightweight monitoring:** customer-managed Suricata and selected Zeek functions, with bounded local ingestion.
2. **Full monitoring:** a customer-managed Zeek and Suricata deployment with a bounded local event pipeline and searchable dashboards.
3. **Malcolm complete deployment:** an optional, independently installed Malcolm environment for organisations with sufficient compute, storage and operational capacity.

Read-only discovery is the default onboarding/visibility mode, not a deployment profile. Firewall integration is a separate optional connector choice: start with read-only visibility; any future change-capable connector must be separately installed, disabled by default, reviewed in a lab and guarded by target-bound preview, human approval, revalidation and tested rollback.

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


## Tenant-scoped searchable evidence store prototype (10 November 2026)

The branch `feat/tenant-scoped-security-event-store-2026-11` adds `scripts/security_event_store.py`, a local SQLite storage primitive for the normalized Suricata/Zeek evidence format and future read-only providers (Malcolm, OPNsense and MISP). It requires the caller to supply an explicit tenant scope, validates the provider and normalized event contract, rejects cross-tenant/provider records and implausibly future timestamps, applies bounded batch/page sizes, makes duplicate event IDs idempotent, and supports indexed tenant-scoped filters with keyset pagination. Retention and per-tenant record caps are configurable. The persistent database file is restricted to owner read/write permissions on platforms where chmod is supported.

Regression coverage is added in `tests/test_security_event_store.py` for tenant isolation, provider mismatch, idempotency, atomic batch rejection, filtering/pagination, retention and record caps. These are automated tests to be run by the existing Enterprise CI workflow; until a fresh workflow run passes, this is an implementation branch, not a validated release capability.

**Important boundary:** this module is not a live listener, authenticated connector transport, event broker, UI or durable multi-node service. Authentication and tenant selection must happen in a trusted host service before calling it. The initial store is a single-process/local SQLite prototype; production deployment still needs service identity, secret handling, concurrency/load testing, backup/recovery, retention governance and authenticated connector adapters. No live Malcolm, OPNsense or MISP API calls are implemented by this batch.


## Local live log-follow prototype (10 November 2026)

The stacked branch `feat/live-network-log-ingestion-2026-11` adds `scripts/live_network_log_ingest.py`. It follows a customer-selected local Zeek JSON `conn` log or Suricata EVE JSONL file and writes normalized records into the tenant-scoped SQLite store from the preceding evidence-store branch. It uses no-follow regular-file opening where supported, bounded line and batch sizes, an atomic owner-only cursor file, file identity checks for rotation, and at-least-once delivery. The database commit occurs before cursor advancement; a crash in between is handled by idempotent event IDs. It starts at the end of an existing file unless `--from-start` is explicitly selected.

Example (Zeek):

```sh
python -m scripts.live_network_log_ingest \
  --provider zeek --tenant-id tenant-a --input /var/log/zeek/current/conn.log \
  --database /var/lib/ujani/events.sqlite3 \
  --checkpoint /var/lib/ujani/cursors/zeek-conn.json --provider-version 7.0.0
```

Example (Suricata):

```sh
python -m scripts.live_network_log_ingest \
  --provider suricata --tenant-id tenant-a --input /var/log/suricata/eve.json \
  --database /var/lib/ujani/events.sqlite3 \
  --checkpoint /var/lib/ujani/cursors/suricata-eve.json --provider-version 7.0.0
```

This is a local single-process log follower, not a network listener, authenticated event receiver or production service manager. One process must own each cursor file. Deployment still requires a trusted service wrapper to authenticate and derive tenant scope, provision directories/permissions, supervise restarts and configure retention. The original follower supported Zeek `conn` records and Suricata EVE records. Draft PR #84 extends it to Zeek JSON `notice` and `weird` streams with distinct checkpoint scopes; this extension is not yet validated on all platforms. Log rotation across all platform variants, Windows file identity guarantees and real sensor-lab validation remain separate acceptance items. Existing unit tests exercise append, partial-line, rotation and tenant-bound cursor behavior; CI results must pass before treating this branch as validated.


CI note: PR #81 targets `main` so the repository's pull-request validation workflow applies to the combined store-and-follower change. The branch remains draft pending fresh CI and real-provider lab verification.


## Trusted-device signed ingestion authentication primitive (10 November 2026)

The branch `feat/trusted-device-ingest-auth-2026-11` adds `scripts/trusted_device_ingest_auth.py`, a reusable authentication gate for a future trusted-host receiver. It verifies a device ID against an operator-managed registry, validates an HMAC-SHA256 signature over the device ID, timestamp, nonce and exact request bytes, rejects requests outside a five-minute clock-skew window, and atomically consumes a per-device nonce in a local SQLite replay database. The tenant identifier is returned from the trusted registry; it is never accepted from the request body. Revoked and unknown devices fail closed. Request bodies are bounded to 256 KiB and replay storage is owner-only where filesystem permissions are supported.

The accompanying tests cover successful identity-to-tenant mapping, replay rejection, revocation, unknown devices, signature/body tampering, stale timestamps, undersized keys, body-size limits and symlink replay-database rejection.

**Not yet a production receiver:** this is a library primitive, not an HTTP server, device-enrollment/key-rotation workflow, protected key vault, certificate-backed identity service or OS service manager. The registry must be supplied by a protected operator-managed source. A future receiver must authenticate before parsing events, apply rate limits, bind authorization to the authenticated principal, and pass only the returned tenant scope into the evidence store. Do not expose a network endpoint or enable remote execution based on this module alone. Cross-platform filesystem hardening, key custody, concurrent multi-process replay tests, rotation/revocation workflow tests and customer-lab validation remain acceptance gates.


The branch also adds `scripts/trusted_network_event_ingest.py` as a library-only composition boundary between the signed device envelope and the existing tenant-scoped `SecurityEventStore`. It authenticates the exact raw request bytes before JSON parsing, derives tenant scope from the trusted device registry, takes provider identity from trusted host connector configuration, and overwrites any tenant/provider labels inside the event payload before storage. It does not open a socket or expose an HTTP listener. Regression tests verify authentication-before-parse and that payload-supplied tenant/provider values cannot redirect evidence into another tenant or provider partition. The receiver, registry lifecycle, key custody, rate limiting and customer deployment remain separate work.
