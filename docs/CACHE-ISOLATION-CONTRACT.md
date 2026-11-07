# Enterprise cache and activity-state contract v1

## Purpose

Reduce repeated work in fleet inventory, operator dashboards, policy evaluation and device discovery without allowing stale cache entries to become an authorization source.

This contract complements Public AI's local search cache design. The two products may share versioned metadata vocabulary, but never cache contents, credentials, encryption keys, user identities or permission decisions.

## Cache partitions

Every entry must be partitioned by all applicable dimensions:
- organisation/tenant ID;
- site or workspace ID;
- authenticated principal or service identity;
- device ID and enrollment generation for device-originated data;
- resource/scope ID;
- data classification;
- policy/schema version and provider version.

A cache key that omits a relevant partition dimension is invalid. Never use a global cache for tenant-owned inventory, activity or file metadata.

## Authorization on every lookup

1. Authenticate the current caller.
2. Resolve the authoritative tenant, role, site and device scope from the live identity/registry services.
3. Authorize the requested operation against current RBAC and policy.
4. Only then read the matching tenant-partitioned cache entry.
5. Validate its freshness, source generation and schema version.
6. If stale or invalid, refresh from an authenticated source or return an explicit stale/unavailable state.

Cached enrollment, role, consent, approval, lease or revocation status must never authorize access. Revocation and tenant/role changes invalidate affected entries immediately. Fail closed when the authoritative authorization source is unavailable.

## Placement

- **Agent-local cache:** bounded device inventory and local discovery metadata needed by that enrolled device. The device agent owns its local cache; operators cannot read personal paths or files through this cache.
- **Control-plane cache:** tenant-scoped fleet snapshots, device health summaries, workload status and dashboard aggregates sourced from authenticated agents and services.
- **Operator UI cache:** short-lived presentation state only. It must not retain bearer tokens or be treated as an authoritative record.

## Data minimisation

Cache only the minimum metadata required for the use case. Do not cache:
- passwords, tokens, private keys, recovery codes or session credentials;
- raw file contents, extracted document text, OCR, transcripts or embeddings;
- unrestricted process command lines or personal browsing activity;
- raw telemetry payloads where a bounded, classified summary is sufficient.

Any exception requires a separate data-classification, retention and security review. Encryption at rest must use keys from a protected key provider outside the cache directory.

## Freshness and invalidation

Each entry records source identity, source generation, schema version, creation time, expiry time and last successful validation time. Use bounded TTL and LRU/size limits. Invalidate on:
- device enrollment, de-enrollment, key rotation or revocation;
- tenant/site reassignment;
- principal role or permission change;
- owner consent or administrator approval change;
- policy, schema or agent-version change;
- stale heartbeat, source integrity failure or lease expiry;
- explicit administrator refresh or retention expiry.

A stale value may be displayed only with an explicit stale label and only when the caller is currently authorised to see it. It must never be used to dispatch work or renew a lease.

## Audit and observability

Record cache hit/miss, source generation, validation outcome, invalidation reason and access principal under the organisation's audit policy. Do not put secret values or raw private file names in cache telemetry. Audit reads of sensitive organisation-controlled metadata.

## Acceptance tests

- A principal from tenant A cannot retrieve tenant B cache entries, even with guessed IDs.
- Revoked devices, expired leases and de-enrolled agents cannot use cached state to pass authorization.
- Role/site/tenant changes invalidate old entries.
- Stale or schema-incompatible snapshots are refreshed or marked unavailable.
- Cache outage never weakens authorization or causes cross-tenant fallback.
- Concurrent refreshes cannot overwrite a newer source generation with an older one.
- Cache size and TTL limits are enforced.

## Delivery boundary

This document is a design contract. It does not claim that the repository currently has an authenticated multi-tenant control plane, a live agent, a cache service or an operator dashboard. Those require the trusted enrollment registry, protected key custody, authenticated transport and server-side RBAC tracked by the control-plane roadmap.
