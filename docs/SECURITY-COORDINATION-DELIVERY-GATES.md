# Enterprise Security Coordination — delivery gates

**Status:** Implementation plan / acceptance contract  
**Date:** 10 November 2026  
**Scope:** UJANI Enterprise AI Security and Defence Coordination Centre

This plan turns the existing Enterprise Intelligence Orchestration and Collective Defence designs into small, testable delivery patches. It does not claim that a production security centre, authenticated connector service, endpoint sensor, incident correlation engine, or response automation already exists.

## Product boundary

UJANI is the organisation-controlled coordination layer. Specialist products remain responsible for their specialist functions:

- Firewalls enforce network policy.
- Antivirus/EPP/EDR products inspect and protect endpoints.
- Suricata and similar IDS/IPS tools inspect traffic according to their deployment mode.
- Zeek produces network observations and protocol metadata.
- Malcolm and comparable systems provide their own network-analysis capabilities.
- SIEM products remain systems of record where the customer has selected them.

UJANI may discover supported capabilities, collect explicitly authorised read-only evidence, preserve provenance, correlate observations, explain uncertainty, and present a controlled operator workflow. It must not claim to replace these engines.

## Non-negotiable safety rules

1. Read-only integration is the first release boundary.
2. Collective Defence remains off by default and requires separate tenant-administrator and individual-user opt-in.
3. A device signature is not proof that telemetry is truthful or that a human consented.
4. Tenant identity, user role, device identity and permissions are derived by a trusted host service, never from connector output or model text.
5. Every provider response is untrusted and must be bounded, validated and provenance-tagged.
6. Unknown, stale, unavailable and conflicting evidence remain visible as such; missing evidence never means safe.
7. AI may summarise and prioritise evidence. Deterministic policy and specialist providers decide/perform operations.
8. No remote command execution, autonomous containment, firewall writes, inline enforcement or endpoint policy changes in these patches.
9. Any future state-changing action requires exact-target preview, digest-bound approval, receiver-side revalidation, audit, rollback plan and independent security review.
10. No connector is silently installed, enabled, or granted broad credentials.

## Patch sequence and acceptance criteria

### Patch SEC-01 — Establish verified baseline
- Inventory existing contracts, scripts, schemas, tests and open pull requests.
- Record the exact default-branch state and exact-head CI/security results.
- Mark each capability as implemented, prototype, planned, or blocked.
- Do not merge an open PR solely because its feature is desirable.
- Acceptance: status matrix links to source and test evidence; no production claim is inferred from a branch or draft PR.

### Patch SEC-02 — Tenant-scoped event store
- Review the existing SQLite evidence-store prototype and its branch/PR lineage.
- Validate explicit tenant scope, provider identity, schema version, event provenance, timestamp bounds, idempotency, keyset pagination and retention.
- Add tests for cross-tenant reads/writes, duplicate IDs, atomic batch rejection, malformed and oversized events, retention boundaries, restart behaviour and concurrent access.
- Acceptance: all tests pass on the exact PR head; tenant selection is made by the trusted caller; storage is not described as a distributed production service.

### Patch SEC-03 — Bounded local ingestion
- Review the existing Suricata EVE and Zeek JSONL import/follow prototypes.
- Preserve safe no-follow file handling, file identity/rotation checks, bounded lines/batches, cursor atomicity and at-least-once/idempotent delivery.
- Ensure log contents cannot set tenant identity, principal, trust, severity verdict or response permission.
- Acceptance: malformed, oversized, rotated, truncated and symlink inputs fail safely; replay does not create duplicate evidence; ingestion remains local-only until authenticated transport is implemented.

### Patch SEC-04 — Read-only provider connectors
- Review OPNsense posture and MISP lookup prototypes; retain fixed endpoint allowlists, TLS verification, redirect rejection, bounded response/timeouts and least-privilege credentials.
- Add connector identity, provider/adapter versions, health/freshness, permission declaration and explicit data classification.
- Add contract tests for credential failures, provider outages, malformed responses, unexpected fields, pagination limits and cancellation.
- Acceptance: live integration is claimed only after a customer-controlled lab test against a documented provider version. No write endpoints are enabled.

### Patch SEC-05 — Authenticated host boundary
- Define the trusted host service that authenticates administrators, endpoints and connectors.
- Resolve tenant, principal, role and device identity from trusted identity sources.
- Enforce RBAC, tenant isolation, request size limits, rate limits, replay protection, timeouts and durable audit.
- Bind connector calls and evidence writes to authenticated context.
- Acceptance: IDOR/cross-tenant tests and authentication/revocation tests pass; caller-supplied tenant IDs cannot cross the trust boundary.

### Patch SEC-06 — Durable dual-consent authority
- Replace reference-only in-memory consent with a durable, restart-safe, tenant-scoped authority.
- Persist tenant and individual generations, consent notice digest/version, purpose, device/principal binding, expiry and revocation.
- Make revocation durable before acknowledgement and re-check consent at collection and outbound-queue boundaries.
- Define rollback-resistant generation storage and outage behaviour.
- Acceptance: restart, concurrent revocation, replay, rollback, stale permit and unavailable-store tests pass. Collection/transmission remains disabled until this gate passes.

### Patch SEC-07 — Normalised evidence pipeline
- Add provenance-preserving normalisation, deduplication, freshness handling, bounded retention and tenant-scoped query/cache semantics.
- Preserve source event IDs and references; do not fabricate missing fields or threat verdicts.
- Define severity as provider-supplied or explicitly derived by a deterministic, documented rule.
- Acceptance: source, timestamp, provider version, schema version and confidence/identity limitations are visible for every finding.

### Patch SEC-08 — Deterministic correlation and incident timeline
- Start with explainable deterministic rules over validated evidence.
- Link events only when asset identity and time-window evidence support the relationship.
- Store the rule/version and evidence IDs behind every correlation.
- AI-generated summaries must cite the underlying evidence and state uncertainty.
- Acceptance: duplicate, contradictory, stale and incomplete evidence tests pass; AI cannot create a new finding without source evidence.

### Patch SEC-09 — Read-only Security Centre UI
- Build provider catalogue, connector health, asset view, evidence search, incident timeline and audit view.
- Distinguish DEMO DATA, local prototype data and authenticated live data.
- Display stale/unknown/unavailable states and provider-native drill-down links.
- Keep action controls absent or visibly disabled.
- Acceptance: UI never implies that a provider is connected or a control is active when it is not; role and tenant scoping are tested.

### Patch SEC-10 — Approval and response design (no execution enablement)
- Define human-readable action previews with exact device/target, proposed change, reason, evidence, impact, expiry and rollback.
- Define approval bound to preview digest, actor, role, policy version and target scope.
- Define receiver-side revalidation, idempotency, audit and rollback result contracts.
- Keep actual firewall/EDR writes and containment disabled.
- Acceptance: negative tests prove stale, broadened, replayed, expired and wrong-target approvals are rejected.

### Patch SEC-11 — Independent security and lab validation
- Threat-model the host service, connectors, event pipeline, UI, identity and consent flows.
- Run dependency/SBOM checks, fuzz/property tests, tenant-isolation tests, concurrency tests and provider-specific integration tests.
- Test a lab topology with customer-selected tools; document unsupported versions and failure modes.
- Acceptance: independent review findings are triaged and critical/high issues resolved before any production pilot.

## Parallel workstreams

Work may proceed in parallel only where ownership and interfaces are stable:

- Workstream A: evidence storage, normalisation and local ingestion.
- Workstream B: read-only provider adapters and connector contracts.
- Workstream C: identity, tenant boundary, RBAC and durable consent.
- Workstream D: read-only operator UI using clearly labelled fixtures until authenticated APIs exist.
- Workstream E: test harness, threat model, SBOM and release evidence.

Do not parallelise competing edits to the same contract, schema or core policy module. Integrate through small reviewed PRs.

## Release labels

- **Available:** merged, tested, documented, compatible and included in a tagged release.
- **Preview:** implemented but limited; production suitability not established.
- **Prototype:** a bounded proof of concept, often local-only or in-memory.
- **Planned:** accepted design, not implemented.
- **Blocked:** a prerequisite or security gate remains open.

## Current hard stop

No employee-device deployment, production telemetry collection, remote workload dispatch, remote execution, autonomous containment, firewall modification, or inline enforcement until the relevant identity, consent, isolation, authorization, audit, rollback, lab and independent-review gates have passed.

## Related architecture and status documents

- `ROADMAP.md`
- `docs/ENTERPRISE-INTELLIGENCE-ORCHESTRATION.md`
- `docs/CONNECTOR-INTEGRATION-STATUS.md`
- `docs/COLLECTIVE-DEFENCE-CONSENT.md`
- `docs/COLLECTIVE-DEFENCE-EVENTS.md`
- `docs/OPERATOR-WORKFLOWS.md`
