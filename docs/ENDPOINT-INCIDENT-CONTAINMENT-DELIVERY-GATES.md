# Endpoint Incident Containment — Enterprise Delivery Gates

**Status:** Delivery contract; not a claim that endpoint detection or production containment is implemented.
**Scope:** Coordinate customer-selected endpoint protection and approved device/lease policy.
**Default:** Opt-in, tenant-scoped, evidence-first; no remote execution or autonomous destructive response.

## Verified current boundary

The existing collective-defence event schema is a privacy-minimised read-only telemetry contract. Its documentation explicitly says it is not an endpoint sensor, ingestion API, antivirus engine, threat detector or response agent. The event store is a local storage primitive, not a network listener or authentication service. Device-trust and lease-control primitives provide useful authenticated policy foundations, but do not establish that an endpoint is uncompromised.

A valid device signature proves possession of an enrolled key for a request; it does not prove the operating system, sensor, event contents or device itself is trustworthy. Treat compromised sensors and stale/replayed/poisoned telemetry as expected threat cases.

## Incident lifecycle

Use an explicit tenant-scoped incident state machine:

- `observed`: one or more authenticated, provenance-tagged signals received.
- `triage`: deterministic rules and an authorised analyst review evidence and confidence.
- `suspected`: multiple or sufficiently strong indicators warrant investigation; not a confirmed compromise.
- `confirmed`: an authorised responder records the evidence and basis for confirmation.
- `containment_requested`: exact device and intended control are previewed for approval.
- `containment_approved`: authorised tenant role and required device-owner consent/policy checks have passed.
- `contained`: the receiving control plane confirms the specific action and records its result.
- `recovery`: device owner/admin follows remediation and verification steps using specialist endpoint tools.
- `reinstated`: trust is explicitly re-established after verification and required approvals.
- `closed`: evidence, decisions, outcomes and audit references are retained under tenant policy.

A single signal or AI-generated summary cannot move an incident directly to confirmed, contained or reinstated.

## Evidence and privacy requirements

1. Authenticate device identity and tenant using existing enrolled-device request signing and replay protection. Derive tenant and actor from trusted server context, not event payload claims.
2. Validate schema, source allowlists, timestamps, monotonic sequence, payload bounds, provider identity/version and freshness before storage.
3. Events are observations, not verdicts. Correlate independent evidence and record confidence, contradictions, source health and uncertainty.
4. Never ingest file contents, memory dumps, credentials, raw command lines, unrestricted process arguments or unrestricted file paths.
5. Treat hashes, domains, path fingerprints and device identifiers as sensitive linkable data. Minimise, encrypt, access-log and expire them.
6. A compromised device may hold a valid enrolled key. Support immediate suspension/revocation through an independently authorised control-plane path.
7. AI may summarise and prioritise; deterministic policy enforces authorization. Model output is never an action credential.

## Safe containment policy

The first response capability should be narrow and reversible:

- Suspend the device from new compute-workload admission.
- Stop lease renewal and revoke active UJANI resource leases through the authenticated control plane.
- Mark device trust as suspended/revoked according to the existing durable registry semantics.
- Notify the device owner and tenant security operator.
- Preserve a minimal, tamper-evident incident audit trail.

Do not claim that lease suspension isolates the operating system or stops malware. It only stops UJANI's own participation and workload allocation.

Network isolation, account/session revocation, process termination, file quarantine and firewall changes remain the responsibility of customer-selected specialist tools until separately integrated. Any future integration must use documented provider APIs, exact-target previews, scoped approval, receiver-side revalidation, idempotency keys, expiry, rollback/recovery, durable audit and independent security review.

## Delivery batches and acceptance

### INC-01 — Baseline and state model
- Map existing device trust, lease acquire/renew/release, owner opt-in, admin approval and event-store paths.
- Define incident identifiers, tenant scope, evidence references, state transitions and actor provenance.
- Add transition tests rejecting skipped, stale, cross-tenant and unauthorised transitions.
- Acceptance: documentation clearly distinguishes device trust from endpoint health.

### INC-02 — Authenticated event ingestion
- Build only on existing device-trust signed request and replay-protection primitives.
- Bind event batch digest, tenant/device, method/resource, timestamp, sequence and nonce.
- Add receiver-side authorization, rate/size limits, schema validation, idempotency, retention and tenant isolation tests.
- Acceptance: unauthenticated, replayed, revoked-device, tenant-substituted and malformed batches are rejected.

### INC-03 — Read-only endpoint/provider connectors
- Start with customer-selected Defender/EDR and supported network telemetry connectors.
- Use fixed documented endpoints, TLS verification, redirect rejection, bounded responses/timeouts and least-privilege credentials.
- Record provider identity/version, freshness and health; unknown/stale telemetry never becomes healthy.
- Acceptance: no connector can issue a response action.

### INC-04 — Incident correlation and operator review
- Correlate independent signals with explainable evidence and confidence.
- Defend against duplicate, replayed, contradictory and poisoned sensor reports.
- Add tenant-scoped RBAC, analyst notes and audit references.
- Acceptance: AI cannot confirm incidents or create approvals.

### INC-05 — UJANI compute containment
- Add a narrowly scoped, authenticated device suspension operation that blocks new leases and prevents renewals.
- Revoke active UJANI leases atomically where supported; preserve idempotent results and audit receipts.
- Require tenant administrator approval and apply individual owner consent policy; provide a break-glass process only if separately designed and audited.
- Acceptance: tests cover races with lease acquisition/renewal, stale approvals, replay, tenant crossing, partial failure and restart recovery.

### INC-06 — Recovery and re-enrolment
- Require external endpoint-provider remediation evidence and device-owner acknowledgement where appropriate.
- Rotate/re-enrol device keys through existing proof-of-possession flows; reject stale generations and replay.
- Restore workload participation only after authorised reapproval and a fresh health/trust evaluation.
- Acceptance: no automatic reinstatement after a timer or an AI recommendation.

### INC-07 — Independent validation
- Test with harmless EICAR only in an isolated provider-integration lab, synthetic ransomware-like file bursts, simulated credential misuse and malicious telemetry fixtures.
- Verify no cross-tenant leakage, no arbitrary remote execution, no autonomous destructive action and no hidden external data transfer.
- Conduct an independent penetration test before production containment is enabled.

## Non-negotiable release gates

- Collective Defence remains disabled by default and requires tenant administrator plus individual participant opt-in.
- No production endpoint sensor, authenticated ingestion service or containment feature may be claimed until deployed and tested.
- A device signature is not a clean bill of health.
- Lease suspension is not OS/network isolation.
- Remote execution, autonomous quarantine, firewall writes and arbitrary shell commands remain disabled.
- Any state-changing operation requires explicit authority, target binding, receiver-side revalidation, audit and tested recovery.
