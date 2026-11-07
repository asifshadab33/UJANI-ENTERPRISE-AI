# Fleet operator dashboard and network workflows (read-only first)

**Status: design contract / pre-alpha.** This document does not claim that a live agent, authenticated control plane, network discovery service, or dashboard is implemented.

## Purpose and operating boundary

The operator dashboard is for an authorised network operator managing organisation-owned or explicitly enrolled devices. It is not a personal-device surveillance tool. Inventory must arrive from authenticated, tenant-bound agents through the future control plane. The dashboard must never infer that a device is enrolled merely because it is reachable.

Do not add arbitrary remote shell, remote desktop, credential collection, packet interception, stealth monitoring, or unrestricted network scanning. Site and subnet grouping is based on administrator-provisioned inventory metadata or approved agent reports. Reachability checks, when eventually added, must be explicitly scoped, rate-limited, audited, and performed by an enrolled agent or approved service.

## Delivery sequence

1. **Trust foundation (P1, blocks live data):** complete issue #20. Establish administrator-created enrollment, explicit device-owner consent, tenant/site binding, device key custody, rotation/revocation, authenticated heartbeat and telemetry, and authenticated acquire/renew/release lease APIs. Protect the durable ledger with an injected trusted integrity key. Add replay, expiry, tenant-crossing, revoked-key and recovery tests.
2. **Dashboard shell with mock fixtures (safe to build in parallel):** implement navigation and responsive layouts using clearly marked synthetic data. Mock data must never be presented as live devices or real security alerts.
3. **Read-only live inventory:** after step 1, add a server API that returns only authenticated records. Enforce tenant/site/device RBAC server-side; filter again in the UI only for presentation. Display source, collection time, last heartbeat, trust and freshness for every record.
4. **Operator workflows:** health alerts, workload/lease views, audit search/export, maintenance windows, rollout rings and staged update status. All are read-only until a separate action API has receiver-side authorization.
5. **Narrow privileged controls:** only after threat review and receiver enforcement. Start with low-impact actions such as request fresh inventory or schedule a maintenance window. Drain/cordon, credential revocation, isolation and signed agent updates require step-up authentication, short-lived scoped approval, idempotency, expiry, cancellation, audit and dual approval where impact warrants it.

## Dashboard navigation

- **Overview:** enrolled/approved count; online, stale, offline and unknown count; heartbeat freshness; critical alerts; workload queue; last successful control-plane sync.
- **Device fleet:** searchable inventory; filters for tenant, site, platform, agent version, trust, freshness and power state. Device detail shows hardware/runtime inventory, capacity, telemetry provenance and policy version.
- **Sites & network:** administrator-defined sites, subnets and device groups. Show only approved topology metadata and authenticated agent-reported service health. Never silently scan arbitrary ranges.
- **Health & security:** stale heartbeat, low disk, memory pressure, thermal/power warnings, agent/version drift, policy mismatch, revoked/untrusted identity and failed update status. Alerts must show evidence and freshness.
- **Workloads:** queued/approved/running/completed/failed/expired state, manifest digest, assigned device, resource reservation, lease expiry and cancellation status. A dashboard row is not proof that a process actually ran.
- **Maintenance & updates:** maintenance calendar, drain/cordon requests, rollout rings, staged signed update status, rollback state and operator approvals.
- **Audit:** immutable or tamper-evident event history with actor, role, tenant/site/device scope, action, approval, request ID, timestamp, result and evidence references.
- **Policies & access:** tenant/site role assignments, policy versions, approval thresholds and session/MFA status.

## Required UI semantics

- Use **Unknown**, **Stale**, **Unverified**, **Revoked**, **Offline** and **Not reported** as distinct states. Missing data is never zero and a stale heartbeat is never "online".
- Show timestamps in the operator's chosen timezone and preserve UTC timestamps in API records.
- Show the telemetry source and collection timestamp beside each metric. Do not label inferred hardware or network details as verified.
- Synthetic fixtures carry a persistent "DEMO DATA" banner and cannot enable actions.
- A device is eligible for operational consideration only when it is enrolled, not revoked, owner-opted-in, administrator-approved, running, and has fresh authenticated telemetry. The existing policy validator is a local contract, not proof of live enrollment.
- Every action preview must show exact target scope, reason, expected impact, expiry and rollback/cancel path before approval.

## Read-only inventory response contract

Use `schemas/fleet-inventory-v1.schema.json`. The API must authenticate the caller and derive tenant scope from the server-side identity; it must not trust a tenant ID supplied by the browser. The response is a snapshot, not a live socket or command channel. Server-side RBAC and tenant isolation are mandatory even if the UI hides controls.

Suggested future routes (not implemented by this document):
- `GET /api/v1/fleet/summary`
- `GET /api/v1/fleet/devices`
- `GET /api/v1/fleet/devices/{device_id}`
- `GET /api/v1/fleet/sites`
- `GET /api/v1/fleet/alerts`
- `GET /api/v1/fleet/workloads`
- `GET /api/v1/audit/events`

No write/action endpoint should be exposed until issue #20 and receiver-side enforcement are independently verified.

## Acceptance criteria

- Mock mode is visibly synthetic and cannot call privileged APIs.
- Live inventory rejects invalid, stale, future-dated, revoked, unapproved or non-consenting device records.
- Every metric has provenance and freshness; missing values remain null/unknown.
- Tenant/site/device authorization is tested at the API boundary, including IDOR attempts.
- Audit search is scoped and exports redact secrets and credential material.
- UI tests cover empty, loading, error, stale, unknown, revoked, offline and large-fleet states.
- Accessibility: keyboard navigation, focus visibility, semantic tables, screen-reader status labels and responsive layouts.
