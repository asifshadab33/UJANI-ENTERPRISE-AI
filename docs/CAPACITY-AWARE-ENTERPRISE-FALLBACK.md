# Capacity-aware scheduling and external fallback — UJANI Enterprise AI

**Status:** Requirements and implementation contract. This document does not claim a live fleet dashboard, capacity forecaster, cloud-routing service or production dispatch gateway.

## Objective

Use suitable local and organisation-authorised compute first. If all eligible devices are busy, unavailable, incompatible or short of CPU/RAM/accelerator memory, UJANI must explain the shortfall and request the appropriate approval before using an organisation-approved external AI service.

The decision is workload-specific. There is no fixed local/cloud percentage.

## Capacity model and dashboard

The operator view must distinguish:

- **Registered:** enrolled in the organisation's inventory.
- **Trusted:** identity, tenant binding and revocation state verified.
- **Owner opted-in:** current individual/device participation permission is valid.
- **Online:** authenticated heartbeat is recent enough for the policy.
- **Available:** currently passes policy, schedule, interactive-use, power, thermal, resource and workload-class checks.
- **Reserved / busy:** capacity already committed to active leases or local user work.
- **Ineligible:** a clear rejection reason such as stale telemetry, insufficient memory, unsupported accelerator/runtime, policy denial, owner opt-out or tenant mismatch.

For each task show requested CPU, memory, accelerator/runtime capability, data classification, time budget and workload class. For each device show fresh available capacity after OS reserve and existing reservations, with telemetry timestamp and provenance. Never count installed RAM as free RAM or double-count resources already reserved by active leases.

Use the existing policy crate's plan_local_first_placement as a dry-run admission foundation: it validates a manifest and policy-backed candidates, returns eligible/rejected devices and deliberately does not start execution or reserve resources. Extend rather than duplicate this planner when implementation proceeds. Its inputs must be authenticated and fresh; the planner's current result is not proof of a live fleet or scheduler.

## Routing sequence

1. **Local deterministic tools / local model:** use the requesting workstation when it has sufficient safe headroom and a compatible runtime.
2. **Trusted enterprise pool:** evaluate only enrolled, non-revoked, tenant-scoped, owner-opted-in, administrator-approved devices with fresh authenticated telemetry. Respect user activity, schedule, AC power, thermal state, workload class, quotas, data classification and isolation requirements.
3. **Re-evaluate the shortfall:** if no eligible worker can satisfy the whole task, report the actual rejection reasons and aggregate compatible capacity. Do not treat incompatible fragmented capacity as usable memory.
4. **External AI proposal:** if permitted by organisation policy, offer a specific approved provider and explain why the internal pool cannot meet the request.
5. **Approval gate:** obtain administrator approval according to tenant policy and user/requester confirmation where required. Neither approval substitutes for device-owner consent when using a worker. A user cannot override an administrator's egress prohibition; an administrator cannot silently override an individual's device participation opt-out.
6. **Data review:** display the exact proposed data categories and task payload scope, destination/provider, residency/retention facts available from the provider configuration, and any redaction/minimisation applied.
7. **Execute only the approved scope:** bind approval to provider, tenant, workload manifest, data classification, payload digest, budget and expiry. Revalidate at dispatch. Reject stale, replayed or broadened approvals.
8. **Audit and report:** record the decision, capacity snapshot, rejection reasons, approvals, provider, payload scope, cost/budget where known, outcome and provenance. Do not log secrets or unnecessary prompt content.

If external assistance is blocked or declined, queue the task, suggest a smaller model/workload, split it into safe independent subtasks, or report that it cannot currently be completed. Never bypass policy to keep a job running.

## Enterprise policy controls

Administrators must be able to configure:
- approved providers and permitted regions/endpoints;
- allowed workload classes and data classifications per provider;
- whether fresh approval is required for every task or a bounded standing grant is allowed;
- per-task and per-tenant spend/request/size/time budgets;
- redaction rules, retention, audit and residency requirements;
- whether requester confirmation is also required;
- queue, timeout and retry behaviour.

Standing grants must be narrow, expiring, revocable and bound to an approved provider and data class. Highly sensitive/restricted data must remain local unless an explicit lawful and organisation-approved exception exists.

## Failure and safety cases

- All registered devices busy: show zero currently eligible capacity, not zero registered capacity.
- Enough aggregate RAM but no single compatible worker: report fragmentation/incompatibility; do not pretend memory can be pooled across machines for a single model.
- Stale heartbeat or unknown free memory: exclude the device.
- Device opts out or becomes interactive: cancel/prevent new work and follow verified lease cancellation/cleanup policy.
- Admin policy blocks egress: no cloud route is offered as executable; explain the block.
- Approval denied or expires: no dispatch.
- Provider unavailable or budget exceeded: stop bounded retries and return to queue/failure handling.
- Data class disallows provider: block before payload transmission.
- No route meets requirements: defer or decline; never silently wake devices or use personal/anonymous peers.

## Acceptance tests

1. Registered-but-busy devices do not count as available.
2. Existing reservations and OS headroom are deducted exactly once.
3. Freshness, owner consent, admin approval, tenant scope and device trust are all required.
4. Insufficient per-device memory is not masked by aggregate fleet memory.
5. No eligible worker causes an external-assistance proposal, not an automatic request.
6. Admin egress prohibition blocks the proposal/dispatch.
7. Requester or administrator denial results in zero provider dispatches.
8. Approval is bound to exact workload, payload digest, provider, tenant, data class, budget and expiry.
9. Payload minimisation and redaction are tested before network transmission.
10. Cancellation, lease expiry, provider timeout, retries and audit completeness are tested.
11. Dashboard distinguishes registered, trusted, online, available, busy and ineligible states.
12. Synthetic capacity fixtures are always labelled DEMO DATA; live metrics require authenticated telemetry and freshness evidence.

## Current implementation boundary

The Enterprise repository already has policy-level CPU/memory admission and a dry-run local-first placement planner. The roadmap explicitly states that live telemetry, the authenticated control-plane service, durable live scheduling, dashboard and safe worker execution remain incomplete. This document specifies the capacity-exhaustion and approved external fallback behaviour; it does not implement those runtime services.