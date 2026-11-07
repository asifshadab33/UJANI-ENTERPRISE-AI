# Collective Defence consent policy foundation

## Security objective

Collective Defence is **off by default**. Participation requires two separate, independently verified signatures:

1. An authorized administrator's tenant-scoped opt-in.
2. The individual user's separate opt-in for one named device, using a trusted identity-provider key bound to that tenant, device, and principal.

A tenant administrator enabling the feature never enrolls users or devices automatically. The user consent is purpose-bound to read-only Collective Defence telemetry, the current tenant-policy generation, and a versioned consent notice.

## Implemented policy primitive

`ujani_enterprise_policy::collective_defence_consent` provides:

- Domain-separated Ed25519 signatures for tenant and individual consent statements.
- Tenant-scoped administrator key lookup.
- Tenant-, device-, and principal-scoped individual key lookup.
- Strict purpose and event-schema version checks.
- Bounded consent expiry (24 hours), clock-skew checks, and retention limits.
- Separate tenant and individual generations. A tenant policy change invalidates prior individual approvals; individual withdrawal invalidates that user's device generation.
- A short-lived `ConsentPermit` that must be rechecked immediately before transmission against freshly loaded generations.
- Fail-closed errors for missing, disabled, expired, mismatched, untrusted, or stale consent.

The policy primitive contains no sensor, network transport, event collector, ingestion API, persistence layer, scheduler, remote command, or response action.

## Required production integration

This crate does **not** persist consent or revocation state. Production integration must not treat the in-memory policy result as sufficient authority. Before any telemetry is collected or transmitted, the service must:

- Load trusted admin and individual identity keys from protected tenant-scoped identity infrastructure.
- Load current tenant and individual generations from a durable, rollback-resistant authority.
- Verify both signatures and bind the user key to the exact tenant, device, and principal.
- Re-evaluate consent at collection and again at the outbound queue boundary; discard queued events if consent changed.
- Persist withdrawal and generation increments before acknowledging revocation.
- Revoke the relevant participation credential or lease on user withdrawal or tenant disablement.
- Fail closed if the consent store, identity provider, clock, or revocation authority is unavailable.
- Append an auditable record of the consent notice version, purpose, retention, actor, device, policy generation, timestamps, and revocation result. Keep the shared security event payload separate from this audit record.
- Never share file contents, credentials, conversations, raw command lines, unrestricted process data, or arbitrary endpoint payloads.

A device signature alone is not proof of informed human consent. The individual key must be controlled by a trusted identity flow that records the user's explicit action on the versioned notice.

## Explicit non-goals

Collective Defence consent authorizes only the allowlisted, privacy-minimised, read-only event schema. It does not authorize remote access, remote execution, automated containment, endpoint policy changes, cross-tenant sharing, or silent background collection. Those capabilities remain disabled and require separate design, authorization, and security review.

## Validation requirements

The policy tests cover default-off behavior at both levels, separate signatures, tenant/device/principal binding, stale generations, expiry, retention, schema version, tampering, and permit invalidation. A production service still needs durable restart/revocation race tests, authenticated ingestion tests, tenant-isolation/IDOR tests, rate limits, poisoning resistance, and an independent security review.
