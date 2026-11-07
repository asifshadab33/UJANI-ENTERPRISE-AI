# Durable device trust registry: implementation boundary

## What this change provides

`device_trust::durable::DurableDeviceRegistry` is a persistence adapter around the existing signed device-trust primitive. It:

- reloads the authoritative registry under an OS advisory lock for each operation, including across separate processes;
- persists tenant binding, device public keys, key IDs, monotonic device-key generations, enrollment/revocation state, administrator-command nonces and device-request nonces;
- authenticates the complete snapshot with HMAC-SHA256 and a domain-separated format version;
- requires the HMAC key and administrator verifying keys to be injected by the trusted host; neither is read from the writable registry directory;
- writes a same-directory temporary snapshot, syncs it, and uses backup/rename recovery for interrupted replacement;
- rejects oversized, malformed, unknown-version, duplicate, wrong-key-ID and MAC-invalid state without silently resetting it;
- never persists device private keys, raw request signatures, or lease capability secrets.

The integrity key's key_id is part of the authenticated envelope and must match the configured active key. A key rotation is performed by a trusted host deployment that verifies/exports the old state under the old protected key and performs a controlled migration; automatic multi-key rotation is not yet provided.

## Important limitations

This is a durable policy primitive, not a complete production control plane. It is not an HTTP server, identity provider, tenant RBAC engine, audit event sink, admin-key lifecycle service, or workload dispatcher. The caller must still authenticate administrators, authorize tenant scopes before signing commands, load keys from a protected provider, protect registry files, bind leases to authenticated principals and emit a separate append-only audit event. Remote execution remains disabled.

## Proposed authenticated API contract

| Operation | Required authorization | Required binding |
|---|---|---|
| POST /v1/tenants/{tenant}/devices/enroll | Tenant device-admin role; step-up auth | Signed admin command, new-key proof of possession |
| POST /v1/tenants/{tenant}/devices/{device}/rotate-key | Tenant device-admin role; step-up auth | Existing-key and new-key proof; expected generation |
| POST /v1/tenants/{tenant}/devices/{device}/revoke | Tenant security-admin role; step-up auth | Signed command; monotonic generation |
| POST /v1/tenants/{tenant}/leases | Enrolled device workload-submit role | Device signature, tenant, device, workload, manifest digest, policy approval and expiry |
| POST /v1/tenants/{tenant}/leases/{id}/renew | Same enrolled device and lease owner | Lease capability, request nonce, generation, expiry |
| DELETE /v1/tenants/{tenant}/leases/{id} | Same enrolled device and lease owner or authorized tenant operator | Lease capability or audited operator override |

All requests must have bounded bodies, strict versioned schemas, request IDs/nonces, short expiry windows and explicit clock-skew handling. Unknown fields and scopes are rejected. Tenant identity is derived from the authenticated principal and compared with the signed device claim; it is never trusted from a URL/body field alone.

## RBAC minimum roles

- Platform security administrator: manages protected platform trust roots and emergency revocation; no workload submission by default.
- Tenant device administrator: enrolls, rotates and revokes devices within one tenant.
- Tenant security auditor: reads redacted audit and device status; cannot mutate trust or leases.
- Workload submitter: requests leases only for permitted workload classes and devices.
- Device principal: authenticates only as its enrolled tenant/device/key generation and acts only on its own authorized leases.
- Fleet operator: read-only cross-tenant operational metadata where explicitly granted; no tenant secrets or workload content.

Every role is deny-by-default. Cross-tenant actions require explicit platform-level permission and an auditable reason.

## Required validation before enabling the service

- restart and multi-process concurrency tests for nonce consumption and device lifecycle;
- tampered snapshot, missing key, wrong key ID, stale generation, revoked device and cross-tenant rejection;
- protected key-provider integration and a documented key rotation/recovery drill;
- authenticated HTTP adapter tests for role/scope checks, body limits, rate limits, clock skew and request replay;
- external security review of the service boundary and deployment permissions.

Passing crate tests is not a substitute for service and deployment validation.
