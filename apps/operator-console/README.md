# UJANI Enterprise Operator Console (read-only preview)

This is the first browser application surface for the Enterprise control plane. It is deliberately read-only. It does not enroll/revoke devices, approve work, create leases, dispatch workloads, execute remote code, or change firewall/security controls.

## Current integration status

- The static console is implemented in plain HTML, CSS and JavaScript; it has no third-party runtime dependencies.
- It reads one same-origin endpoint: `GET /api/v1/operator/overview`.
- The Enterprise repository currently provides policy, trust and persistence libraries, not the authenticated HTTP control-plane service. Until that service is implemented and deployed, the console correctly displays an unavailable state and never invents/demo-populates fleet data.
- This is not a production-ready Enterprise deployment. Authentication, tenant-scoped authorization, durable API service, key management, audit transactions, service monitoring and deployment hardening remain release gates.

## API contract v1

The endpoint must require an authenticated operator session and enforce tenant-scoped RBAC on the server. The browser sends same-origin cookies only; it does not accept arbitrary API URLs, API keys or cross-origin destinations.

Example response shape (contract only; not fixture data):

```json
{
  "schema_version": 1,
  "generated_at_unix_ms": 0,
  "fleet": {
    "registered_devices": 0,
    "trusted_consented_devices": 0,
    "online_fresh_devices": 0,
    "schedulable_devices": 0
  },
  "devices": [
    {
      "device_id": "opaque-device-id",
      "display_name": "Workstation",
      "platform": "linux",
      "trust_state": "enrolled",
      "availability": "schedulable",
      "remaining_cpu_millis": 1500,
      "remaining_memory_mb": 4096,
      "last_seen_unix_ms": 0
    }
  ],
  "workloads": [],
  "approvals": []
}
```

The counts are distinct: registered is not trusted; trusted is not necessarily online; online/fresh is not necessarily schedulable. Schedulable must be computed only from authenticated, non-revoked, owner-opted-in and administrator-approved devices with fresh telemetry, safe power/thermal state, user not paused/active, and capacity after OS reserves and active leases. Do not aggregate fleet RAM as if it were one model-sized memory pool.

The server must not expose secrets, prompts, local paths, employee activity details or raw telemetry in this overview. Return only the minimum operator-visible inventory and admission reason needed to administer the fleet.

## Security and deployment requirements

1. Serve over HTTPS behind the organization's identity provider; use secure, HttpOnly, SameSite session cookies and CSRF protection for any future state-changing routes.
2. Keep the API same-origin. Add server-side CSP, HSTS, frame denial, MIME sniffing protection and strict cache controls. The HTML CSP is defense-in-depth, not a substitute for response headers.
3. Apply tenant isolation and role checks on every server request; never trust client-side filtering.
4. Record authenticated operator reads and all future approval/administrative mutations in an append-only audit system with actor, tenant, scope, timestamp and outcome.
5. No state-changing actions belong in this read-only milestone. Any later approval action must be explicit, scoped, expiring and audited; remote execution remains disabled pending independent security review.

## Local static preview

Serve this directory with any static file server and open `index.html`. The overview will remain unavailable until the authenticated API is deployed. This behavior is intentional.
