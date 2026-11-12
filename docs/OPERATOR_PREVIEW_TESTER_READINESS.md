# UJANI Enterprise AI — operator preview tester readiness

**Status:** architecture and policy preview only; no deployable fleet-management service is available for external operator testing yet.

## What can be reviewed now

The current repository contains a transport-independent operator control-plane core and a read-only console contract. The core validates short-lived tenant-bound operator sessions, checks overview consistency and requires an audit sink acknowledgement. The repository does **not** yet contain a network listener, production OIDC/SAML identity adapter, durable multi-tenant overview repository, durable audit sink or deployed endpoint.

Current main commit at the 2026-11-12 audit: `82f2b951951516bc7b34e0c1a90f3faa5250806c`. It includes merged PR #130 (read-only tenant-validated model/runtime inventory metadata), PR #134 (shared task/model-inventory contract vectors and validators), and PR #136 (tenant-scoped PostgreSQL replay claims and monotonic status/receipt sequence storage). The exact-head CI, PostgreSQL tenant-isolation, CodeQL and dependency checks passed for the respective PR heads before their merges; no post-merge main workflow run was returned during this audit. PR #130 does not add the production authenticated device-sample adapter or durable live inventory repository, so inventory may remain empty. PR #136 adds storage primitives only; it does not add authenticated intake, consent/lease admission or dispatch. This is not proof of a deployed service or live device connectivity.

## Safe preview review

A reviewer may inspect the operator UI and documentation using synthetic/demo data only. Record confusing labels, missing states, accessibility issues and workflow gaps. Clearly label all displayed inventory and telemetry as DEMO DATA unless sourced from a verified live backend.

- [ ] Device states distinguish registered, trusted, online/fresh and currently schedulable.
- [ ] Tenant context is visible and cannot be selected or overridden by an untrusted browser field.
- [ ] Empty, stale, unavailable and audit-failure states are explicit.
- [ ] The UI does not imply that a device is trusted merely because it is registered.
- [ ] No prompt content, file paths, employee activity, secrets or raw device logs appear in operator views.
- [ ] No control suggests remote execution, endpoint containment or firewall mutation is enabled.

## Not authorized for external operational testing

Do not connect customer networks, enroll real employee devices, upload production inventory, provision real signing keys, or attempt remote workload execution. Do not deploy the preview as a fleet manager. No remote execution, workload dispatch, endpoint containment or firewall writes are enabled or approved.

## Required before an enterprise pilot

1. Production identity-provider adapter and administrator-managed tenant/role provisioning.
2. Durable, transactionally consistent tenant-scoped device/workload/approval/telemetry repository.
3. Protected key provider, key rotation/revocation/recovery and rollback protection external to writable ledger files.
4. Authenticated lease acquire/renew/release endpoints with replay, expiry and clock-skew enforcement.
5. Durable append-only tamper-evident audit sink; fail closed on audit failure.
6. Cross-tenant, revoked-device, replay, stale-key, tamper, restart, crash-recovery and concurrency integration tests.
7. Independent security review and controlled lab validation before any dispatch integration.

**Tester hand-off decision:** Public AI Android alpha can receive controlled smoke testers under its separate tester pack. Enterprise AI remains architecture/UI review only until the service and trust boundary above are implemented and independently validated.
