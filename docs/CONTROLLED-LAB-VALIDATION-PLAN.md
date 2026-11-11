# Enterprise AI controlled-lab validation plan

Use an isolated lab, synthetic tenants, test identities and non-production devices only. Record commit, environment, configuration, expected/actual result and redacted evidence. Do not connect employee endpoints or production data.

## Evidence rules
- CI proves only the checks executed on that exact commit.
- Unit tests do not prove live identity integration, durable tenant isolation, real device connectivity, OS sandboxing or production key custody.
- Mark unexecuted external checks Not run.
- Remote worker execution, remote containment and arbitrary command dispatch remain disabled throughout this programme.

## Policy and trust matrix
| ID | Area | Procedure | Expected result |
|---|---|---|---|
| E01 | Tenant isolation | Tenant A requests tenant B overview | Denied; no cross-tenant data; denial audited |
| E02 | Operator sessions | Valid, expired, future, malformed, tampered and overlong tokens | Only valid in-window token accepted |
| E03 | Identity | Attempt session mint without trusted identity verification | No browser-controlled route can mint privileged claims |
| E04 | Enrollment | Unknown, uninvited, revoked and wrong-tenant device | Fail closed; no implicit trust |
| E05 | Dual consent | Admin-only and owner-only consent | Neither alone authorizes participation |
| E06 | Revocation | Revoke owner consent/device while lease exists | New work denied; lease transition audited |
| E07 | Telemetry | Stale, future-dated, replayed and wrong-device signed telemetry | Admission fails closed |
| E08 | Assignment | Alter signature, nonce, expiry or policy version | Invalid/replayed assignment rejected |
| E09 | Lease | Create, renew, release, expire and replay token | Correct binding required; accounting safe/idempotent as specified |
| E10 | Capacity | Reconcile signed samples and active reservations | Reservations counted exactly once; no over-admission |
| E11 | Resource safety | Simulate user activity, battery, thermal warning, low RAM, stale heartbeat | Batch admission denied or paused per policy |
| E12 | Audit failure | Make audit sink unavailable | Protected response/action not completed without required audit acknowledgement |
| E13 | Persistence | Restart, corrupt or roll back test ledger | Integrity failure detected; no silent trust escalation |
| E14 | Key lifecycle | Rotate test signing/integrity keys | Rotation explicit, bounded and documented |
| E15 | Cancellation | Disconnect simulated worker/controller during lease | New work stops; cleanup/reconciliation bounded and audited |

## Deployment gates
Before exposing a service, independently validate HTTPS, secure cookies, CSRF/origin protections, request limits, rate limits, OIDC/SAML issuer/audience/nonce validation, MFA/role mapping, tenant-scoped durable queries, append-only audit persistence, backup/restore and secret rotation. The current read-only console/service foundations are not a deployed control plane.

## Device/workload safety
Use only already-powered, explicitly enrolled lab devices with administrator approval and individual owner opt-in. Never wake sleeping devices or run while an interactive user is active. Verify OS-enforced sandboxing, scoped mounts, network egress, CPU/RAM/disk/time quotas and emergency pause on every OS before considering workload execution. Do not log prompts, file paths, credentials or raw telemetry.

## Tester report
Test ID; commit; environment; tenant/device fixture; identity role; preconditions; steps; expected; actual; pass/fail/blocked; evidence; severity; reproducibility; tester.

## Release gates
Require independent threat-model review, verified identity/tenant isolation, device credential lifecycle tests, OS isolation/resource enforcement, egress-denial tests, audit durability, rollback/recovery drills and incident-response procedures. Until evidenced, retain controlled-lab status and keep remote execution disabled.