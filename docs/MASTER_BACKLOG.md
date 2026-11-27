# UJANI Consolidated Master Backlog — Enterprise AI

**Live reconciliation:** 27 November 2026. Default branch `main` at `76092417f3df1046c2e544df13384c3fe31d20c4`. This is an implementation/evidence snapshot, not a production-readiness claim.

## Product boundary

- Enterprise is standalone; Public AI is not a runtime dependency.
- Primary purpose is authorised organisation resource utilisation, reducing avoidable dependence on central AI data centres.
- Inventory is limited to enrolled/authorised devices and privacy-minimised capability/resource metadata. No prompts, file contents, paths, credentials, history or employee activity.
- Owner consent and organisation policy are separate. Inventory consent is not compute consent.
- Remote dispatch/execution, model distribution and automated containment remain disabled.

## P0 — complete before any worker pilot

1. Production authenticated OIDC/HTTP control plane, tenant isolation and authenticated device agent.
2. One atomic admission path binding device trust, owner + administrator consent, exact task digest/privacy class/capabilities, bounded CPU/RAM/time/output, expiry and replay claim to a durable lease and audit record.
3. Protected customer-selected key custody, rotation/recovery and independent monotonic anti-rollback anchoring. Do not require cloud KMS for every deployment.
4. Receiver-side authorization and OS-enforced process/filesystem/network isolation, quotas, cancellation and revocation.
5. Signed, verifiable receipts bound to exact task/input/output bytes; monotonic task states and crash/partition/lease recovery.
6. Customer-hosted deployment, backup/restore and independent security review.

## P1 — useful work continues without remote execution

1. Wire authenticated model-inventory v2 intake and PostgreSQL admission to a full-schema-validating host adapter and tenant-scoped repository.
2. Implement the bounded v2 operator read projection/API/GUI. Preserve evidence source/confidence/freshness/unknown states; never expose prompts or infer execution authority.
3. Keep model/task matching advisory; improve catalogue parity, fresh resource evidence and measured CPU/RAM/GPU/NPU/energy views.
4. Continue read-only Security Centre provider freshness and consented event ingestion; no automated remediation.
5. Continue operator accessibility, deployment, setup and troubleshooting.

## P2 — after foundations

1. Multi-site scheduling, fairness, priorities and energy-aware optimisation.
2. Optional customer-selected IDS/network/security integrations with controlled-lab validation.

## Live evidence — 27 November 2026

### Repository baselines

- Enterprise `main`: `76092417f3df1046c2e544df13384c3fe31d20c4`.
- Public AI `main`: `b21f37b6967f466ae9c3fad29fba16091c7990e5`.
- The Public and Enterprise workstreams retain independent product/runtime boundaries. The shared task-contract and model-inventory schemas were previously verified byte-identical; do not change shared wire contracts without coordinated cross-repository review.

### Enterprise PR evidence

- PR [#362](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/362) merged at `dd3b8f9806130b9f910f94e671a64010f6c59228`. It binds authenticated device identity and the exact signed telemetry sample in a private-field envelope. It is a type-safety boundary only; it does not implement the HTTP host, SQLx repository, transaction wrapper or OIDC.
- PR [#361](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/361) merged at `fecc8d65ee30d5c90b53f026e4e3da3d89dbaa05`. It adds a schema-aligned, tenant-authorized read-only model-task-match response with inventory/match timestamps, bounded unique reasons, safe integer checks and verified-only positive compatibility. Reported/estimated evidence cannot produce a positive compatibility claim.
- PR [#342](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/342) is closed as superseded by merged #369. PR [#343](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/343) remains draft; its process-local mutex does not solve cross-process key lifecycle races and it must not be merged until protected inter-process locking and recovery tests exist. PR [#344](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/344) remains the stale stacked draft; refreshed PR #370 carries its lease-revocation work onto current main.
- Merged Enterprise PRs #357–#360 are included in `main` at the baseline above.

- PR [#364](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/364) merged at `3c6cf99679277eee21935ae7e080f4b848bf8e55`. It adds PostgreSQL regressions for tenant-context reset after rollback/commit and tenant A-to-B switching on a reused backend connection. This validates transaction-local context lifecycle; a caller-settable custom GUC is still not authentication.
- PR [#363](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/363) merged at `78c54b7dd1822e42d68666a0670507d72639bbe2` and reconciles the master backlog.
- PR [#366](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/366) merged at `b26b701b79879e284da00a123c92cdc2eb0f180b`; PR [#368](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/368) merged at `855deb4c0234341d03056e89f363ae6bfe3cbaa1` and refactored the request decoder to reuse the crate-wide recursive strict JSON parser. The 8 KiB decoder rejects duplicate keys, unknown fields, malformed/trailing bodies and oversize payloads. This is transport-neutral request validation, not an HTTP listener or authentication boundary.

- PR [#369](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/369) merged at `76092417f3df1046c2e544df13384c3fe31d20c4`. Migration `0018` persists organisation + individual/device Collective Defence consent, generation/CAS, revocation, idempotency and append-only audit. Database persistence assumes the authenticated host verifies signed consent and binds identity before calling the SQL functions.
- PR [#370](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/370) is open for migration `0019` to revoke active leases/reservations immediately when device trust, owner binding, dual consent, approval or key generation changes. It has exact-head PostgreSQL 16 and cross-platform checks in progress; database revocation does not stop a remote process by itself.
### P0 authenticated-service boundary

The next implementation owner is the authenticated service/database boundary tracked by [#90](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/issues/90) and [#353](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/issues/353).

Existing foundations:
- Transport-independent operator session/service core and tenant-scoped read projection.
- Device-signed telemetry intake preflight, monotonic generation/sequence checks and exact-body binding.
- PostgreSQL migrations `0001`–`0018`, including transactional telemetry, lease lifecycle, lock-order correction and durable dual-party consent. Migration `0019` is under review in PR #370.
- Existing PostgreSQL CI tests cover RLS with correctly set tenant context, unset-context denial, cross-tenant row filtering, append-only audit, and transaction-local context reset on a reused session.

Still missing:
- Production OIDC/device-authenticated HTTP host and trusted identity-to-tenant binding.
- A production PostgreSQL repository/transaction wrapper; current GUC context is still supplied by SQL session state and is not an independent authentication credential.
- Pool reuse under concurrent alternating tenants, rollback, cancellation and connection failure through the actual repository.
- Adversarial tests and deployment controls proving only the trusted service can obtain the runtime DB credential and reach PostgreSQL. SQL-level RLS tests alone cannot prove this.
- Durable audit writer connected to service transactions, production key-provider integration and independent monotonic rollback anchor.

**Security interpretation:** PostgreSQL `current_setting('ujani.tenant_id', true)` is a tenant selector, not an authentication factor. The current `ujani_runtime` test role can set session context; the production boundary must therefore prevent untrusted clients from possessing runtime DB credentials or a direct DB network path, and must only set transaction-local context from verified server-side identity. Do not claim that RLS alone resists arbitrary SQL executed with the runtime role.

### Public AI / shared-protocol status

Public `main` is `b21f37b6967f466ae9c3fad29fba16091c7990e5`. PR [#461](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/461) (late task progress listener cleanup) merged at `380585bb496975d39204a61c318897f7cbe499ab`; PR [#462](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/462) (updater-feed first-publication handling) merged at `46c281bb8d5082a860ccb1bc3432fde7ac577fed`. PR [#469](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/469) merged at `b21f37b6967f466ae9c3fad29fba16091c7990e5` with native-confirmation denial-before-side-effect tests. PR [#470](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/470) remains open for fresh post-picker capability revalidation before selected-folder traversal. No shared schema change is proposed by this Enterprise pass.

## Evidence labels and completion rules

- **Implemented:** code exists; no test claim implied.
- **Unit-tested:** focused tests pass locally or in a named workflow.
- **CI-verified:** all required hosted checks pass on the exact current commit SHA.
- **Integration-verified:** complete cross-component workflow passes.
- **Device-verified:** real enrolled endpoint and protected host pass.
- **Blocked:** identity, key provider, platform capability, infrastructure or independent review is missing.
- **Release-ready:** all applicable gates have evidence; not currently asserted.

1. Keep remote execution disabled until identity, dual consent, replay, transactional lease, key custody, isolation, receipts and failure recovery pass end-to-end.
2. Never treat a signed device measurement as proof of physical truth; label source and confidence.
3. Never pool RAM across devices as if it were one machine.
4. Missing, stale, estimated or contradictory evidence fails closed for admission.
5. Keep model matching advisory; it must not install a model, reserve resources or dispatch a workload.
6. Use real service data in the Control Plane; label fixtures and simulations.

**Current safety decision:** UJANI Enterprise remains a pre-alpha policy/control-plane prototype, not production-ready for remote worker execution. No job dispatch, remote execution, autonomous containment or endpoint-control actions are enabled.
