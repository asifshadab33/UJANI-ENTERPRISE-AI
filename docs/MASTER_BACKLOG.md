# UJANI Consolidated Master Backlog — Enterprise AI

**Live reconciliation:** 27 November 2026. Default branch `main` at `dd3b8f9806130b9f910f94e671a64010f6c59228`. This is an implementation/evidence snapshot, not a production-readiness claim.

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

- Enterprise `main`: `dd3b8f9806130b9f910f94e671a64010f6c59228`.
- Public AI `main`: `9163675e55494346740a4e37e226b9bfbc24cd36`.
- The Public and Enterprise workstreams retain independent product/runtime boundaries. The shared task-contract and model-inventory schemas were previously verified byte-identical; do not change shared wire contracts without coordinated cross-repository review.

### Enterprise PR evidence

- PR [#362](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/362) merged at `dd3b8f9806130b9f910f94e671a64010f6c59228`. It binds authenticated device identity and the exact signed telemetry sample in a private-field envelope. It is a type-safety boundary only; it does not implement the HTTP host, SQLx repository, transaction wrapper or OIDC.
- PR [#361](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/361), current head `45f18cbae81626f06035a0a95ba26a23813d3e04`, remains draft. The original positive fixtures were corrected to use verified evidence; reported evidence now has an explicit negative-confidence regression. The read-only response is bound to device identity and inventory/match timestamps, and its Rust serializer now enforces the response-schema invariants. Exact-head hosted checks are still required before merge.
- PRs [#342](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/342), [#343](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/343) and [#344](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/344) remain draft/stale. #344 is stacked on #342. Their older green runs do not transfer to refreshed heads. #343's process-local mutex does not solve cross-process key lifecycle races.
- Merged Enterprise PRs #357–#360 are included in `main` at the baseline above.

- PR [#364](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/364) merged at `3c6cf99679277eee21935ae7e080f4b848bf8e55`. It adds PostgreSQL regressions for tenant-context reset after rollback/commit and tenant A-to-B switching on a reused backend connection. This validates transaction-local context lifecycle; a caller-settable custom GUC is still not authentication.
- PR [#363](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/363) merged at `78c54b7dd1822e42d68666a0670507d72639bbe2` and reconciles the master backlog.
- PR [#366](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/366) is open for a bounded, duplicate-key-rejecting decoder for the operator model-task-match request. It is a transport-neutral decoder only, not an HTTP listener or authentication boundary.

### P0 authenticated-service boundary

The next implementation owner is the authenticated service/database boundary tracked by [#90](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/issues/90) and [#353](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/issues/353).

Existing foundations:
- Transport-independent operator session/service core and tenant-scoped read projection.
- Device-signed telemetry intake preflight, monotonic generation/sequence checks and exact-body binding.
- PostgreSQL migrations `0001`–`0017`, including transactional telemetry, lease lifecycle and lock-order correction.
- Existing PostgreSQL CI tests cover RLS with correctly set tenant context, unset-context denial, cross-tenant row filtering, append-only audit, and transaction-local context reset on a reused session.

Still missing:
- Production OIDC/device-authenticated HTTP host and trusted identity-to-tenant binding.
- A production PostgreSQL repository/transaction wrapper; current GUC context is still supplied by SQL session state and is not an independent authentication credential.
- Pool reuse under concurrent alternating tenants, rollback, cancellation and connection failure through the actual repository.
- Adversarial tests and deployment controls proving only the trusted service can obtain the runtime DB credential and reach PostgreSQL. SQL-level RLS tests alone cannot prove this.
- Durable audit writer connected to service transactions, production key-provider integration and independent monotonic rollback anchor.

**Security interpretation:** PostgreSQL `current_setting('ujani.tenant_id', true)` is a tenant selector, not an authentication factor. The current `ujani_runtime` test role can set session context; the production boundary must therefore prevent untrusted clients from possessing runtime DB credentials or a direct DB network path, and must only set transaction-local context from verified server-side identity. Do not claim that RLS alone resists arbitrary SQL executed with the runtime role.

### Public AI / shared-protocol status

Public `main` is `e6ca323fec61a947c382886a5c0d0607ebb689f0`. PR [#461](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/461) (late task progress listener cleanup) merged at `380585bb496975d39204a61c318897f7cbe499ab`; PR [#462](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/462) (updater-feed first-publication handling) merged at `46c281bb8d5082a860ccb1bc3432fde7ac577fed`. PR [#469](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/469) merged at `b21f37b6967f466ae9c3fad29fba16091c7990e5` with native-confirmation denial-before-side-effect tests; PR [#470](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/470) subsequently merged at `e6ca323fec61a947c382886a5c0d0607ebb689f0`, adding fresh post-picker capability revalidation before selected-folder traversal. PR [#472](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/472) is closed as superseded by [#474](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/474), which carries the trusted-origin IPC gate, explicit policy registry and command-map parity correction. On #474 exact head `c19dec2402f86e29ddece95432bc412abac9d208`, the native command security-map check, Rust core tests (203 passed) and React TypeScript build passed; platform/native tests, Android, CodeQL, dependency and installer checks were still running at this reconciliation. PR [#473](https://github.com/asifshadab33/UJANI-PUBLIC-AI-/pull/473) separately offloads queued memory probes from async workers; exact-head cross-platform/native CI, Android, CodeQL and installer checks remain in progress. No shared schema change is proposed by this Enterprise pass.

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
