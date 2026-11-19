# Enterprise model/runtime inventory v2 ingestion status

Status: database admission primitive implemented and PostgreSQL-tested; not a deployed hosting service.

## Purpose and boundary

Enterprise stores a bounded, privacy-minimised inventory of locally discovered runtimes, installed model identifiers, versions, capability evidence and resource requirements. It is for operator visibility and future capability-aware placement only. It does not inspect prompts, model contents, personal files, local paths, credentials or unnecessary user activity.

The shared wire contract remains [Model/runtime inventory v2](MODEL-RUNTIME-INVENTORY-V2.md). Public AI's `personal_local_only` descriptor intentionally omits an Enterprise device reference and is not directly admissible by this route. Enterprise requires a separately authenticated `organisation_enrolled` descriptor, current individual owner consent and current administrator policy. Public AI does not transmit its local inventory to Enterprise by default.

## Implemented database boundary

Migration `0014_atomic_model_inventory_v2_admission.sql` adds:

- A tenant-scoped, revisioned administrator inventory policy with bounded evidence age and an enabled/disabled state
- A latest-snapshot table with tenant RLS, bounded runtime/model counts and a monotonically increasing server-side inventory revision
- A `SECURITY INVOKER` transaction that rechecks authenticated tenant context, enrolled device trust, active key ID/generation, current owner binding and consent generation, enabled administrator approval/policy version, signed-request expiry/replay and generated-at freshness
- A digest-only audit receipt committed with the replay claim, snapshot and device revision
- A tenant audit lock acquired before device row locks, matching the repository's existing lock order
- Immediate clearing of the stored runtime/model JSON when device trust, active key, owner consent, administrator approval or organisation policy changes. A later opt-in or policy approval requires a fresh report.

The inventory envelope is independently bounded in SQL: exact top-level and consent/privacy envelope keys, current device reference, policy version, maximum 16 runtimes and 512 models, and explicit false values for prompt, user-file, local-path and credential collection. The `authenticate_model_inventory_v2_request` boundary verifies the enrolled-device signature over the exact raw body and performs trust/owner-consent preflight when the hosting adapter passes the unchanged body and signed request. The hosting adapter must still perform full Draft 2020-12 JSON Schema validation before it calls the database transaction; the SQL function is not a substitute for schema validation or device authentication.

The policy's `max_age_ms` currently bounds the overall snapshot `generated_at_unix_ms`; it does not independently declare every nested runtime/model evidence item fresh. Per-field `observed_at_unix_ms`, source and confidence are preserved as evidence. Until the operator API and capability matcher are implemented, consumers must classify each item as fresh, stale or unknown; stale/unknown or merely reported/estimated evidence must never satisfy a verified scheduling requirement. The future matcher must apply explicit per-evidence age and confidence rules rather than treating a fresh top-level snapshot as proof that every nested field is fresh.

A revoked row retains the pseudonymous tenant/device reference, inventory revision and timestamps, key/consent/policy generation references, request ID and payload digest; it no longer retains runtime/model metadata. The database does not claim external anti-rollback protection: PostgreSQL transaction atomicity and local HMAC/checksums are not a substitute for a separately protected monotonic checkpoint.

## Verification added

The CI pipeline applies migration 0014 after migrations 0001–0013 and runs `test_model_inventory_v2_admission.sql` against PostgreSQL 16. The regression test covers:

- Successful admission with both administrator approval and owner consent
- Request replay, equal/older timestamps, future timestamps and stale evidence
- Stale key generation, mismatched policy version, disabled policy and denied administrator approval
- Privacy-envelope and device-reference rejection
- Rollback of replay claim, snapshot and device revision when the caller aborts
- Rollback after a late audit uniqueness failure
- Snapshot clearing after policy, administrator approval and owner-consent changes
- Visible-to-revoked identity immutability across devices, with a matching destination key to exercise the trigger rather than a foreign-key failure
- Fresh-clock future-skew rejection and strictly increasing restoration timestamps
- Tenant RLS and narrow runtime database privileges

The SQL test exercises the database envelope and transaction; it does not claim to run the full JSON Schema validator or a real device signature. Those checks must be performed by the eventual hosting adapter before it calls the database function.

## Remaining P0/P1 work

1. Build the authenticated customer-hosted HTTP adapter and tenant-scoped SQL repository. Verify exact signed raw request bytes, validate the full shared schema, load current consent generation from the tenant repository and call the transaction in the same authoritative request flow.
2. Add an authenticated administrator policy-edit workflow. The current policy table requires an enabled administrator and a strictly increasing revision, but no OIDC-backed policy editor exists.
3. Add the operator read API and GUI for runtime/model availability, verified capability/resource fit, evidence freshness, unknown metadata and current reservations. Always filter by current trust, consent, administrator approval and policy revision.
4. Add permitted model-family/workload policy fields and capability-aware placement. Keep per-device model choice under owner control; do not silently replace models.
5. Complete protected key-provider integration and separately protected monotonic rollback anchoring.
6. Complete durable audit/ledger encryption, backup/restore, retention/compaction and crash/power-loss recovery.

No model downloading, worker dispatch, remote execution, autonomous firewall changes or containment actions are enabled by this work. The full trust, isolation, lease, approval, audit and rollback lifecycle must be independently proven before any dispatch implementation.
