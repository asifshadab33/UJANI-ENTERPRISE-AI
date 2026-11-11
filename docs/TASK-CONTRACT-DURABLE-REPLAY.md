# Shared task-contract durable replay storage

## Scope

Migration `0002_task_contract_replay_storage.sql` adds tenant-scoped PostgreSQL storage primitives for the optional shared task-contract v1. It is not an HTTP intake service and does not enable remote execution.

The migration stores only identifiers, decoded nonces, SHA-256 digests, expiry/state metadata and sequence watermarks. It never stores prompts, user files, model outputs or payload bytes.

## Atomic task admission boundary

After authenticating the sender and validating the envelope/signature/consent context, a future intake adapter must claim the task in the same database transaction as the authoritative admission record:

- Insert `(tenant_id, task_id, sender_device_id, nonce)` into `task_contract_replays`.
- The primary key rejects task-ID reuse within a tenant.
- The unique key on `(tenant_id, sender_device_id, nonce)` rejects nonce reuse for that sender within a tenant. The database constraint is the concurrency primitive; an application-side pre-check is not sufficient.
- Persist the envelope and payload digests, expiry and initial state. Do not persist the payload itself.
- If the claim conflicts, reject the request as replayed. Do not overwrite the existing record or treat a duplicate as an idempotent new task.

The sender device must already be authenticated and enrolled in the tenant device registry. The migration does not establish that identity or validate signatures.

## Monotonic message streams

`task_contract_sequences` stores separate watermarks for `task_status` and `execution_receipt`, keyed by tenant, task and message type. Each stream may start at sequence 1.

A future adapter must advance a watermark with a conditional upsert in the same transaction as the verified message/task update:

```sql
INSERT INTO ujani_control.task_contract_sequences
  (tenant_id, task_id, message_type, last_sequence, message_digest)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, task_id, message_type) DO UPDATE
SET last_sequence = EXCLUDED.last_sequence,
    message_digest = EXCLUDED.message_digest,
    updated_at = now()
WHERE ujani_control.task_contract_sequences.last_sequence < EXCLUDED.last_sequence;
```

A row count of zero means the sequence was repeated or stale and must be rejected. The caller must not commit any associated state transition when this update fails. The adapter must verify message signatures and task/tenant/device bindings before attempting the update.

## Tenant isolation and lifecycle

Both tables enable and force row-level security using the transaction-local `ujani.tenant_id` setting. The runtime role must be non-owner, non-superuser and must not have `BYPASSRLS`. Missing tenant context returns no rows and prevents writes. The migration grants no role privileges; deployment grants must be reviewed separately.

Expired rows are not automatically deleted by this migration. A future retention/cleanup policy must retain replay tombstones for the full task expiry and clock-skew window and must never delete an active task or a sequence watermark still needed for receipt verification.

## Not implemented by this migration

- Authenticated HTTP/gRPC transport or identity-provider integration.
- Sender/worker key enrollment, rotation, revocation or KMS custody.
- Verification of Ed25519 signatures or payload bytes (the native Rust verifier is a separate module).
- Atomic coupling to administrator approval, device-owner consent, resource reservation or leases.
- Task dispatch, worker execution, OS sandboxing, cancellation or egress enforcement.

Remote worker execution remains disabled.
