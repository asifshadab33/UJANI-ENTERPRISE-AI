# External monotonic snapshot anchor contract

## Status

The policy crate now exposes `MonotonicSnapshotAnchor` and
`DurableDeviceRegistry::open_with_anchor`. The interface is implemented and
has a deterministic in-memory test provider. **No production KMS, HSM, TPM or
remote control-plane provider is included.** The default `open` constructor
continues to provide HMAC integrity only and does not detect rollback.

This is an integration contract, not a claim that anti-rollback is deployed.

## Required provider semantics

A production provider must:

1. Store one record per immutable registry identifier in a trust domain separate
   from the registry file and its backup directory.
2. Return the current monotonically increasing generation and the SHA-256 digest
   of the exact authenticated snapshot bytes.
3. Implement a durable, linearizable compare-and-set. Creation must accept only
   an absent record and generation 1. Updates must accept only the exact expected
   generation and advance it by one.
4. Reject stale generations, duplicate initialization, tenant/registry ID
   collisions and replayed updates. A stale caller must not overwrite a newer
   anchor record.
5. Authenticate callers using service identity and tenant/registry scope. Do not
   accept a caller-supplied HMAC key or public key as proof of anchor authority.
6. Provide audited backup, recovery, key rotation, access control and outage
   behavior. If the provider cannot be reached, anchored registry operations
   fail closed.

A local file, SQLite table beside the registry, or a second writable sidecar on
the same host is not an external monotonic anchor.

## Snapshot commit and recovery order

The anchored adapter uses this order:

1. Acquire the existing OS advisory registry lock.
2. Read the external anchor record.
3. Accept the primary snapshot only when its exact-byte digest matches the
   anchored digest. If the primary does not match, accept the backup only when
   its exact-byte digest matches the same anchor, then restore that backup.
4. Apply the authenticated registry operation and write/fsync the new snapshot
   using the existing same-directory atomic replacement.
5. Compare-and-set the external anchor from the previously observed generation
   to the next generation and new snapshot digest.
6. Report success only after the provider confirms the compare-and-set.

If the process stops after the local snapshot write but before the anchor update,
the prior backup still matches the old anchor and is restored on the next open.
If the anchor update succeeds but its response is lost, the new primary digest
matches the provider on the next open. If neither local snapshot matches the
provider, the registry fails closed.

## Tests and limits

The in-memory provider test covers a rollback to an older snapshot that still
has a valid HMAC. It validates the interface and local recovery logic only; it
does not test a real distributed provider, network partitions, provider
consistency, administrator authorization, disaster recovery or hardware-backed
key custody.

Before remote dispatch is considered, add provider contract tests for concurrent
CAS, stale writers, duplicate bootstrap, provider outage, ambiguous timeout
after commit, backup restoration, cross-tenant access, recovery and key
rotation. Keep worker dispatch disabled until those tests and an independent
threat review pass.
