# Protected integrity-key provider contract

## Status

The Enterprise policy crate defines a host-owned `IntegrityKeyProvider`
interface in `integrity_key_provider.rs`. Both the durable device-trust registry
and durable reservation ledger now expose provider-backed constructors. New
snapshots are signed with the provider's active key, and snapshots signed by a
retained previous key can be verified during rotation. Store tests cover
sequential rotation and fail-closed provider absence; the ledger also tests
provider-backed anchored backup recovery.

Both stores retain caller-injected raw-key constructors for prototype
compatibility and existing tests. Those constructors are not a completed
production custody design. There is no production OS-keyring, TPM, KMS or HSM
adapter in this repository. Windows anchored ledger snapshot writes remain
disabled until a safe durable-rename adapter is available; the provider-backed
anchored backup-recovery regression therefore runs on Unix platforms only.
Unanchored provider-backed ledger persistence is still exercised on Windows.

## Provider boundary

The interface exposes only operations and non-secret key identifiers:

- provision key material inside the provider without returning key bytes;
- activate a previously provisioned key for one store purpose;
- create a MAC with the active key and return its identifier and tag;
- verify a stored MAC with an active or retained previous key;
- retire a non-active key after all snapshots and retained backups are migrated.

Key namespaces are separated for the device-trust registry and reservation
ledger. Provider implementations must use constant-time verification, immutable
non-reused key IDs, bounded I/O, and fail-closed outage behavior.

## Deployment options

A local installation may use an OS-protected cryptographic facility or
non-exportable TPM-backed key handle where the platform supports it. An
organisation may instead provide an authenticated KMS/HSM adapter. Cloud KMS
is not mandatory. The adapter must keep key creation, activation and retirement
inside the protected provider and enforce the host's administrator authorization
for those operations.

Do not invent a UJANI root key, derive production keys from machine identifiers,
store keys beside snapshots, or silently fall back to a software test provider.
If the configured provider is unavailable, integrity-sensitive store operations
must fail closed.

## Rotation sequence

1. Provision a new key in protected custody.
2. Activate it for the selected purpose.
3. Continue verifying snapshots and backups signed by the previous key.
4. Rewrite and verify every retained snapshot and backup with the new key.
5. Confirm retention/backup policy no longer requires the old key.
6. Retire the old key through the provider's separately authorised operation.

The provider cannot infer whether an external backup still references an old key.
The host must enforce that precondition before retirement. Never retire a key
while an unverified backup or restore point may still need it.

## Security limits

This interface does not encrypt ledger contents, provide external anti-rollback,
or establish a root of trust by itself. HMAC integrity is distinct from
confidentiality; anti-rollback still requires the separately protected,
linearizable monotonic anchor described in
`EXTERNAL-SNAPSHOT-ANCHOR-CONTRACT.md`.

The in-memory provider exists only under unit tests and uses deterministic test
material. It must never be exposed in a production build.

## Required integration work

Before this can be considered a production key-custody implementation:

- define an explicit, audited migration procedure for snapshots created by
  the legacy raw-key constructors. A provider must already retain the old key ID
  to verify those snapshots; the interface deliberately has no key-export
  operation and does not silently import caller-supplied bytes;
- extend store-level tests to cover concurrent rotation, stale writers,
  retained-backup verification, key retirement and crash recovery. Current
  tests cover sequential rotation and fail-closed startup; the ledger additionally
  exercises provider-backed anchored backup recovery;
- implement at least one reviewed OS-protected local adapter and document
  platform-specific custody and access-control limits;
- add an optional customer KMS/HSM adapter boundary and integration tests;
- test crash/power-loss behavior during key rotation and backup replacement.

Provider calls are synchronous at this boundary. Each production adapter must
apply strict transport deadlines internally and fail closed; an explicit shared
cancellation/deadline context for key-provider calls remains future work.

Until those steps pass review and deployment testing, key custody remains
partially integrated and remote worker dispatch must remain disabled.
