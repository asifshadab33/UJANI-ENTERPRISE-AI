# Protected integrity-key provider contract

## Status

The Enterprise policy crate now defines a host-owned `IntegrityKeyProvider`
interface in `integrity_key_provider.rs`. It is a contract and test seam only.
It is **not yet wired into** `DurableDeviceRegistry` or `DurableLedger`, and
there is no production OS-keyring, TPM, KMS or HSM adapter in this repository.

Existing durable-store constructors still accept caller-supplied key bytes
through `DeviceTrustIntegrityKey` and `LedgerIntegrityKey`. Those paths remain
for the current prototype and tests; they must not be treated as a completed
production custody design.

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

- wire both durable stores to this provider without exporting raw key bytes;
- add a versioned snapshot migration path that verifies legacy MACs and writes
  the new provider-backed format without losing rollback/backup guarantees;
- add provider contract tests for unavailable providers, concurrent rotation,
  stale writers, retained-backup verification, key retirement and recovery;
- implement at least one reviewed OS-protected local adapter and document
  platform-specific custody and access-control limits;
- add an optional customer KMS/HSM adapter boundary and integration tests;
- test crash/power-loss behavior during key rotation and backup replacement.

Until those steps pass review and deployment testing, the current key handling
remains a prototype boundary and remote worker dispatch must remain disabled.
