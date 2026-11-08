# Durable reservation ledger — implementation boundary

## What is implemented

The Enterprise policy crate contains a local file-backed DurableLedger prototype. Each operation takes an OS advisory lock on a companion lock file, reloads the latest snapshot, applies one operation, and writes a checksummed snapshot through a same-directory temporary file and backup/rename recovery path.

The ledger currently supports:

- Capacity admission and reservation against the supplied device capacity and class policy.
- Opaque 256-bit lease capabilities. Callers must generate them with an OS cryptographically secure random generator. The raw capability is not persisted; only a domain-separated SHA-256 digest is stored.
- Lease renewal and release only when the caller supplies the matching capability.
- Expiry cleanup and an aggregate reservation snapshot.
- Durable, single-use dispatch challenge nonces used when signed worker telemetry and administrator scheduling policy are verified.
- A verified scheduling context bound to the exact device ID, workload ID, workload manifest digest and evidence expiry. The context is non-cloneable and reservation APIs consume it by value.
- A 16 MiB snapshot-size ceiling. Writes that would exceed the limit fail before replacing the last committed snapshot.

The implementation has unit tests for process-restart persistence, token-protected renewal/release, recovery from a corrupt current snapshot when a valid backup exists, cross-instance concurrent admission, challenge replay rejection, and signed-evidence binding.

## External monotonic anti-rollback mode

The ledger now also exposes `DurableLedger::open_with_anchor`, which accepts the same external `MonotonicSnapshotAnchor` contract used by the durable device-trust registry. The anchor must be a separate trust domain with durable, linearizable `load` and `compare_and_set` semantics. A load started after a completed compare-and-set must observe that record or a later generation; stale reads are not permitted. A file, SQLite table, or backup in the same writable host directory is not sufficient.

In anchored mode, each transaction:

1. Loads the anchor generation and SHA-256 digest before reading mutable ledger state.
2. Accepts the primary snapshot only when its digest matches the anchor; otherwise it may recover a backup only when that backup matches the same anchored digest.
3. Writes the candidate snapshot while retaining the previous committed snapshot as a rollback file.
4. Advances the external anchor by exactly one generation with compare-and-set.
5. Deletes the rollback file only after the anchor confirms the new digest. If the anchor rejects the generation, the local candidate is rolled back. Ambiguous anchor responses are read back before deciding whether to roll back.

If the compare-and-set response is lost and read-back also fails, the operation returns `AnchorUnavailable`; the commit outcome is unknown. This prototype has no durable per-operation outcome history. Therefore callers must hold a per-ledger cross-process operation coordinator from before any potentially ambiguous operation until recovery is complete; after `AnchorUnavailable`, no caller may start another ledger operation until the caller has reopened/reconciled the anchored snapshot and determined whether the prior operation committed. The ledger's OS lock serializes individual transactions, but does not span this caller-level reconciliation interval. The provider must settle or fence any in-flight update before returning an error so a late commit cannot occur after rollback.

Unanchored `open_with_integrity_keys` remains available for tests and local prototypes, but its HMAC still does **not** prevent rollback to an older valid snapshot. Existing unanchored files are rejected by `open_with_anchor`; migration requires a separately audited process that establishes the initial external anchor. The repository provides the contract and test adapter only—not a production KMS/control-plane anchor implementation. Each ledger and the device-trust registry must use a distinct `registry_id` when sharing an anchor provider; reusing an identifier causes their records to collide and produces `AnchorMismatch`.

The provider contract is synchronous. `load`, `compare_and_set`, and ambiguous-result read-back execute while the ledger holds both its in-process mutex and OS file lock, including for read-only snapshots. Providers must therefore enforce bounded timeouts. Every `load` is also a quiescence barrier: it must settle or fence all earlier in-flight compare-and-set requests for that namespace, including requests left pending by a crashed caller, before returning the current record. This prevents recovery from restoring an older snapshot while an earlier anchor update can still commit later. Before returning an error from `compare_and_set`, the provider must likewise settle or fence the request's in-flight update so it cannot commit after the ledger has rolled back its candidate snapshot. In anchored mode, the candidate snapshot file is flushed before the anchor advances, and the containing-directory rename must be made durable first. The ledger parent must already exist as a real directory and must not be group- or world-writable; anchored mode fails closed rather than creating a directory tree or operating in a directory where an untrusted principal could replace a restore file. Restore temporaries are created exclusively with restrictive permissions and symlink destinations are rejected. On Unix, opening an anchored ledger syncs each existing ancestor directory entry up to the filesystem root before the first snapshot can be anchored, then requires a parent-directory `fsync` after the snapshot rename, including `.` for a bare relative ledger path. Windows anchored writes currently fail closed before changing the snapshot or calling compare-and-set: this crate forbids unsafe code, and a reviewed safe Windows durable-rename adapter has not yet been added. Other unsupported platforms also fail closed. The unanchored prototype retains best-effort directory syncing.

## Security properties and limits

- The OS advisory lock coordinates cooperating processes using the same lock path. It is not a distributed lock service.
- The V2 snapshot is authenticated with HMAC-SHA256. The key is injected through LedgerIntegrityKey by the trusted caller and is not written to the ledger or its companion files. A writer who can modify the ledger directory but cannot access the external key cannot forge a valid snapshot. The key provider is not implemented by this crate: production callers must retrieve keys from an OS keyring, TPM-backed service or HSM and must not store them beside the ledger.
- The ledger is not encrypted at rest. Unix files created by the implementation request mode 0600, but parent-directory permissions, ownership and deployment ACLs remain the operator's responsibility. Windows ACLs must be provisioned by the host service.
- Lease-token hashes are safe only when the control plane supplies high-entropy 32-byte tokens from an OS CSPRNG and protects the raw token from workloads and logs.
- The ledger is single-host and file-backed. It does not provide replication, multi-node consensus, database transactions across services, or high availability.
- The 16 MiB ceiling is a fail-closed safety bound, not automatic compaction. Operators must provision retention/compaction before sustained approval and replay records approach the limit.
- A file checksum and OS file lock do not defend against a privileged local attacker, filesystem rollback, malicious storage administrator, or compromise of the service account. Only callers using `open_with_anchor` with a separately protected, linearizable anchor gain snapshot rollback detection; the unanchored API does not.
- Integrity-key rotation is supported by supplying the active key plus previous verification keys; the first successful transaction rewrites the snapshot with the active key. Operators must retain previous keys until snapshots and backups have been rewritten, then remove retired keys. The crate does not implement secure key provisioning, hardware-backed key storage, root-key custody or disaster recovery. Key lists and device capacity/class inventory used by signed-evidence verification must still be sourced from an authenticated, non-caller-controlled enrollment registry. This repository does not yet implement that registry, its root of trust, durable device enrollment/revocation or authenticated transport.
- Signed scheduling evidence verifies policy inputs; it does not create a sandbox, enforce network egress, or launch/authorize a remote process.

## Required before production

1. Replace or formally harden the file store for the intended deployment (for example, a transactional database with authenticated access, durable constraints, backups and tested recovery).
2. Add authenticated control-plane APIs and bind lease capabilities to an authenticated principal, workload, device and expiry at the service boundary.
3. Implement enrollment, key rotation/revocation, registry-root protection and trusted inventory provenance.
4. Integrate an OS keyring/TPM/HSM-backed integrity-key provider, document key rotation and recovery procedures, and add OS-specific directory ACL provisioning, encryption-at-rest policy, schema migrations and backup/restore drills.
5. Test crash/power-loss and concurrent access on every supported OS and filesystem; review advisory-lock semantics on network filesystems.
6. Complete receiver-side authorization, encrypted/authenticated transport, OS-enforced workload isolation, audit anchoring and independent security review.

This is a pre-alpha policy/storage foundation. It is not a production scheduler, fleet manager, remote execution service or security certification.