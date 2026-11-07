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

## Security properties and limits

- The OS advisory lock coordinates cooperating processes using the same lock path. It is not a distributed lock service.
- The V2 snapshot is authenticated with HMAC-SHA256. The key is injected through LedgerIntegrityKey by the trusted caller and is not written to the ledger or its companion files. A writer who can modify the ledger directory but cannot access the external key cannot forge a valid snapshot. The key provider is not implemented by this crate: production callers must retrieve keys from an OS keyring, TPM-backed service or HSM and must not store them beside the ledger.
- The ledger is not encrypted at rest. Unix files created by the implementation request mode 0600, but parent-directory permissions, ownership and deployment ACLs remain the operator's responsibility. Windows ACLs must be provisioned by the host service.
- Lease-token hashes are safe only when the control plane supplies high-entropy 32-byte tokens from an OS CSPRNG and protects the raw token from workloads and logs.
- The ledger is single-host and file-backed. It does not provide replication, multi-node consensus, database transactions across services, or high availability.
- The 16 MiB ceiling is a fail-closed safety bound, not automatic compaction. Operators must provision retention/compaction before sustained approval and replay records approach the limit.
- A file checksum and OS file lock do not defend against a privileged local attacker, filesystem rollback, malicious storage administrator, or compromise of the service account.
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