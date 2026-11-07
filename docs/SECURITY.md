# Security Policy

## Status

UJANI Enterprise AI is pre-alpha. Do not deploy it to production infrastructure or employee endpoints. The current code is illustrative policy logic, not an enforcement system.

## Reporting

Please do not publish exploitable details in a public issue. Use GitHub private vulnerability reporting if enabled, or a verified private maintainer contact.

Include affected commit, environment, impact, safe reproduction steps and suggested mitigation.

## Required controls before production

- Explicit device enrolment, strong identity, key rotation and revocation.
- Mutual authentication and signed workload assignments.
- OS-enforced workload isolation and least privilege.
- Strict network egress, filesystem and resource limits.
- Tenant/workspace isolation and data classification.
- No silent employee-device participation.
- Admin policy, user-visible status and audit trail.
- Signed agent updates, dependency provenance and rollback.
- Incident response and independent penetration testing.

## Current policy-library additions and their limits

The current policy branch includes a local file-backed reservation ledger. Transactions reload the latest snapshot while holding an OS advisory file lock, use same-directory temporary/backup files for recovery, and persist only domain-separated hashes of 256-bit lease capabilities. Lease renewal and release require the matching capability. Signed worker telemetry and administrator scheduling evidence are bound to a device, workload ID, manifest digest, freshness window and a durable one-time dispatch challenge. The verified context is non-cloneable and re-checks those bindings at admission.

These are library-level controls only. The durable ledger now uses a V2 HMAC-SHA256 snapshot whose key is injected by a trusted caller and must live outside the writable ledger directory. The crate supports key rotation by verifying with previous keys and writing with an active key, but does not itself retrieve or protect keys in an OS keyring, TPM or HSM. V1 checksum-only snapshots are rejected. The ledger is not encrypted at rest. File access control depends on the parent directory and OS account. The ledger is single-host and file-backed, not a replicated database or a distributed transaction service. The signing-key lists and device capacity/inventory passed into verification must come from a trusted enrollment registry; this repository does not yet implement that registry, its root of trust, durable key revocation, authenticated transport or receiver-side execution. A signed policy decision does not itself create an OS sandbox.

A policy decision in application code is not a substitute for OS-enforced security. Do not describe the platform as secure or compliant until controls are implemented and independently assessed.
