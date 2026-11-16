# Enterprise key custody and encrypted snapshot architecture

## Decision

UJANI Enterprise supports **both** customer-controlled local/on-premises key custody and optional cloud-managed key custody. Neither option is mandatory. The organisation chooses the provider and deployment boundary; UJANI must not silently move key custody or sensitive data to another provider.

## Data protected

The provider-backed persistence boundary covers at least:

- Durable reservation-ledger state, including lease revisions, telemetry replay state and reservation watermarks.
- Durable device-trust registry state.
- Future policy and execution receipts when those records are persisted by the Enterprise service.

Prompts, document contents, model weights and task payloads are not sent to a KMS merely to encrypt a ledger. A cloud KMS integration should receive only the minimum key-wrapping or cryptographic operation required by its provider protocol.

## Supported custody models

### Local and on-premises

A production host adapter may use the operating system's protected credential facilities, for example:

- Windows DPAPI / Credential Manager.
- macOS Keychain.
- Linux Secret Service or an organisation-managed keyring.
- TPM-backed keys or a customer-managed HSM where available.

The key provider must not write plaintext key material to ordinary application files, configuration, logs or crash reports. A keyring-backed implementation may retrieve a secret into the trusted process for cryptographic use; that is OS-protected at rest, but it must not be described as hardware non-exportable unless the selected TPM/HSM actually provides that property.

### Cloud-managed

A customer may choose an approved KMS/HSM service such as AWS KMS or Azure Key Vault, or an on-premises KMS/HSM with a compatible adapter. Cloud custody is optional and must be configured by the organisation.

For large snapshots, the adapter should use envelope encryption: a fresh data-encryption key seals the snapshot with a vetted AEAD algorithm, while the customer KMS protects the data key. The provider returns an opaque envelope containing the key version, wrapped data key, nonce, ciphertext and authentication tag. The policy crate does not need a vendor SDK and must not depend on a particular cloud.

## Provider contract

The existing `IntegrityKeyProvider` remains the common abstraction. It supports purpose-scoped integrity operations and now defines fail-closed `seal_active` / `open_sealed` operations for authenticated encryption.

Production adapters must:

1. Use a vetted AEAD construction; never implement a custom production cipher.
2. Keep encryption and MAC key material cryptographically separated, even if they share a logical key identifier.
3. Bind snapshot format/version, key purpose, key identifier and caller-provided context as AEAD associated data.
4. Generate a unique nonce for every encryption under a key.
5. Support decryption with retained previous key versions during rotation.
6. Fail closed on missing, revoked, unavailable or unverifiable keys.
7. Bound payload sizes and avoid logging plaintext, keys or sensitive metadata.
8. Define customer-controlled backup, recovery, revocation and retirement procedures.

The shared envelope helper binds the format header, purpose and caller context. The provider implementation must additionally bind the selected key identifier inside its authenticated-encryption operation.

## Snapshot and rollback model

Provider-backed ledger and device-trust snapshots use a versioned encrypted envelope around the existing HMAC-authenticated payload. This provides confidentiality at rest and retains the existing integrity check as defence in depth.

Encryption does **not** prevent restoration of an older, valid encrypted snapshot. Filesystem anti-rollback still requires the separate monotonic anchor (for example, TPM-backed state or customer-controlled append-only storage) and fail-closed recovery rules. A hash chain stored only beside the snapshot is not an independent anchor.

## Rotation and recovery

- New snapshots use the active key version.
- Previously written snapshots remain decryptable only while their key versions are retained.
- Rotation must re-encrypt and verify snapshots before retiring old key versions.
- Recovery must verify both the encrypted snapshot and its independent monotonic anchor.
- Missing keys, an anchor rollback or an unverifiable restore must not trigger an automatic empty-ledger reset.
- Legacy HMAC-only snapshots require an explicit, audited migration path; they must not be silently treated as encrypted.

## Current implementation status

- The provider abstraction and versioned encrypted snapshot envelope are being added for the durable reservation ledger and device-trust registry.
- The in-repository provider used by unit tests is deliberately test-only and is **not cryptography**.
- UJANI does not yet ship production Windows, macOS, Linux, TPM, KMS or HSM adapters. Therefore no production deployment should yet be described as having completed encryption-at-rest support.
- The legacy host-injected-key path remains HMAC-only and is not suitable for production storage of sensitive records.
- Production adapters, explicit legacy migration, recovery drills, anti-rollback validation and independent security review remain release gates.

## Required validation before production use

- Round-trip encrypt/decrypt tests for both ledger and device-trust snapshots.
- Tampering tests for ciphertext, nonce, tag, header, purpose, key identifier and associated data.
- Key rotation tests with old-key retention and safe retirement.
- Provider unavailable / revoked / missing-key fail-closed tests.
- Backup restore and monotonic-anchor rollback tests.
- Platform tests on Windows, macOS and Linux for local custody.
- Customer-environment tests for cloud KMS/HSM custody, IAM scope, rate limits, outages and recovery.
- Independent security review of the adapter and persistence lifecycle.
