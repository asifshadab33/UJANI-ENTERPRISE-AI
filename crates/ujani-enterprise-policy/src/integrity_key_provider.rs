//! Protected integrity-key provider boundary for durable Enterprise state.
//!
//! This module defines operations over protected integrity and encryption keys.
//! It deliberately does not provide a production key store: hosts must supply an
//! OS-protected provider or an organisation-managed KMS/HSM adapter.

use std::fmt;

/// Separates key namespaces even when an installation reuses a human-readable ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityKeyPurpose {
    /// Authenticates the durable enrolled-device registry.
    DeviceTrustRegistry,
    /// Authenticates durable reservations, leases and replay state.
    ReservationLedger,
}

impl IntegrityKeyPurpose {
    /// Stable provider namespace. Do not change these values after deployment.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceTrustRegistry => "device-trust-registry",
            Self::ReservationLedger => "reservation-ledger",
        }
    }
}

/// Fail-closed errors returned by a protected integrity-key provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityKeyProviderError {
    InvalidKeyId,
    KeyAlreadyExists,
    UnknownKey,
    ActiveKeyCannotBeRetired,
    VerificationFailed,
    EncryptionUnavailable,
    EncryptionFailed,
    Unavailable,
    LockPoisoned,
}

impl fmt::Display for IntegrityKeyProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidKeyId => "integrity key identifier is invalid",
            Self::KeyAlreadyExists => "integrity key identifier already exists",
            Self::UnknownKey => "integrity key is unavailable",
            Self::ActiveKeyCannotBeRetired => "active integrity key cannot be retired",
            Self::VerificationFailed => "integrity authentication failed",
            Self::EncryptionUnavailable => "AEAD is not supported by this key provider",
            Self::EncryptionFailed => "authenticated encryption or decryption failed",
            Self::Unavailable => "integrity key provider is unavailable",
            Self::LockPoisoned => "integrity key provider state is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for IntegrityKeyProviderError {}

/// Host-owned interface for non-exportable integrity keys.
///
/// Implementations must:
/// - generate key material inside the protected provider during provisioning;
/// - never return raw key material to callers;
/// - sign only with the currently active key for the requested purpose;
/// - verify with the named active or retained previous key, using a
///   constant-time MAC verification operation;
/// - encrypt snapshots with vetted authenticated encryption (AEAD), never a
///   home-grown production cipher; bind format, purpose, key ID and caller AAD;
/// - decrypt only with the named active or retained previous encryption key;
/// - generate a unique nonce for every encryption under a key and fail closed
///   on nonce-generation, provider or authentication errors;
/// - keep integrity and encryption key material cryptographically separated,
///   even when they share a logical key ID;
/// - keep key identifiers immutable and never reuse a retired identifier;
/// - enforce bounded provider I/O and fail closed on timeout or outage;
/// - isolate purposes so a key for one store cannot authenticate another.
///
/// Rotation is staged: provision a new key, activate it, keep the previous key
/// available for verification while snapshots and backups are rewritten, then
/// retire the previous key only after the host has verified that no retained
/// state references it. Provision/activate/retire must be authorised by the
/// host's administrator policy; this trait is not an operator authorization API.
pub trait IntegrityKeyProvider: Send + Sync {
    /// Provision a new key inside protected custody. No secret bytes are returned.
    fn provision_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError>;

    /// Atomically make a previously provisioned key the active signing key.
    fn activate_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError>;

    /// Sign with the active key and return its non-secret identifier with the MAC.
    fn sign_active(
        &self,
        purpose: IntegrityKeyPurpose,
        payload: &[u8],
    ) -> Result<(String, [u8; 32]), IntegrityKeyProviderError>;

    /// Verify a stored MAC using the named active or retained previous key.
    fn verify(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
        payload: &[u8],
        tag: &[u8; 32],
    ) -> Result<(), IntegrityKeyProviderError>;

    /// Encrypt a snapshot using the active protected key. Implementations must
    /// use a vetted AEAD construction and return an opaque nonce+ciphertext+tag
    /// envelope; raw key material must never leave the provider.
    ///
    /// The supplied AAD binds the snapshot format and key purpose. Implementations
    /// must additionally bind the selected key ID internally. The default keeps
    /// older adapters fail-closed until they implement authenticated encryption.
    fn seal_active(
        &self,
        _purpose: IntegrityKeyPurpose,
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<(String, Vec<u8>), IntegrityKeyProviderError> {
        Err(IntegrityKeyProviderError::EncryptionUnavailable)
    }

    /// Decrypt and authenticate an opaque envelope using the named active or
    /// retained key. Implementations must authenticate AAD and key ID before
    /// returning plaintext, and must not return unauthenticated partial data.
    fn open_sealed(
        &self,
        _purpose: IntegrityKeyPurpose,
        _key_id: &str,
        _aad: &[u8],
        _sealed: &[u8],
    ) -> Result<Vec<u8>, IntegrityKeyProviderError> {
        Err(IntegrityKeyProviderError::EncryptionUnavailable)
    }

    /// Retire a non-active key after all snapshots and retained backups are migrated.
    fn retire_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError>;
}

/// Wrap authenticated ciphertext in a versioned, binary-safe snapshot envelope.
/// The provider binds the selected key ID internally; this wrapper binds the
/// version header and purpose through AEAD associated data.
pub fn seal_snapshot(
    provider: &dyn IntegrityKeyProvider,
    purpose: IntegrityKeyPurpose,
    header: &str,
    caller_aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, IntegrityKeyProviderError> {
    if header.is_empty()
        || header.len() > 128
        || header.bytes().any(|byte| byte == b'\n' || byte == b'\r')
    {
        return Err(IntegrityKeyProviderError::InvalidKeyId);
    }
    let mut aad = Vec::with_capacity(header.len() + caller_aad.len() + 32);
    aad.extend_from_slice(header.as_bytes());
    aad.push(0);
    aad.extend_from_slice(purpose.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(caller_aad);
    let (key_id, sealed) = provider.seal_active(purpose, &aad, plaintext)?;
    if !valid_integrity_key_id(&key_id) || sealed.is_empty() {
        return Err(IntegrityKeyProviderError::EncryptionFailed);
    }
    let mut output = Vec::with_capacity(header.len() + key_id.len() + sealed.len() + 2);
    output.extend_from_slice(header.as_bytes());
    output.push(b'\n');
    output.extend_from_slice(key_id.as_bytes());
    output.push(b'\n');
    output.extend_from_slice(&sealed);
    Ok(output)
}

/// Return the non-secret key identifier in a versioned encrypted snapshot.
pub fn encrypted_snapshot_key_id(
    expected_header: &str,
    bytes: &[u8],
) -> Result<String, IntegrityKeyProviderError> {
    let header_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(IntegrityKeyProviderError::EncryptionFailed)?;
    if &bytes[..header_end] != expected_header.as_bytes() {
        return Err(IntegrityKeyProviderError::EncryptionFailed);
    }
    let remainder = &bytes[header_end + 1..];
    let key_end = remainder
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(IntegrityKeyProviderError::EncryptionFailed)?;
    let key_id = std::str::from_utf8(&remainder[..key_end])
        .map_err(|_| IntegrityKeyProviderError::InvalidKeyId)?;
    if !valid_integrity_key_id(key_id) || key_end + 1 >= remainder.len() {
        return Err(IntegrityKeyProviderError::EncryptionFailed);
    }
    Ok(key_id.to_string())
}

/// Open a versioned encrypted snapshot. Plaintext legacy snapshots are not
/// accepted through this provider-backed path; migration must be explicit.
pub fn open_snapshot(
    provider: &dyn IntegrityKeyProvider,
    purpose: IntegrityKeyPurpose,
    expected_header: &str,
    caller_aad: &[u8],
    bytes: &[u8],
) -> Result<Vec<u8>, IntegrityKeyProviderError> {
    let header_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(IntegrityKeyProviderError::EncryptionFailed)?;
    if &bytes[..header_end] != expected_header.as_bytes() {
        return Err(IntegrityKeyProviderError::EncryptionFailed);
    }
    let remainder = &bytes[header_end + 1..];
    let key_end = remainder
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(IntegrityKeyProviderError::EncryptionFailed)?;
    let key_id = std::str::from_utf8(&remainder[..key_end])
        .map_err(|_| IntegrityKeyProviderError::InvalidKeyId)?;
    if !valid_integrity_key_id(key_id) || key_end + 1 >= remainder.len() {
        return Err(IntegrityKeyProviderError::EncryptionFailed);
    }
    let sealed = &remainder[key_end + 1..];
    let mut aad = Vec::with_capacity(expected_header.len() + caller_aad.len() + 32);
    aad.extend_from_slice(expected_header.as_bytes());
    aad.push(0);
    aad.extend_from_slice(purpose.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(caller_aad);
    provider.open_sealed(purpose, key_id, &aad, sealed)
}

/// Validate the bounded, non-secret identifier stored alongside a snapshot MAC.
pub fn valid_integrity_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
pub(crate) use tests::TestIntegrityKeyProvider;

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zeroize::Zeroize;

    const TEST_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-TEST-INTEGRITY-MAC-V1\0";

    #[derive(Default)]
    struct TestState {
        keys: HashMap<(IntegrityKeyPurpose, String), [u8; 32]>,
        active: HashMap<IntegrityKeyPurpose, String>,
        retired: std::collections::HashSet<(IntegrityKeyPurpose, String)>,
        nonce_counter: u64,
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            for key in self.keys.values_mut() {
                key.zeroize();
            }
        }
    }

    /// Deterministic in-memory provider for contract tests only. Never use in production.
    #[derive(Default)]
    pub(crate) struct TestIntegrityKeyProvider(Mutex<TestState>);

    impl IntegrityKeyProvider for TestIntegrityKeyProvider {
        fn provision_key(
            &self,
            purpose: IntegrityKeyPurpose,
            key_id: &str,
        ) -> Result<(), IntegrityKeyProviderError> {
            if !valid_integrity_key_id(key_id) {
                return Err(IntegrityKeyProviderError::InvalidKeyId);
            }
            let mut state = self
                .0
                .lock()
                .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
            let map_key = (purpose, key_id.to_string());
            if state.retired.contains(&map_key) {
                return Err(IntegrityKeyProviderError::KeyAlreadyExists);
            }
            let seed = format!("test-only:{}:{key_id}", purpose.as_str());
            let key: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
            match state.keys.entry(map_key) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    Err(IntegrityKeyProviderError::KeyAlreadyExists)
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(key);
                    Ok(())
                }
            }
        }

        fn activate_key(
            &self,
            purpose: IntegrityKeyPurpose,
            key_id: &str,
        ) -> Result<(), IntegrityKeyProviderError> {
            let mut state = self
                .0
                .lock()
                .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
            if !state.keys.contains_key(&(purpose, key_id.to_string())) {
                return Err(IntegrityKeyProviderError::UnknownKey);
            }
            state.active.insert(purpose, key_id.to_string());
            Ok(())
        }

        fn sign_active(
            &self,
            purpose: IntegrityKeyPurpose,
            payload: &[u8],
        ) -> Result<(String, [u8; 32]), IntegrityKeyProviderError> {
            let (key_id, mut key) = {
                let state = self
                    .0
                    .lock()
                    .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
                let key_id = state
                    .active
                    .get(&purpose)
                    .cloned()
                    .ok_or(IntegrityKeyProviderError::UnknownKey)?;
                let key = state
                    .keys
                    .get(&(purpose, key_id.clone()))
                    .copied()
                    .ok_or(IntegrityKeyProviderError::UnknownKey)?;
                (key_id, key)
            };
            let tag = test_mac(&key, purpose, &key_id, payload);
            key.zeroize();
            Ok((key_id, tag))
        }

        fn verify(
            &self,
            purpose: IntegrityKeyPurpose,
            key_id: &str,
            payload: &[u8],
            tag: &[u8; 32],
        ) -> Result<(), IntegrityKeyProviderError> {
            let mut key = {
                let state = self
                    .0
                    .lock()
                    .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
                state
                    .keys
                    .get(&(purpose, key_id.to_string()))
                    .copied()
                    .ok_or(IntegrityKeyProviderError::UnknownKey)?
            };
            let result = verify_test_mac(&key, purpose, key_id, payload, tag);
            key.zeroize();
            result
        }

        fn seal_active(
            &self,
            purpose: IntegrityKeyPurpose,
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<(String, Vec<u8>), IntegrityKeyProviderError> {
            let (key_id, mut key, counter) = {
                let mut state = self
                    .0
                    .lock()
                    .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
                let key_id = state
                    .active
                    .get(&purpose)
                    .cloned()
                    .ok_or(IntegrityKeyProviderError::UnknownKey)?;
                let key = state
                    .keys
                    .get(&(purpose, key_id.clone()))
                    .copied()
                    .ok_or(IntegrityKeyProviderError::UnknownKey)?;
                state.nonce_counter = state
                    .nonce_counter
                    .checked_add(1)
                    .ok_or(IntegrityKeyProviderError::EncryptionFailed)?;
                (key_id, key, state.nonce_counter)
            };
            // Test-only reversible transform to exercise provider plumbing. It is
            // not a cryptographic construction and must never ship outside cfg(test).
            let nonce_material = format!("test-only:{counter}:{}:{key_id}", purpose.as_str());
            let nonce_hash = Sha256::digest(nonce_material.as_bytes());
            let nonce: [u8; 16] = nonce_hash[..16]
                .try_into()
                .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
            let mut encryption_key = test_encryption_key(&key, purpose);
            let encrypted = test_stream_xor(&encryption_key, &nonce, plaintext);
            let tag = test_sealed_tag(&encryption_key, purpose, &key_id, aad, &nonce, &encrypted);
            let mut sealed = Vec::with_capacity(16 + encrypted.len() + 32);
            sealed.extend_from_slice(&nonce);
            sealed.extend_from_slice(&encrypted);
            sealed.extend_from_slice(&tag);
            key.zeroize();
            encryption_key.zeroize();
            Ok((key_id, sealed))
        }

        fn open_sealed(
            &self,
            purpose: IntegrityKeyPurpose,
            key_id: &str,
            aad: &[u8],
            sealed: &[u8],
        ) -> Result<Vec<u8>, IntegrityKeyProviderError> {
            if sealed.len() < 48 {
                return Err(IntegrityKeyProviderError::EncryptionFailed);
            }
            let mut key = {
                let state = self
                    .0
                    .lock()
                    .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
                state
                    .keys
                    .get(&(purpose, key_id.to_string()))
                    .copied()
                    .ok_or(IntegrityKeyProviderError::UnknownKey)?
            };
            let nonce: [u8; 16] = sealed[..16]
                .try_into()
                .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
            let ciphertext = &sealed[16..sealed.len() - 32];
            let tag: [u8; 32] = sealed[sealed.len() - 32..]
                .try_into()
                .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
            let mut encryption_key = test_encryption_key(&key, purpose);
            let expected =
                test_sealed_tag(&encryption_key, purpose, key_id, aad, &nonce, ciphertext);
            if expected != tag {
                key.zeroize();
                encryption_key.zeroize();
                return Err(IntegrityKeyProviderError::VerificationFailed);
            }
            let plaintext = test_stream_xor(&encryption_key, &nonce, ciphertext);
            key.zeroize();
            encryption_key.zeroize();
            Ok(plaintext)
        }

        fn retire_key(
            &self,
            purpose: IntegrityKeyPurpose,
            key_id: &str,
        ) -> Result<(), IntegrityKeyProviderError> {
            let mut state = self
                .0
                .lock()
                .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
            if state
                .active
                .get(&purpose)
                .is_some_and(|active| active == key_id)
            {
                return Err(IntegrityKeyProviderError::ActiveKeyCannotBeRetired);
            }
            let retired_id = (purpose, key_id.to_string());
            let mut key = state
                .keys
                .remove(&retired_id)
                .ok_or(IntegrityKeyProviderError::UnknownKey)?;
            key.zeroize();
            state.retired.insert(retired_id);
            Ok(())
        }
    }

    fn test_mac(
        key: &[u8; 32],
        purpose: IntegrityKeyPurpose,
        key_id: &str,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("32-byte test key");
        mac.update(TEST_DOMAIN);
        mac.update(&(purpose.as_str().len() as u32).to_be_bytes());
        mac.update(purpose.as_str().as_bytes());
        mac.update(&(key_id.len() as u32).to_be_bytes());
        mac.update(key_id.as_bytes());
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }

    fn test_encryption_key(key: &[u8; 32], purpose: IntegrityKeyPurpose) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"UJANI-TEST-ENCRYPTION-SUBKEY-V1\0");
        digest.update(purpose.as_str().as_bytes());
        digest.update(key);
        digest.finalize().into()
    }

    fn test_stream_xor(key: &[u8; 32], nonce: &[u8; 16], input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        for (index, chunk) in input.chunks(32).enumerate() {
            let mut digest = Sha256::new();
            digest.update(b"UJANI-TEST-STREAM-V1\0");
            digest.update(key);
            digest.update(nonce);
            digest.update((index as u64).to_be_bytes());
            let stream = digest.finalize();
            output.extend(
                chunk
                    .iter()
                    .zip(stream.iter())
                    .map(|(left, right)| *left ^ *right),
            );
        }
        output
    }

    fn test_sealed_tag(
        key: &[u8; 32],
        purpose: IntegrityKeyPurpose,
        key_id: &str,
        aad: &[u8],
        nonce: &[u8; 16],
        ciphertext: &[u8],
    ) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("32-byte test encryption key");
        mac.update(b"UJANI-TEST-SEALED-SNAPSHOT-V1\0");
        mac.update(purpose.as_str().as_bytes());
        mac.update(&(key_id.len() as u32).to_be_bytes());
        mac.update(key_id.as_bytes());
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad);
        mac.update(nonce);
        mac.update(ciphertext);
        mac.finalize().into_bytes().into()
    }

    fn verify_test_mac(
        key: &[u8; 32],
        purpose: IntegrityKeyPurpose,
        key_id: &str,
        payload: &[u8],
        tag: &[u8; 32],
    ) -> Result<(), IntegrityKeyProviderError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| IntegrityKeyProviderError::VerificationFailed)?;
        mac.update(TEST_DOMAIN);
        mac.update(&(purpose.as_str().len() as u32).to_be_bytes());
        mac.update(purpose.as_str().as_bytes());
        mac.update(&(key_id.len() as u32).to_be_bytes());
        mac.update(key_id.as_bytes());
        mac.update(payload);
        mac.verify_slice(tag)
            .map_err(|_| IntegrityKeyProviderError::VerificationFailed)
    }

    #[test]
    fn sealed_snapshots_round_trip_and_authenticate_context_and_payload() {
        let provider = TestIntegrityKeyProvider::default();
        let purpose = IntegrityKeyPurpose::ReservationLedger;
        provider.provision_key(purpose, "ledger-v1").unwrap();
        provider.activate_key(purpose, "ledger-v1").unwrap();
        let original = b"synthetic reservation snapshot";
        let sealed = seal_snapshot(
            &provider,
            purpose,
            "UJANI-TEST-ENCRYPTED-V1",
            b"test-context",
            original,
        )
        .unwrap();
        assert!(!sealed
            .windows(original.len())
            .any(|window| window == original));
        assert_eq!(
            open_snapshot(
                &provider,
                purpose,
                "UJANI-TEST-ENCRYPTED-V1",
                b"test-context",
                &sealed,
            )
            .unwrap(),
            original
        );
        assert!(open_snapshot(
            &provider,
            purpose,
            "UJANI-OTHER-HEADER-V1",
            b"test-context",
            &sealed,
        )
        .is_err());
        assert!(open_snapshot(
            &provider,
            purpose,
            "UJANI-TEST-ENCRYPTED-V1",
            b"other-context",
            &sealed,
        )
        .is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_snapshot(
            &provider,
            purpose,
            "UJANI-TEST-ENCRYPTED-V1",
            b"test-context",
            &tampered,
        )
        .is_err());
    }

    #[test]
    fn rotation_keeps_previous_key_available_for_verification() {
        let provider = TestIntegrityKeyProvider::default();
        let purpose = IntegrityKeyPurpose::ReservationLedger;
        provider.provision_key(purpose, "ledger-v1").unwrap();
        provider.activate_key(purpose, "ledger-v1").unwrap();

        let payload = b"committed snapshot v1";
        let (old_id, old_tag) = provider.sign_active(purpose, payload).unwrap();
        assert_eq!(old_id, "ledger-v1");
        provider
            .verify(purpose, &old_id, payload, &old_tag)
            .unwrap();

        provider.provision_key(purpose, "ledger-v2").unwrap();
        provider.activate_key(purpose, "ledger-v2").unwrap();
        let (new_id, new_tag) = provider.sign_active(purpose, b"snapshot v2").unwrap();
        assert_eq!(new_id, "ledger-v2");

        // Existing snapshots remain verifiable until the host has migrated backups.
        provider
            .verify(purpose, &old_id, payload, &old_tag)
            .unwrap();
        provider
            .verify(purpose, &new_id, b"snapshot v2", &new_tag)
            .unwrap();
        assert_eq!(
            provider.retire_key(purpose, "ledger-v2"),
            Err(IntegrityKeyProviderError::ActiveKeyCannotBeRetired)
        );

        provider.retire_key(purpose, "ledger-v1").unwrap();
        assert_eq!(
            provider.verify(purpose, &old_id, payload, &old_tag),
            Err(IntegrityKeyProviderError::UnknownKey)
        );
        assert_eq!(
            provider.provision_key(purpose, "ledger-v1"),
            Err(IntegrityKeyProviderError::KeyAlreadyExists)
        );
    }

    #[test]
    fn integrity_purposes_are_cryptographically_separated() {
        let provider = TestIntegrityKeyProvider::default();
        provider
            .provision_key(IntegrityKeyPurpose::DeviceTrustRegistry, "shared-id")
            .unwrap();
        provider
            .provision_key(IntegrityKeyPurpose::ReservationLedger, "shared-id")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::DeviceTrustRegistry, "shared-id")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::ReservationLedger, "shared-id")
            .unwrap();

        let (id, tag) = provider
            .sign_active(IntegrityKeyPurpose::DeviceTrustRegistry, b"state")
            .unwrap();
        assert_eq!(id, "shared-id");
        assert_eq!(
            provider.verify(IntegrityKeyPurpose::ReservationLedger, &id, b"state", &tag),
            Err(IntegrityKeyProviderError::VerificationFailed)
        );
    }

    #[test]
    fn invalid_identifiers_and_duplicate_provisioning_fail_closed() {
        let provider = TestIntegrityKeyProvider::default();
        let purpose = IntegrityKeyPurpose::DeviceTrustRegistry;
        assert!(!valid_integrity_key_id("../outside"));
        assert!(!valid_integrity_key_id(""));
        assert!(!valid_integrity_key_id(&"x".repeat(129)));
        assert_eq!(
            provider.provision_key(purpose, "../outside"),
            Err(IntegrityKeyProviderError::InvalidKeyId)
        );
        provider.provision_key(purpose, "device-v1").unwrap();
        assert_eq!(
            provider.provision_key(purpose, "device-v1"),
            Err(IntegrityKeyProviderError::KeyAlreadyExists)
        );
    }
}
