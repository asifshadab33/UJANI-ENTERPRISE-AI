//! Protected integrity-key provider boundary for durable Enterprise state.
//!
//! This module defines operations over non-exportable MAC keys. It deliberately
//! does not provide a production key store: hosts must supply an OS-protected
//! provider or an organisation-managed KMS/HSM adapter.

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

    /// Retire a non-active key after all snapshots and retained backups are migrated.
    fn retire_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError>;
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

#[cfg(test)]
pub(crate) use tests::TestIntegrityKeyProvider;
