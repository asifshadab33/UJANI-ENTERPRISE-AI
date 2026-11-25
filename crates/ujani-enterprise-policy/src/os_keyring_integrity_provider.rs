//! OS-native protected key custody for Enterprise durable state.
//!
//! Production adapter for the existing `IntegrityKeyProvider` contract. Secrets
//! are stored in the platform credential manager (Windows Credential Manager,
//! macOS Keychain, or Linux Secret Service). The adapter never falls back to a
//! plaintext file or environment variable. A headless Linux service must have a
//! persistent Secret Service available to its service account; otherwise startup
//! and all key operations fail closed.
//!
//! This is OS-protected custody, not an HSM/KMS or an external anti-rollback
//! anchor. High-assurance deployments should inject a customer KMS/HSM provider.
//! Provision/activate/retire must be performed by one trusted administrative
//! process at a time; the platform credential API does not expose a portable
//! cross-process create-if-absent transaction.

use crate::integrity_key_provider::{
    valid_integrity_key_id, IntegrityKeyProvider, IntegrityKeyProviderError,
    IntegrityKeyPurpose,
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const SERVICE_NAME: &str = "org.ujani.enterprise.integrity";
const KEY_MATERIAL_BYTES: usize = 64;
const MAC_KEY_RANGE: std::ops::Range<usize> = 0..32;
const AEAD_KEY_RANGE: std::ops::Range<usize> = 32..64;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_NONCE_BYTES: usize = 12;
const MIN_ENVELOPE_BYTES: usize = 1 + ENVELOPE_NONCE_BYTES + 16;
const MAC_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-INTEGRITY-MAC-V1\\0";
const AEAD_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-INTEGRITY-AEAD-V1\\0";

/// Minimal storage abstraction so lifecycle and cryptographic behavior can be
/// tested without accessing a developer's real OS credential store.
pub trait ProtectedSecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, IntegrityKeyProviderError>;
    fn put(&self, name: &str, value: &[u8]) -> Result<(), IntegrityKeyProviderError>;
    fn delete(&self, name: &str) -> Result<(), IntegrityKeyProviderError>;
}

/// Platform-native credential-manager implementation. Errors, locked stores,
/// missing Linux Secret Service sessions and unsupported providers are surfaced;
/// there is deliberately no disk or environment-variable fallback.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeyringSecretStore;

impl ProtectedSecretStore for OsKeyringSecretStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, IntegrityKeyProviderError> {
        let entry = keyring::Entry::new(SERVICE_NAME, name)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        match entry.get_secret() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(IntegrityKeyProviderError::Unavailable),
        }
    }

    fn put(&self, name: &str, value: &[u8]) -> Result<(), IntegrityKeyProviderError> {
        let entry = keyring::Entry::new(SERVICE_NAME, name)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        entry
            .set_secret(value)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)
    }

    fn delete(&self, name: &str) -> Result<(), IntegrityKeyProviderError> {
        let entry = keyring::Entry::new(SERVICE_NAME, name)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(IntegrityKeyProviderError::Unavailable),
        }
    }
}

/// Protected provider backed by a platform credential manager or an injected
/// protected secret store. MAC and AEAD use separate 256-bit subkeys.
pub struct KeyringIntegrityKeyProvider<S = OsKeyringSecretStore> {
    store: S,
    operation_lock: Mutex<()>,
}

impl<S> std::fmt::Debug for KeyringIntegrityKeyProvider<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyringIntegrityKeyProvider")
            .field("store", &"[protected]")
            .finish()
    }
}

impl Default for KeyringIntegrityKeyProvider<OsKeyringSecretStore> {
    fn default() -> Self {
        Self::new(OsKeyringSecretStore)
    }
}

impl<S: ProtectedSecretStore> KeyringIntegrityKeyProvider<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            operation_lock: Mutex::new(()),
        }
    }

    fn key_name(purpose: IntegrityKeyPurpose, key_id: &str) -> String {
        format!("v1:key:{}:{key_id}", purpose.as_str())
    }

    fn active_name(purpose: IntegrityKeyPurpose) -> String {
        format!("v1:active:{}", purpose.as_str())
    }

    fn retired_name(purpose: IntegrityKeyPurpose, key_id: &str) -> String {
        format!("v1:retired:{}:{key_id}", purpose.as_str())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, IntegrityKeyProviderError> {
        self.operation_lock
            .lock()
            .map_err(|_| IntegrityKeyProviderError::LockPoisoned)
    }

    fn is_retired(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<bool, IntegrityKeyProviderError> {
        Ok(self
            .store
            .get(&Self::retired_name(purpose, key_id))?
            .is_some())
    }

    fn read_material(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<Zeroizing<[u8; KEY_MATERIAL_BYTES]>, IntegrityKeyProviderError> {
        if !valid_integrity_key_id(key_id) {
            return Err(IntegrityKeyProviderError::InvalidKeyId);
        }
        if self.is_retired(purpose, key_id)? {
            return Err(IntegrityKeyProviderError::UnknownKey);
        }
        let mut stored = self
            .store
            .get(&Self::key_name(purpose, key_id))?
            .ok_or(IntegrityKeyProviderError::UnknownKey)?;
        if stored.len() != KEY_MATERIAL_BYTES {
            stored.zeroize();
            return Err(IntegrityKeyProviderError::Unavailable);
        }
        let mut material = Zeroizing::new([0u8; KEY_MATERIAL_BYTES]);
        material.copy_from_slice(&stored);
        stored.zeroize();
        Ok(material)
    }

    fn active_key_id(
        &self,
        purpose: IntegrityKeyPurpose,
    ) -> Result<String, IntegrityKeyProviderError> {
        let stored = self
            .store
            .get(&Self::active_name(purpose))?
            .ok_or(IntegrityKeyProviderError::UnknownKey)?;
        let key_id = String::from_utf8(stored)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        if !valid_integrity_key_id(&key_id) || self.is_retired(purpose, &key_id)? {
            return Err(IntegrityKeyProviderError::UnknownKey);
        }
        Ok(key_id)
    }

    fn mac_input(purpose: IntegrityKeyPurpose, key_id: &str, payload: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(
            MAC_DOMAIN.len() + purpose.as_str().len() + key_id.len() + payload.len() + 24,
        );
        input.extend_from_slice(MAC_DOMAIN);
        input.extend_from_slice(&(purpose.as_str().len() as u32).to_be_bytes());
        input.extend_from_slice(purpose.as_str().as_bytes());
        input.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
        input.extend_from_slice(key_id.as_bytes());
        input.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        input.extend_from_slice(payload);
        input
    }

    fn aead_aad(purpose: IntegrityKeyPurpose, key_id: &str, caller_aad: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            AEAD_DOMAIN.len() + purpose.as_str().len() + key_id.len() + caller_aad.len() + 16,
        );
        aad.extend_from_slice(AEAD_DOMAIN);
        aad.extend_from_slice(&(purpose.as_str().len() as u32).to_be_bytes());
        aad.extend_from_slice(purpose.as_str().as_bytes());
        aad.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
        aad.extend_from_slice(key_id.as_bytes());
        aad.extend_from_slice(caller_aad);
        aad
    }
}

impl<S: ProtectedSecretStore> IntegrityKeyProvider for KeyringIntegrityKeyProvider<S> {
    fn provision_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError> {
        if !valid_integrity_key_id(key_id) {
            return Err(IntegrityKeyProviderError::InvalidKeyId);
        }
        let _guard = self.lock()?;
        let name = Self::key_name(purpose, key_id);
        if self.is_retired(purpose, key_id)? || self.store.get(&name)?.is_some() {
            return Err(IntegrityKeyProviderError::KeyAlreadyExists);
        }
        let mut material = Zeroizing::new([0u8; KEY_MATERIAL_BYTES]);
        OsRng
            .try_fill_bytes(&mut *material)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        self.store.put(&name, &*material)?;
        Ok(())
    }

    fn activate_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError> {
        if !valid_integrity_key_id(key_id) {
            return Err(IntegrityKeyProviderError::InvalidKeyId);
        }
        let _guard = self.lock()?;
        let _material = self.read_material(purpose, key_id)?;
        self.store
            .put(&Self::active_name(purpose), key_id.as_bytes())
    }

    fn sign_active(
        &self,
        purpose: IntegrityKeyPurpose,
        payload: &[u8],
    ) -> Result<(String, [u8; 32]), IntegrityKeyProviderError> {
        let _guard = self.lock()?;
        let key_id = self.active_key_id(purpose)?;
        let material = self.read_material(purpose, &key_id)?;
        let input = Self::mac_input(purpose, &key_id, payload);
        let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&material[MAC_KEY_RANGE])
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        mac.update(&input);
        let tag: [u8; 32] = mac.finalize().into_bytes().into();
        Ok((key_id, tag))
    }

    fn verify(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
        payload: &[u8],
        tag: &[u8; 32],
    ) -> Result<(), IntegrityKeyProviderError> {
        let _guard = self.lock()?;
        let material = self.read_material(purpose, key_id)?;
        let input = Self::mac_input(purpose, key_id, payload);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&material[MAC_KEY_RANGE])
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
        mac.update(&input);
        mac.verify_slice(tag)
            .map_err(|_| IntegrityKeyProviderError::VerificationFailed)
    }

    fn seal_active(
        &self,
        purpose: IntegrityKeyPurpose,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(String, Vec<u8>), IntegrityKeyProviderError> {
        let _guard = self.lock()?;
        let key_id = self.active_key_id(purpose)?;
        let material = self.read_material(purpose, &key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&material[AEAD_KEY_RANGE])
            .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
        let mut nonce_bytes = [0u8; ENVELOPE_NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let authenticated_aad = Self::aead_aad(purpose, &key_id, aad);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &authenticated_aad,
                },
            )
            .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
        let mut envelope = Vec::with_capacity(1 + nonce_bytes.len() + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        nonce_bytes.zeroize();
        Ok((key_id, envelope))
    }

    fn open_sealed(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Vec<u8>, IntegrityKeyProviderError> {
        if sealed.len() < MIN_ENVELOPE_BYTES || sealed[0] != ENVELOPE_VERSION {
            return Err(IntegrityKeyProviderError::EncryptionFailed);
        }
        let _guard = self.lock()?;
        let material = self.read_material(purpose, key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&material[AEAD_KEY_RANGE])
            .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)?;
        let nonce = Nonce::from_slice(&sealed[1..1 + ENVELOPE_NONCE_BYTES]);
        let authenticated_aad = Self::aead_aad(purpose, key_id, aad);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed[1 + ENVELOPE_NONCE_BYTES..],
                    aad: &authenticated_aad,
                },
            )
            .map_err(|_| IntegrityKeyProviderError::EncryptionFailed)
    }

    fn retire_key(
        &self,
        purpose: IntegrityKeyPurpose,
        key_id: &str,
    ) -> Result<(), IntegrityKeyProviderError> {
        if !valid_integrity_key_id(key_id) {
            return Err(IntegrityKeyProviderError::InvalidKeyId);
        }
        let _guard = self.lock()?;
        match self.active_key_id(purpose) {
            Ok(active_key_id) if active_key_id == key_id => {
                return Err(IntegrityKeyProviderError::ActiveKeyCannotBeRetired);
            }
            Ok(_) | Err(IntegrityKeyProviderError::UnknownKey) => {}
            Err(error) => return Err(error),
        }
        let name = Self::key_name(purpose, key_id);
        if self.store.get(&name)?.is_none() {
            return Err(IntegrityKeyProviderError::UnknownKey);
        }
        // Tombstone first. If credential deletion fails, the key remains unusable
        // and the provider fails closed; key IDs can never be silently reused.
        self.store
            .put(&Self::retired_name(purpose, key_id), b"retired-v1")?;
        self.store.delete(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemorySecretStore(Mutex<HashMap<String, Vec<u8>>>);

    impl ProtectedSecretStore for MemorySecretStore {
        fn get(&self, name: &str) -> Result<Option<Vec<u8>>, IntegrityKeyProviderError> {
            Ok(self.0.lock().map_err(|_| IntegrityKeyProviderError::LockPoisoned)?.get(name).cloned())
        }

        fn put(&self, name: &str, value: &[u8]) -> Result<(), IntegrityKeyProviderError> {
            self.0.lock().map_err(|_| IntegrityKeyProviderError::LockPoisoned)?.insert(name.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<(), IntegrityKeyProviderError> {
            self.0.lock().map_err(|_| IntegrityKeyProviderError::LockPoisoned)?.remove(name);
            Ok(())
        }
    }

    fn provider() -> KeyringIntegrityKeyProvider<MemorySecretStore> {
        KeyringIntegrityKeyProvider::new(MemorySecretStore::default())
    }

    #[test]
    fn provisioning_rotation_and_retirement_are_purpose_scoped() {
        let provider = provider();
        let purpose = IntegrityKeyPurpose::DeviceTrustRegistry;
        provider.provision_key(purpose, "device-v1").unwrap();
        assert_eq!(provider.provision_key(purpose, "device-v1"), Err(IntegrityKeyProviderError::KeyAlreadyExists));
        provider.activate_key(purpose, "device-v1").unwrap();
        let (old_id, old_tag) = provider.sign_active(purpose, b"registry-snapshot-v1").unwrap();

        provider.provision_key(purpose, "device-v2").unwrap();
        provider.activate_key(purpose, "device-v2").unwrap();
        provider.verify(purpose, &old_id, b"registry-snapshot-v1", &old_tag).unwrap();
        assert_eq!(provider.retire_key(purpose, "device-v2"), Err(IntegrityKeyProviderError::ActiveKeyCannotBeRetired));

        provider.retire_key(purpose, "device-v1").unwrap();
        assert_eq!(provider.verify(purpose, &old_id, b"registry-snapshot-v1", &old_tag), Err(IntegrityKeyProviderError::UnknownKey));
        assert_eq!(provider.provision_key(purpose, "device-v1"), Err(IntegrityKeyProviderError::KeyAlreadyExists));
    }

    #[test]
    fn mac_and_aead_keys_are_separate_and_aead_binds_purpose_key_and_context() {
        let provider = provider();
        let purpose = IntegrityKeyPurpose::ReservationLedger;
        provider.provision_key(purpose, "ledger-v1").unwrap();
        provider.activate_key(purpose, "ledger-v1").unwrap();
        let (key_id, sealed) = provider.seal_active(purpose, b"tenant-a:ledger", b"synthetic-ledger").unwrap();
        assert_eq!(provider.open_sealed(purpose, &key_id, b"tenant-a:ledger", &sealed).unwrap(), b"synthetic-ledger");
        assert!(provider.open_sealed(purpose, &key_id, b"tenant-b:ledger", &sealed).is_err());
        assert!(provider.open_sealed(IntegrityKeyPurpose::DeviceTrustRegistry, &key_id, b"tenant-a:ledger", &sealed).is_err());

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(provider.open_sealed(purpose, &key_id, b"tenant-a:ledger", &tampered).is_err());
    }

    #[test]
    fn missing_active_key_and_corrupt_envelopes_fail_closed() {
        let provider = provider();
        assert_eq!(provider.sign_active(IntegrityKeyPurpose::ReservationLedger, b"x"), Err(IntegrityKeyProviderError::UnknownKey));
        assert_eq!(provider.open_sealed(IntegrityKeyPurpose::ReservationLedger, "missing", b"", &[0; 4]), Err(IntegrityKeyProviderError::EncryptionFailed));
    }
}
