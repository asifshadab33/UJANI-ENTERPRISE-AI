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
//! Calls are synchronous and may block on the platform credential service; async
//! hosts must execute them on a dedicated blocking pool, never on an async worker.
//! All instances in this process share a mutex because some native stores do not
//! guarantee ordering across concurrent calls. Every provider also requires a
//! lock file in the service's private state directory; an OS file lock serializes
//! lifecycle operations across independent processes and is released on crash.
//! The host must use the same protected lock path for every instance belonging to
//! one service identity. Windows inherits the directory ACL; Unix directories
//! must not be group/world writable and the lock file is created mode 0600.

use crate::integrity_key_provider::{
    valid_integrity_key_id, IntegrityKeyProvider, IntegrityKeyProviderError, IntegrityKeyPurpose,
};
use crate::operator_control_plane::{OperatorAuthError, OperatorSessionMacProvider};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
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
static KEYRING_OPERATION_LOCK: Mutex<()> = Mutex::new(());

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
    lock_path: PathBuf,
}

struct KeyringOperationGuard {
    _file: File,
    _process_guard: MutexGuard<'static, ()>,
}

fn validate_lifecycle_lock_path(path: &Path) -> Result<(), IntegrityKeyProviderError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(IntegrityKeyProviderError::Unavailable);
    }
    let parent = path.parent().ok_or(IntegrityKeyProviderError::Unavailable)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| IntegrityKeyProviderError::Unavailable)?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(IntegrityKeyProviderError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o022 != 0 {
            return Err(IntegrityKeyProviderError::Unavailable);
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(IntegrityKeyProviderError::Unavailable);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(IntegrityKeyProviderError::Unavailable);
            }
        }
    }
    Ok(())
}

fn open_lifecycle_lock_file(path: &Path) -> Result<File, IntegrityKeyProviderError> {
    validate_lifecycle_lock_path(path)?;
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options.mode(0o600);
    }
    let file = match create_options.create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                fs::symlink_metadata(path).map_err(|_| IntegrityKeyProviderError::Unavailable)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(IntegrityKeyProviderError::Unavailable);
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| IntegrityKeyProviderError::Unavailable)?
        }
        Err(_) => return Err(IntegrityKeyProviderError::Unavailable),
    };
    let metadata = file
        .metadata()
        .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
    if !metadata.is_file() {
        return Err(IntegrityKeyProviderError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IntegrityKeyProviderError::Unavailable);
        }
    }
    file.lock()
        .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
    Ok(file)
}

impl<S> std::fmt::Debug for KeyringIntegrityKeyProvider<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyringIntegrityKeyProvider")
            .field("store", &"[protected]")
            .finish()
    }
}

impl KeyringIntegrityKeyProvider<OsKeyringSecretStore> {
    /// Construct the production platform-keyring adapter with the service's
    /// protected lifecycle-lock file path. The parent directory must already
    /// exist and be private to the service identity.
    pub fn new_os_keyring(
        lock_path: impl Into<PathBuf>,
    ) -> Result<Self, IntegrityKeyProviderError> {
        Self::new(OsKeyringSecretStore, lock_path)
    }
}

impl<S: ProtectedSecretStore> KeyringIntegrityKeyProvider<S> {
    /// Create a provider bound to a shared, protected inter-process lifecycle lock.
    /// The parent directory must already exist and be private to the service identity.
    pub fn new(
        store: S,
        lock_path: impl Into<PathBuf>,
    ) -> Result<Self, IntegrityKeyProviderError> {
        let lock_path = lock_path.into();
        validate_lifecycle_lock_path(&lock_path)?;
        Ok(Self { store, lock_path })
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

    fn lock(&self) -> Result<KeyringOperationGuard, IntegrityKeyProviderError> {
        let process_guard = KEYRING_OPERATION_LOCK
            .lock()
            .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?;
        let file = open_lifecycle_lock_file(&self.lock_path)?;
        Ok(KeyringOperationGuard {
            _file: file,
            _process_guard: process_guard,
        })
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
        let key_id =
            String::from_utf8(stored).map_err(|_| IntegrityKeyProviderError::Unavailable)?;
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
        let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&material[MAC_KEY_RANGE])
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
        // Use the fallible OS RNG API: a nonce-generation failure must return
        // an error, never panic or continue with an uninitialized/reused nonce.
        let mut nonce_bytes = [0u8; ENVELOPE_NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| IntegrityKeyProviderError::Unavailable)?;
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
        let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
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

fn map_operator_session_key_error(error: IntegrityKeyProviderError) -> OperatorAuthError {
    match error {
        IntegrityKeyProviderError::UnknownKey | IntegrityKeyProviderError::InvalidKeyId => {
            OperatorAuthError::UnknownKeyId
        }
        IntegrityKeyProviderError::VerificationFailed => OperatorAuthError::InvalidSignature,
        _ => OperatorAuthError::InvalidKey,
    }
}

impl<S: ProtectedSecretStore> OperatorSessionMacProvider for KeyringIntegrityKeyProvider<S> {
    fn sign_active(&self, payload: &[u8]) -> Result<(String, Vec<u8>), OperatorAuthError> {
        let (key_id, tag) =
            IntegrityKeyProvider::sign_active(self, IntegrityKeyPurpose::OperatorSession, payload)
                .map_err(map_operator_session_key_error)?;
        Ok((key_id, tag.to_vec()))
    }

    fn verify(
        &self,
        key_id: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), OperatorAuthError> {
        let tag: [u8; 32] = signature
            .try_into()
            .map_err(|_| OperatorAuthError::InvalidSignature)?;
        IntegrityKeyProvider::verify(
            self,
            IntegrityKeyPurpose::OperatorSession,
            key_id,
            payload,
            &tag,
        )
        .map_err(map_operator_session_key_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_trust::durable::DurableDeviceRegistry;
    #[cfg(not(windows))]
    use crate::device_trust::durable::{
        AnchorCallContext, AnchorCallPolicy, MonotonicSnapshotAnchor, SnapshotAnchorRecord,
    };
    use crate::durable_ledger::DurableLedger;
    use crate::operator_control_plane::{
        OperatorRole, OperatorSessionClaims, OperatorSessionProviderVerifier,
    };
    use ed25519_dalek::SigningKey;
    use std::{
        collections::HashMap,
        path::PathBuf,
        process::Command,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct MemorySecretStore(Mutex<HashMap<String, Vec<u8>>>);

    impl ProtectedSecretStore for MemorySecretStore {
        fn get(&self, name: &str) -> Result<Option<Vec<u8>>, IntegrityKeyProviderError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?
                .get(name)
                .cloned())
        }

        fn put(&self, name: &str, value: &[u8]) -> Result<(), IntegrityKeyProviderError> {
            self.0
                .lock()
                .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?
                .insert(name.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<(), IntegrityKeyProviderError> {
            self.0
                .lock()
                .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?
                .remove(name);
            Ok(())
        }
    }

    fn test_lock_path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let directory = std::env::temp_dir().join(format!(
            "ujani-keyring-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &directory,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        directory.join("lifecycle.lock")
    }

    fn provider() -> KeyringIntegrityKeyProvider<MemorySecretStore> {
        KeyringIntegrityKeyProvider::new(MemorySecretStore::default(), test_lock_path()).unwrap()
    }

    #[cfg(not(windows))]
    #[derive(Default)]
    struct MemorySnapshotAnchor(Mutex<HashMap<String, SnapshotAnchorRecord>>);

    #[cfg(not(windows))]
    impl MonotonicSnapshotAnchor for MemorySnapshotAnchor {
        fn load(
            &self,
            registry_id: &str,
            context: &AnchorCallContext,
        ) -> Result<Option<SnapshotAnchorRecord>, String> {
            context.check_active().map_err(|error| error.to_string())?;
            let record = self
                .0
                .lock()
                .map_err(|_| "test anchor lock poisoned".to_owned())?
                .get(registry_id)
                .cloned();
            context.check_active().map_err(|error| error.to_string())?;
            Ok(record)
        }

        fn compare_and_set(
            &self,
            registry_id: &str,
            expected_generation: Option<u64>,
            next: SnapshotAnchorRecord,
            context: &AnchorCallContext,
        ) -> Result<bool, String> {
            context.check_active().map_err(|error| error.to_string())?;
            let mut records = self
                .0
                .lock()
                .map_err(|_| "test anchor lock poisoned".to_owned())?;
            let current = records
                .get(registry_id)
                .map(SnapshotAnchorRecord::generation);
            let expected_next = expected_generation
                .and_then(|value| value.checked_add(1))
                .unwrap_or(1);
            if current != expected_generation || next.generation() != expected_next {
                return Ok(false);
            }
            records.insert(registry_id.to_owned(), next);
            context.check_active().map_err(|error| error.to_string())?;
            Ok(true)
        }
    }

    #[test]
    fn provisioning_rotation_and_retirement_are_purpose_scoped() {
        let provider = provider();
        let purpose = IntegrityKeyPurpose::DeviceTrustRegistry;
        provider.provision_key(purpose, "device-v1").unwrap();
        assert_eq!(
            provider.provision_key(purpose, "device-v1"),
            Err(IntegrityKeyProviderError::KeyAlreadyExists)
        );
        provider.activate_key(purpose, "device-v1").unwrap();
        let (old_id, old_tag) =
            IntegrityKeyProvider::sign_active(&provider, purpose, b"registry-snapshot-v1").unwrap();

        provider.provision_key(purpose, "device-v2").unwrap();
        provider.activate_key(purpose, "device-v2").unwrap();
        IntegrityKeyProvider::verify(
            &provider,
            purpose,
            &old_id,
            b"registry-snapshot-v1",
            &old_tag,
        )
        .unwrap();
        assert_eq!(
            provider.retire_key(purpose, "device-v2"),
            Err(IntegrityKeyProviderError::ActiveKeyCannotBeRetired)
        );

        provider.retire_key(purpose, "device-v1").unwrap();
        assert_eq!(
            IntegrityKeyProvider::verify(
                &provider,
                purpose,
                &old_id,
                b"registry-snapshot-v1",
                &old_tag,
            ),
            Err(IntegrityKeyProviderError::UnknownKey)
        );
        assert_eq!(
            provider.provision_key(purpose, "device-v1"),
            Err(IntegrityKeyProviderError::KeyAlreadyExists)
        );
    }

    #[test]
    fn mac_and_aead_keys_are_separate_and_aead_binds_purpose_key_and_context() {
        let provider = provider();
        let purpose = IntegrityKeyPurpose::ReservationLedger;
        provider.provision_key(purpose, "ledger-v1").unwrap();
        provider.activate_key(purpose, "ledger-v1").unwrap();
        let (key_id, sealed) = provider
            .seal_active(purpose, b"tenant-a:ledger", b"synthetic-ledger")
            .unwrap();
        assert_eq!(
            provider
                .open_sealed(purpose, &key_id, b"tenant-a:ledger", &sealed)
                .unwrap(),
            b"synthetic-ledger"
        );
        assert!(provider
            .open_sealed(purpose, &key_id, b"tenant-b:ledger", &sealed)
            .is_err());
        assert!(provider
            .open_sealed(
                IntegrityKeyPurpose::DeviceTrustRegistry,
                &key_id,
                b"tenant-a:ledger",
                &sealed
            )
            .is_err());

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(provider
            .open_sealed(purpose, &key_id, b"tenant-a:ledger", &tampered)
            .is_err());
    }

    #[test]
    fn repeated_seals_use_fresh_random_nonces() {
        let provider = provider();
        let purpose = IntegrityKeyPurpose::ReservationLedger;
        provider.provision_key(purpose, "nonce-v1").unwrap();
        provider.activate_key(purpose, "nonce-v1").unwrap();

        let (first_key_id, first) = provider
            .seal_active(purpose, b"same-context", b"same-plaintext")
            .unwrap();
        let (second_key_id, second) = provider
            .seal_active(purpose, b"same-context", b"same-plaintext")
            .unwrap();

        assert_eq!(first_key_id, second_key_id);
        assert_ne!(
            first, second,
            "independent encryptions must not reuse the nonce/ciphertext envelope"
        );
        assert_eq!(
            provider
                .open_sealed(purpose, &first_key_id, b"same-context", &first)
                .unwrap(),
            b"same-plaintext"
        );
        assert_eq!(
            provider
                .open_sealed(purpose, &second_key_id, b"same-context", &second)
                .unwrap(),
            b"same-plaintext"
        );
    }

    /// Exercises both durable adapters through the same provider contract with an
    /// injected store; platform credential-manager access is validated separately.
    #[test]
    fn protected_provider_reopens_the_durable_registry_and_reservation_ledger() {
        let mut random = [0u8; 8];
        OsRng.try_fill_bytes(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "ujani-enterprise-keyring-integration-{}",
            u64::from_ne_bytes(random)
        ));
        std::fs::create_dir_all(&directory).unwrap();

        let provider = Arc::new(
            KeyringIntegrityKeyProvider::new(
                MemorySecretStore::default(),
                directory.join("keyring-lifecycle.lock"),
            )
            .unwrap(),
        );
        provider
            .provision_key(IntegrityKeyPurpose::DeviceTrustRegistry, "registry-v1")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::DeviceTrustRegistry, "registry-v1")
            .unwrap();
        provider
            .provision_key(IntegrityKeyPurpose::ReservationLedger, "ledger-v1")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::ReservationLedger, "ledger-v1")
            .unwrap();

        let admin = SigningKey::from_bytes(&rand::random());
        let registry_path = directory.join("device-trust.json");
        let registry = DurableDeviceRegistry::open_with_key_provider(
            &registry_path,
            vec![("test-admin".to_owned(), admin.verifying_key())],
            provider.clone(),
        )
        .unwrap();
        drop(registry);
        let reopened_registry = DurableDeviceRegistry::open_with_key_provider(
            &registry_path,
            vec![("test-admin".to_owned(), admin.verifying_key())],
            provider.clone(),
        )
        .unwrap();
        drop(reopened_registry);

        let ledger_path = directory.join("reservation-ledger.json");
        let ledger = DurableLedger::open_with_key_provider(&ledger_path, provider.clone()).unwrap();
        drop(ledger);
        let reopened_ledger =
            DurableLedger::open_with_key_provider(&ledger_path, provider).unwrap();
        drop(reopened_ledger);

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn protected_provider_reopens_anchored_registry_and_ledger() {
        let mut random = [0u8; 8];
        OsRng.try_fill_bytes(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "ujani-enterprise-anchored-keyring-{}",
            u64::from_ne_bytes(random)
        ));
        std::fs::create_dir_all(&directory).unwrap();

        let provider = Arc::new(
            KeyringIntegrityKeyProvider::new(
                MemorySecretStore::default(),
                directory.join("keyring-lifecycle.lock"),
            )
            .unwrap(),
        );
        provider
            .provision_key(
                IntegrityKeyPurpose::DeviceTrustRegistry,
                "anchored-registry-v1",
            )
            .unwrap();
        provider
            .activate_key(
                IntegrityKeyPurpose::DeviceTrustRegistry,
                "anchored-registry-v1",
            )
            .unwrap();
        provider
            .provision_key(IntegrityKeyPurpose::ReservationLedger, "anchored-ledger-v1")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::ReservationLedger, "anchored-ledger-v1")
            .unwrap();

        let admin = SigningKey::from_bytes(&rand::random());
        let anchor: Arc<dyn MonotonicSnapshotAnchor> = Arc::new(MemorySnapshotAnchor::default());
        let policy = AnchorCallPolicy::default();

        let registry_path = directory.join("device-trust-anchored.json");
        let registry = DurableDeviceRegistry::open_with_anchor_and_key_provider(
            &registry_path,
            "device-registry-test",
            vec![("test-admin".to_owned(), admin.verifying_key())],
            provider.clone(),
            anchor.clone(),
            policy.clone(),
        )
        .unwrap();
        drop(registry);
        let reopened_registry = DurableDeviceRegistry::open_with_anchor_and_key_provider(
            &registry_path,
            "device-registry-test",
            vec![("test-admin".to_owned(), admin.verifying_key())],
            provider.clone(),
            anchor.clone(),
            policy.clone(),
        )
        .unwrap();
        drop(reopened_registry);

        let ledger_path = directory.join("reservation-ledger-anchored.json");
        let ledger = DurableLedger::open_with_anchor_and_key_provider(
            &ledger_path,
            "reservation-ledger-test",
            provider.clone(),
            anchor.clone(),
            policy.clone(),
        )
        .unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 0);
        drop(ledger);
        let reopened_ledger = DurableLedger::open_with_anchor_and_key_provider(
            &ledger_path,
            "reservation-ledger-test",
            provider,
            anchor,
            policy,
        )
        .unwrap();
        assert_eq!(reopened_ledger.snapshot().unwrap().active_jobs, 0);
        drop(reopened_ledger);

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn protected_keyring_provider_signs_short_lived_operator_sessions() {
        let provider = provider();
        provider
            .provision_key(IntegrityKeyPurpose::OperatorSession, "operator-session-v1")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::OperatorSession, "operator-session-v1")
            .unwrap();

        let verifier = OperatorSessionProviderVerifier::new(provider);
        let now = 1_000_000;
        let claims = OperatorSessionClaims {
            subject_id: "operator-1".to_owned(),
            tenant_id: "tenant-a".to_owned(),
            role: OperatorRole::Viewer,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            nonce: rand::random(),
        };

        let token = verifier
            .mint_after_identity_verification(&claims, now)
            .unwrap();
        assert_eq!(verifier.authenticate(&token, now).unwrap(), claims);

        let mut tampered = token.clone();
        let replacement = if tampered.ends_with('0') { '1' } else { '0' };
        tampered.pop();
        tampered.push(replacement);
        assert_eq!(
            verifier.authenticate(&tampered, now),
            Err(OperatorAuthError::InvalidSignature)
        );
        assert_eq!(
            verifier.authenticate(&token, claims.expires_at_unix_ms),
            Err(OperatorAuthError::Expired)
        );
    }

    #[test]
    fn operator_sessions_use_the_separate_protected_key_purpose() {
        let provider = KeyringIntegrityKeyProvider::new(
            MemorySecretStore::default(),
            test_lock_path(),
        )
        .unwrap();
        provider
            .provision_key(IntegrityKeyPurpose::OperatorSession, "session-v1")
            .unwrap();
        provider
            .activate_key(IntegrityKeyPurpose::OperatorSession, "session-v1")
            .unwrap();
        let verifier = OperatorSessionProviderVerifier::new(provider);
        let claims = OperatorSessionClaims {
            subject_id: "operator-1".into(),
            tenant_id: "tenant-a".into(),
            role: OperatorRole::Administrator,
            issued_at_unix_ms: 10_000,
            expires_at_unix_ms: 20_000,
            nonce: rand::random(),
        };
        let token = verifier
            .mint_after_identity_verification(&claims, 10_100)
            .unwrap();
        assert_eq!(verifier.authenticate(&token, 10_100).unwrap(), claims);
    }

    #[test]
    fn keyring_lock_child_process() {
        let Ok(lock_path) = std::env::var("UJANI_KEYRING_TEST_LOCK_PATH") else {
            return;
        };
        let ready_path = std::env::var("UJANI_KEYRING_TEST_READY_PATH").unwrap();
        let release_path = std::env::var("UJANI_KEYRING_TEST_RELEASE_PATH").unwrap();
        let provider = KeyringIntegrityKeyProvider::new(
            MemorySecretStore::default(),
            PathBuf::from(lock_path),
        )
        .unwrap();
        let _guard = provider.lock().unwrap();
        std::fs::write(&ready_path, b"locked").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Path::new(&release_path).exists() {
            assert!(Instant::now() < deadline, "parent did not release the inter-process lock");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn keyring_lifecycle_lock_serializes_independent_processes() {
        let lock_path = test_lock_path();
        let directory = lock_path.parent().unwrap();
        let ready_path = directory.join("child-ready");
        let release_path = directory.join("child-release");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("keyring_lock_child_process")
            .arg("--nocapture")
            .env("UJANI_KEYRING_TEST_LOCK_PATH", &lock_path)
            .env("UJANI_KEYRING_TEST_READY_PATH", &ready_path)
            .env("UJANI_KEYRING_TEST_RELEASE_PATH", &release_path)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready_path.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("keyring lock child exited before acquiring the lock: {status}");
            }
            assert!(Instant::now() < deadline, "keyring lock child did not become ready");
            thread::sleep(Duration::from_millis(10));
        }

        let provider = Arc::new(
            KeyringIntegrityKeyProvider::new(MemorySecretStore::default(), lock_path).unwrap(),
        );
        let acquired = Arc::new(AtomicBool::new(false));
        let thread_provider = Arc::clone(&provider);
        let thread_acquired = Arc::clone(&acquired);
        let waiter = thread::spawn(move || {
            let _guard = thread_provider.lock().unwrap();
            thread_acquired.store(true, Ordering::SeqCst);
        });
        thread::sleep(Duration::from_millis(150));
        let blocked_while_child_held_lock = !acquired.load(Ordering::SeqCst);

        std::fs::write(&release_path, b"release").unwrap();
        waiter.join().unwrap();
        let child_status = child.wait().unwrap();
        assert!(child_status.success(), "keyring lock child failed: {child_status}");
        assert!(
            blocked_while_child_held_lock,
            "a second process entered the key lifecycle while the first held the lock"
        );
        assert!(acquired.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_file_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let provider = provider();
        let _guard = provider.lock().unwrap();
        let metadata = std::fs::metadata(&provider.lock_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_rejects_a_group_or_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_lock_path().parent().unwrap().join("unsafe-parent");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        let result = KeyringIntegrityKeyProvider::new(
            MemorySecretStore::default(),
            directory.join("lifecycle.lock"),
        );
        assert!(matches!(result, Err(IntegrityKeyProviderError::Unavailable)));
    }

    #[test]
    fn lock_path_must_be_absolute_and_in_a_non_writable_parent() {
        assert!(matches!(
            KeyringIntegrityKeyProvider::new(
                MemorySecretStore::default(),
                PathBuf::from("relative/keyring.lock"),
            ),
            Err(IntegrityKeyProviderError::Unavailable)
        ));
    }

    #[test]
    fn missing_active_key_and_corrupt_envelopes_fail_closed() {
        let provider = provider();
        assert_eq!(
            IntegrityKeyProvider::sign_active(
                &provider,
                IntegrityKeyPurpose::ReservationLedger,
                b"x",
            ),
            Err(IntegrityKeyProviderError::UnknownKey)
        );
        assert_eq!(
            provider.open_sealed(
                IntegrityKeyPurpose::ReservationLedger,
                "missing",
                b"",
                &[0; 4]
            ),
            Err(IntegrityKeyProviderError::EncryptionFailed)
        );
    }
}
