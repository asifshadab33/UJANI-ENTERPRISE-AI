use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

use ujani_enterprise_policy::{
    integrity_key_provider::{IntegrityKeyProvider, IntegrityKeyProviderError, IntegrityKeyPurpose},
    os_keyring_integrity_provider::{
        KeyringIntegrityKeyProvider, ProtectedSecretStore,
    },
};

struct DeleteFailingSecretStore {
    values: Mutex<HashMap<String, Vec<u8>>>,
    fail_next_delete: AtomicBool,
}

impl ProtectedSecretStore for DeleteFailingSecretStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, IntegrityKeyProviderError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?
            .get(name)
            .cloned())
    }

    fn put(&self, name: &str, value: &[u8]) -> Result<(), IntegrityKeyProviderError> {
        self.values
            .lock()
            .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?
            .insert(name.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), IntegrityKeyProviderError> {
        if self.fail_next_delete.swap(false, Ordering::SeqCst) {
            return Err(IntegrityKeyProviderError::Unavailable);
        }
        self.values
            .lock()
            .map_err(|_| IntegrityKeyProviderError::LockPoisoned)?
            .remove(name);
        Ok(())
    }
}

fn private_test_directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!(
        "ujani-keyring-retirement-failure-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

#[test]
fn retirement_delete_failure_keeps_key_revoked_and_retryable() {
    let directory = private_test_directory();
    let store = DeleteFailingSecretStore {
        values: Mutex::new(HashMap::new()),
        fail_next_delete: AtomicBool::new(true),
    };
    let provider = KeyringIntegrityKeyProvider::new(store, directory.join("lifecycle.lock"))
        .unwrap();
    let purpose = IntegrityKeyPurpose::DeviceTrustRegistry;

    provider.provision_key(purpose, "device-v1").unwrap();
    provider.activate_key(purpose, "device-v1").unwrap();
    let (old_key_id, old_envelope) = provider
        .seal_active(purpose, b"registry-a", b"pre-retirement-state")
        .unwrap();
    assert_eq!(old_key_id, "device-v1");

    provider.provision_key(purpose, "device-v2").unwrap();
    provider.activate_key(purpose, "device-v2").unwrap();

    // The tombstone write succeeds, but physical credential deletion is faulted.
    // The operation reports failure, yet the old key must already be unusable.
    assert_eq!(
        provider.retire_key(purpose, "device-v1"),
        Err(IntegrityKeyProviderError::Unavailable)
    );
    assert_eq!(
        provider.open_sealed(purpose, "device-v1", b"registry-a", &old_envelope),
        Err(IntegrityKeyProviderError::UnknownKey)
    );
    assert_eq!(
        provider.provision_key(purpose, "device-v1"),
        Err(IntegrityKeyProviderError::KeyAlreadyExists)
    );

    // A later retry completes physical deletion without re-enabling the key.
    provider.retire_key(purpose, "device-v1").unwrap();
    assert_eq!(
        provider.open_sealed(purpose, "device-v1", b"registry-a", &old_envelope),
        Err(IntegrityKeyProviderError::UnknownKey)
    );
    assert_eq!(
        IntegrityKeyProvider::sign_active(&provider, purpose, b"post-retirement-state")
            .unwrap()
            .0,
        "device-v2"
    );

    drop(provider);
    std::fs::remove_dir_all(directory).unwrap();
}
