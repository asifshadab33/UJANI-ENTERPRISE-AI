//! HMAC-authenticated, cross-process durable device trust registry.
//!
//! The integrity key and administrator verifying keys are injected by the
//! trusted host from protected configuration. Neither is read from this file.
//! This is a persistence primitive, not an HTTP server or a complete RBAC layer.
use super::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HEADER: &str = "UJANI-DEVICE-TRUST-V1";
const DOMAIN: &[u8] = b"UJANI-DEVICE-TRUST-HMAC-SHA256-V1\0";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = MAX_REPLAY_ENTRIES;

/// Monotonic state recorded outside the writable registry directory.
///
/// Production implementations must provide durable, linearizable compare-and-set
/// semantics in a separate trust domain (for example a KMS-backed service or a
/// strongly consistent control-plane database). A local file or the same host's
/// SQLite database is not an acceptable anti-rollback anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotAnchorRecord {
    generation: u64,
    snapshot_sha256: [u8; 32],
}
impl SnapshotAnchorRecord {
    /// Construct a record returned by a trusted external anchor provider.
    pub fn new(generation: u64, snapshot_sha256: [u8; 32]) -> Option<Self> {
        (generation > 0).then_some(Self {
            generation,
            snapshot_sha256,
        })
    }
    /// Returns the monotonic generation recorded by the anchor.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Returns the SHA-256 digest pinned by the anchor record.
    pub fn snapshot_sha256(&self) -> [u8; 32] {
        self.snapshot_sha256
    }
}

/// External monotonic anchor contract.
///
/// `load` must be linearizable with `compare_and_set`: a load started after a
/// completed compare-and-set must observe that record or a later generation;
/// stale reads are not permitted. `compare_and_set` must atomically create
/// generation 1 when `expected_generation` is `None`, or advance exactly one
/// generation when it is `Some(n)`. It must never accept a stale generation.
/// Implementations must
/// enforce bounded timeouts for every call: the ledger invokes `load`,
/// `compare_and_set`, and ambiguous-result read-back synchronously while holding
/// both its in-process mutex and OS file lock, including for read-only snapshots.
/// Before returning an error from `compare_and_set`, a provider must settle or
/// fence every in-flight update for that request so it cannot commit later;
/// otherwise the ledger cannot safely roll back its candidate snapshot. Each
/// ledger and device-trust registry sharing a provider must use a distinct
/// namespace identifier.
pub trait MonotonicSnapshotAnchor: Send + Sync {
    /// Reads the latest linearizable record for a unique ledger or registry namespace.
    /// A completed compare-and-set must be visible to every subsequent load. Each load
    /// must also act as a quiescence barrier: before returning, it must settle or fence
    /// every earlier in-flight compare-and-set for this namespace, including requests
    /// left pending by a crashed caller, so an old update cannot commit after recovery.
    fn load(&self, registry_id: &str) -> Result<Option<SnapshotAnchorRecord>, String>;
    /// Atomically creates or advances the namespace record if its generation matches.
    ///
    /// Before returning `Err`, the provider must settle or fence the request so an
    /// in-flight update cannot commit after the caller has rolled back local state.
    fn compare_and_set(
        &self,
        registry_id: &str,
        expected_generation: Option<u64>,
        next: SnapshotAnchorRecord,
    ) -> Result<bool, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableDeviceTrustError {
    Io(String),
    CorruptState,
    CapacityExceeded,
    Trust(DeviceTrustError),
    LockPoisoned,
    AnchorUnavailable(String),
    AnchorMismatch,
    AnchorConflict,
    AnchorGenerationExhausted,
}
impl std::fmt::Display for DurableDeviceTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(v) => write!(f, "device trust storage I/O failed: {v}"),
            Self::CorruptState => write!(f, "device trust snapshot is corrupt or unauthenticated"),
            Self::CapacityExceeded => write!(f, "device trust snapshot exceeds its safety limit"),
            Self::Trust(v) => write!(f, "device trust operation rejected: {v:?}"),
            Self::LockPoisoned => write!(f, "device trust thread lock is poisoned"),
            Self::AnchorUnavailable(v) => write!(f, "external monotonic anchor unavailable: {v}"),
            Self::AnchorMismatch => write!(
                f,
                "device trust snapshot does not match its external monotonic anchor"
            ),
            Self::AnchorConflict => {
                write!(f, "external monotonic anchor rejected a stale generation")
            }
            Self::AnchorGenerationExhausted => {
                write!(f, "external monotonic anchor generation exhausted")
            }
        }
    }
}
impl std::error::Error for DurableDeviceTrustError {}
impl From<std::io::Error> for DurableDeviceTrustError {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v.to_string())
    }
}
impl From<DeviceTrustError> for DurableDeviceTrustError {
    fn from(v: DeviceTrustError) -> Self {
        Self::Trust(v)
    }
}

/// Secret material must come from a protected key provider (OS keyring, TPM,
/// HSM or managed secret service), never from the writable registry directory.
#[derive(Clone)]
pub struct DeviceTrustIntegrityKey {
    key_id: String,
    bytes: [u8; 32],
}
impl DeviceTrustIntegrityKey {
    /// Creates a registry integrity key from protected key-provider material.
    pub fn new(key_id: impl Into<String>, bytes: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            bytes,
        }
    }
    /// Returns the non-secret identifier associated with this key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}
impl std::fmt::Debug for DeviceTrustIntegrityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTrustIntegrityKey")
            .field("key_id", &self.key_id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
impl Drop for DeviceTrustIntegrityKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

/// Each operation reloads state while holding an OS advisory lock, so separate
/// instances and processes share one authoritative replay window and registry.
#[derive(Clone)]
pub struct DurableDeviceRegistry {
    path: PathBuf,
    lock_path: PathBuf,
    thread_lock: Arc<Mutex<()>>,
    admin_keys: Arc<Vec<(String, VerifyingKey)>>,
    integrity_key: Arc<DeviceTrustIntegrityKey>,
    anchor_namespace: Option<String>,
    anchor: Option<Arc<dyn MonotonicSnapshotAnchor>>,
}
impl std::fmt::Debug for DurableDeviceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableDeviceRegistry")
            .field("path", &self.path)
            .field("admin_key_count", &self.admin_keys.len())
            .field("integrity_key_id", &self.integrity_key.key_id())
            .finish()
    }
}

impl DurableDeviceRegistry {
    /// Open a locally HMAC-authenticated registry. This protects against
    /// unauthenticated edits but does not detect rollback to an older valid snapshot.
    pub fn open(
        path: impl AsRef<Path>,
        trusted_admin_keys: Vec<(String, VerifyingKey)>,
        integrity_key: DeviceTrustIntegrityKey,
    ) -> Result<Self, DurableDeviceTrustError> {
        Self::open_internal(path, trusted_admin_keys, integrity_key, None)
    }

    /// Open a registry whose current snapshot digest and generation are also
    /// checked against an external monotonic anchor. Existing unanchored files
    /// are rejected; migration must be an explicit, separately audited operation.
    pub fn open_with_anchor(
        path: impl AsRef<Path>,
        registry_id: impl Into<String>,
        trusted_admin_keys: Vec<(String, VerifyingKey)>,
        integrity_key: DeviceTrustIntegrityKey,
        anchor: Arc<dyn MonotonicSnapshotAnchor>,
    ) -> Result<Self, DurableDeviceTrustError> {
        let registry_id = registry_id.into();
        if !valid_id(&registry_id, 128) {
            return Err(DurableDeviceTrustError::CorruptState);
        }
        Self::open_internal(
            path,
            trusted_admin_keys,
            integrity_key,
            Some((registry_id, anchor)),
        )
    }

    fn open_internal(
        path: impl AsRef<Path>,
        trusted_admin_keys: Vec<(String, VerifyingKey)>,
        integrity_key: DeviceTrustIntegrityKey,
        anchor: Option<(String, Arc<dyn MonotonicSnapshotAnchor>)>,
    ) -> Result<Self, DurableDeviceTrustError> {
        if trusted_admin_keys.is_empty()
            || !valid_id(integrity_key.key_id(), 128)
            || trusted_admin_keys.iter().any(|(id, _)| !valid_id(id, 128))
        {
            return Err(DurableDeviceTrustError::CorruptState);
        }
        // Resolve the caller-supplied parent directory once and retain the
        // canonical parent path. This prevents later changes to a symlink alias
        // from redirecting registry, lock, backup or temporary-file operations.
        // The canonical directory must still be owned and protected by the service
        // account; this does not replace handle-relative operations against races.
        let requested_path = path.as_ref();
        let file_name = requested_path
            .file_name()
            .ok_or(DurableDeviceTrustError::CorruptState)?;
        let requested_parent = requested_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(requested_parent)?;
        let canonical_parent = fs::canonicalize(requested_parent)?;
        let path = canonical_parent.join(file_name);
        let (anchor_namespace, anchor) = match anchor {
            Some((namespace, provider)) => (Some(namespace), Some(provider)),
            None => (None, None),
        };
        let store = Self {
            lock_path: suffix(&path, ".lock"),
            path,
            thread_lock: Arc::new(Mutex::new(())),
            admin_keys: Arc::new(trusted_admin_keys),
            integrity_key: Arc::new(integrity_key),
            anchor_namespace,
            anchor,
        };
        store.transact(|_| Ok(()))?;
        Ok(store)
    }

    pub fn apply_admin_command(
        &self,
        command: &SignedDeviceAdminCommand,
        now: u64,
    ) -> Result<u64, DurableDeviceTrustError> {
        self.transact(|registry| {
            registry
                .apply_admin_command(command, now)
                .map_err(Into::into)
        })
    }

    /// Authenticates only when the signed method/resource match the server-selected route.
    ///
    /// A route mismatch does not consume the durable replay nonce.
    pub fn authenticate_request_for(
        &self,
        request: &SignedDeviceRequest,
        expected_method: &str,
        expected_resource_id: &str,
        body: &[u8],
        now: u64,
    ) -> Result<AuthenticatedDeviceRequest, DurableDeviceTrustError> {
        self.transact(|registry| {
            registry
                .authenticate_request_for(request, expected_method, expected_resource_id, body, now)
                .map_err(Into::into)
        })
    }

    /// Re-read the current durable trust record and return its active public key
    /// only while the authenticated request still matches the enrolled tenant,
    /// key ID, and generation. This closes a rotation/revocation gap between
    /// request authentication and verification of a separately signed evidence body.
    pub fn verifying_key_for_authenticated_request(
        &self,
        authenticated: &AuthenticatedDeviceRequest,
    ) -> Result<VerifyingKey, DurableDeviceTrustError> {
        self.transact(|registry| {
            let record = registry
                .devices
                .get(authenticated.device_id())
                .ok_or(DeviceTrustError::DeviceNotFound)?;
            if record.state != DeviceTrustState::Enrolled {
                return Err(DeviceTrustError::DeviceNotEnrolled.into());
            }
            if record.tenant_id != authenticated.tenant_id() {
                return Err(DeviceTrustError::TenantMismatch.into());
            }
            if record.key_id != authenticated.key_id()
                || record.generation != authenticated.key_generation()
            {
                return Err(DeviceTrustError::StaleKeyGeneration.into());
            }
            Ok(record.key.clone())
        })
    }

    /// Authenticates a device request and durably records its replay nonce.
    ///
    /// Pass the same raw body bytes that the request handler will process;
    /// authentication rejects mismatches before persisting replay state.
    pub fn authenticate_request(
        &self,
        request: &SignedDeviceRequest,
        body: &[u8],
        now: u64,
    ) -> Result<AuthenticatedDeviceRequest, DurableDeviceTrustError> {
        self.transact(|registry| {
            registry
                .authenticate_request(request, body, now)
                .map_err(Into::into)
        })
    }

    /// Returns a tenant-scoped, non-secret projection of enrolled device identities.
    /// Enrollment must not be interpreted as live availability or owner consent.
    pub fn tenant_device_summaries(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<DeviceTrustSummary>, DurableDeviceTrustError> {
        self.transact(|registry| {
            registry
                .tenant_device_summaries(tenant_id)
                .map_err(Into::into)
        })
    }

    /// Returns the number of enrolled device records in the durable registry.
    pub fn device_count(&self) -> Result<usize, DurableDeviceTrustError> {
        self.transact(|registry| Ok(registry.devices.len()))
    }

    fn load_anchored_registry(
        &self,
        anchor_record: Option<&SnapshotAnchorRecord>,
    ) -> Result<DeviceRegistry, DurableDeviceTrustError> {
        let backup = suffix(&self.path, ".bak");
        match anchor_record {
            Some(record) => {
                if self.path.exists() {
                    let bytes = fs::read(&self.path)?;
                    if snapshot_sha256(&bytes) == record.snapshot_sha256 {
                        return decode_snapshot(
                            &bytes,
                            &self.admin_keys,
                            self.integrity_key.key_id(),
                            &self.integrity_key.bytes,
                        );
                    }
                }
                if backup.exists() {
                    let bytes = fs::read(&backup)?;
                    if snapshot_sha256(&bytes) == record.snapshot_sha256 {
                        restore_snapshot_from_backup(&self.path, &bytes)?;
                        return decode_snapshot(
                            &bytes,
                            &self.admin_keys,
                            self.integrity_key.key_id(),
                            &self.integrity_key.bytes,
                        );
                    }
                }
                Err(DurableDeviceTrustError::AnchorMismatch)
            }
            None => {
                if self.path.exists() || backup.exists() {
                    return Err(DurableDeviceTrustError::AnchorMismatch);
                }
                DeviceRegistry::new(self.admin_keys.as_ref().clone()).map_err(Into::into)
            }
        }
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut DeviceRegistry) -> Result<T, DurableDeviceTrustError>,
    ) -> Result<T, DurableDeviceTrustError> {
        let _guard = self
            .thread_lock
            .lock()
            .map_err(|_| DurableDeviceTrustError::LockPoisoned)?;
        require_regular_file_if_present(&self.lock_path)?;
        require_regular_file_if_present(&self.path)?;
        require_regular_file_if_present(&suffix(&self.path, ".bak"))?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&self.lock_path)?;
        lock.lock()?;

        let anchor_record = match (&self.anchor, &self.anchor_namespace) {
            (Some(anchor), Some(namespace)) => anchor
                .load(namespace)
                .map_err(DurableDeviceTrustError::AnchorUnavailable)?,
            (None, None) => None,
            _ => return Err(DurableDeviceTrustError::AnchorMismatch),
        };
        let mut registry = if self.anchor.is_some() {
            self.load_anchored_registry(anchor_record.as_ref())?
        } else {
            let backup = suffix(&self.path, ".bak");
            if self.path.exists() {
                decode_snapshot(
                    &fs::read(&self.path)?,
                    &self.admin_keys,
                    self.integrity_key.key_id(),
                    &self.integrity_key.bytes,
                )?
            } else if backup.exists() {
                // Recover only the interrupted-rename case. A present but invalid
                // primary snapshot is never silently replaced by an older backup.
                let bytes = fs::read(&backup)?;
                let recovered = decode_snapshot(
                    &bytes,
                    &self.admin_keys,
                    self.integrity_key.key_id(),
                    &self.integrity_key.bytes,
                )?;
                atomic_write(&self.path, &bytes, false)?;
                recovered
            } else {
                DeviceRegistry::new(self.admin_keys.as_ref().clone())?
            }
        };
        let result = operation(&mut registry)?;
        let bytes = encode_snapshot(
            &registry,
            self.integrity_key.key_id(),
            &self.integrity_key.bytes,
        );
        if bytes.len() as u64 > MAX_BYTES {
            return Err(DurableDeviceTrustError::CapacityExceeded);
        }
        atomic_write(&self.path, &bytes, self.anchor.is_some())?;

        if let (Some(anchor), Some(namespace)) = (&self.anchor, &self.anchor_namespace) {
            let expected_generation = anchor_record.as_ref().map(SnapshotAnchorRecord::generation);
            let generation = expected_generation
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(DurableDeviceTrustError::AnchorGenerationExhausted)?;
            let next = SnapshotAnchorRecord {
                generation,
                snapshot_sha256: snapshot_sha256(&bytes),
            };
            let advanced = anchor
                .compare_and_set(namespace, expected_generation, next)
                .map_err(DurableDeviceTrustError::AnchorUnavailable)?;
            if !advanced {
                return Err(DurableDeviceTrustError::AnchorConflict);
            }
        }
        Ok(result)
    }
}

fn snapshot_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Restore a backup already authenticated by the external anchor without
/// overwriting that backup with the stale primary snapshot.
fn restore_snapshot_from_backup(path: &Path, bytes: &[u8]) -> Result<(), DurableDeviceTrustError> {
    let temp = suffix(path, ".anchor-restore.tmp");
    // A stale regular temporary file may be removed before the atomic restore,
    // but never unlink a symlink, directory, device, or other unexpected object.
    require_regular_file_if_present(&temp)?;
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn suffix(path: &Path, value: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(value);
    PathBuf::from(s)
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}
fn unhex(v: &str) -> Result<Vec<u8>, DurableDeviceTrustError> {
    if !v.len().is_multiple_of(2) {
        return Err(DurableDeviceTrustError::CorruptState);
    }
    let mut out = Vec::with_capacity(v.len() / 2);
    for p in v.as_bytes().as_chunks::<2>().0 {
        let h = (p[0] as char)
            .to_digit(16)
            .ok_or(DurableDeviceTrustError::CorruptState)?;
        let l = (p[1] as char)
            .to_digit(16)
            .ok_or(DurableDeviceTrustError::CorruptState)?;
        out.push(((h << 4) | l) as u8);
    }
    Ok(out)
}
fn hmac(key: &[u8; 32], key_id: &str, body: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(DOMAIN);
    mac.update(&(key_id.len() as u32).to_be_bytes());
    mac.update(key_id.as_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}
fn encode_snapshot(r: &DeviceRegistry, key_id: &str, key: &[u8; 32]) -> Vec<u8> {
    let mut body = format!("{HEADER}\n");
    let mut ids = r.devices.keys().collect::<Vec<_>>();
    ids.sort();
    for id in ids {
        let d = r.devices.get(id).expect("key came from map");
        body.push_str(&format!(
            "D|{}|{}|{}|{}|{}|{}\n",
            hex(id.as_bytes()),
            hex(d.tenant_id.as_bytes()),
            if d.state == DeviceTrustState::Enrolled {
                "E"
            } else {
                "R"
            },
            hex(d.key_id.as_bytes()),
            hex(&d.key.to_bytes()),
            d.generation
        ));
    }
    let mut admins = r.admin_nonces.iter().collect::<Vec<_>>();
    admins.sort_by_key(|(n, _)| **n);
    for (nonce, expiry) in admins {
        body.push_str(&format!("A|{}|{}\n", hex(nonce), expiry));
    }
    let mut requests = r.request_nonces.iter().collect::<Vec<_>>();
    requests.sort_by_key(|(n, _)| **n);
    for (nonce, expiry) in requests {
        body.push_str(&format!("R|{}|{}\n", hex(nonce), expiry));
    }
    let mac = hmac(key, key_id, body.as_bytes());
    body.push_str(&format!("H|{}|{}\n", hex(key_id.as_bytes()), hex(&mac)));
    body.into_bytes()
}
fn decode_snapshot(
    bytes: &[u8],
    admin_keys: &[(String, VerifyingKey)],
    expected_key_id: &str,
    key: &[u8; 32],
) -> Result<DeviceRegistry, DurableDeviceTrustError> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(DurableDeviceTrustError::CapacityExceeded);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    let marker = text
        .rfind("H|")
        .ok_or(DurableDeviceTrustError::CorruptState)?;
    let (body, tail) = text.split_at(marker);
    let fields = tail.trim_end_matches('\n').split('|').collect::<Vec<_>>();
    if fields.len() != 3 || fields[0] != "H" {
        return Err(DurableDeviceTrustError::CorruptState);
    }
    let key_id =
        String::from_utf8(unhex(fields[1])?).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    if !valid_id(&key_id, 128) || key_id != expected_key_id {
        return Err(DurableDeviceTrustError::CorruptState);
    }
    let expected = unhex(fields[2])?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    mac.update(DOMAIN);
    mac.update(&(key_id.len() as u32).to_be_bytes());
    mac.update(key_id.as_bytes());
    mac.update(body.as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| DurableDeviceTrustError::CorruptState)?;
    let mut registry = DeviceRegistry::new(admin_keys.to_vec())?;
    let mut records = 0usize;
    let mut lines = body.lines();
    if lines.next() != Some(HEADER) {
        return Err(DurableDeviceTrustError::CorruptState);
    }
    for line in lines {
        let p = line.split('|').collect::<Vec<_>>();
        records += 1;
        if records > MAX_RECORDS * 2 {
            return Err(DurableDeviceTrustError::CapacityExceeded);
        }
        match p.first().copied() {
            Some("D") if p.len() == 7 => {
                let id = String::from_utf8(unhex(p[1])?)
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let tenant = String::from_utf8(unhex(p[2])?)
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let state = match p[3] {
                    "E" => DeviceTrustState::Enrolled,
                    "R" => DeviceTrustState::Revoked,
                    _ => return Err(DurableDeviceTrustError::CorruptState),
                };
                let key_id = String::from_utf8(unhex(p[4])?)
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let pubkey: [u8; 32] = unhex(p[5])?
                    .try_into()
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let generation = p[6]
                    .parse::<u64>()
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                if !valid_id(&id, 128)
                    || !valid_id(&tenant, 128)
                    || !valid_id(&key_id, 128)
                    || generation == 0
                {
                    return Err(DurableDeviceTrustError::CorruptState);
                }
                let vk = VerifyingKey::from_bytes(&pubkey)
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                if registry
                    .devices
                    .insert(
                        id,
                        DeviceRecord {
                            tenant_id: tenant,
                            state,
                            key_id,
                            key: vk,
                            generation,
                        },
                    )
                    .is_some()
                {
                    return Err(DurableDeviceTrustError::CorruptState);
                }
            }
            Some("A") | Some("R") if p.len() == 3 => {
                let nonce: [u8; 16] = unhex(p[1])?
                    .try_into()
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let expiry = p[2]
                    .parse::<u64>()
                    .map_err(|_| DurableDeviceTrustError::CorruptState)?;
                if nonce.iter().all(|b| *b == 0) || expiry == 0 {
                    return Err(DurableDeviceTrustError::CorruptState);
                }
                let map = if p[0] == "A" {
                    &mut registry.admin_nonces
                } else {
                    &mut registry.request_nonces
                };
                if map.insert(nonce, expiry).is_some() {
                    return Err(DurableDeviceTrustError::CorruptState);
                }
            }
            _ => return Err(DurableDeviceTrustError::CorruptState),
        }
    }
    if registry.devices.len() > MAX_RECORDS
        || registry.admin_nonces.len() > MAX_RECORDS
        || registry.request_nonces.len() > MAX_RECORDS
    {
        return Err(DurableDeviceTrustError::CapacityExceeded);
    }
    Ok(registry)
}
/// Rejects unexpected filesystem object types before a registry path is read or opened.
/// This is a defense-in-depth check, not a substitute for a directory owned exclusively
/// by the service account or platform-specific no-follow/openat handles against races.
fn require_regular_file_if_present(path: &Path) -> Result<(), DurableDeviceTrustError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(DurableDeviceTrustError::Io(format!(
            "refusing non-regular registry path: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
    preserve_backup: bool,
) -> Result<(), DurableDeviceTrustError> {
    let temp = suffix(path, ".tmp");
    let backup = suffix(path, ".bak");
    require_regular_file_if_present(path)?;
    require_regular_file_if_present(&temp)?;
    require_regular_file_if_present(&backup)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let had_old = path.exists();
    if had_old {
        let _ = fs::remove_file(&backup);
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        if had_old {
            let _ = fs::rename(&backup, path);
        }
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        #[cfg(unix)]
        if preserve_backup {
            File::open(parent)?.sync_all()?;
        } else if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        #[cfg(not(unix))]
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    if !preserve_backup {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ujani-device-trust-{}-{time}-{n}.db",
            std::process::id()
        ))
    }
    fn open(path: &Path, admin: &SigningKey) -> DurableDeviceRegistry {
        DurableDeviceRegistry::open(
            path,
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32]),
        )
        .unwrap()
    }
    fn enroll(admin: &SigningKey, device: &SigningKey) -> SignedDeviceAdminCommand {
        let mut c = SignedDeviceAdminCommand {
            action: DeviceCommandAction::Enroll,
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            admin_key_id: "admin-v1".into(),
            target_key_id: "device-key-v1".into(),
            target_public_key: Some(device.verifying_key().to_bytes()),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1000,
            nonce: [1; 16],
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        c.new_device_signature = Some(device.sign(&enrollment_proof_bytes(&c)).to_bytes());
        c.signature = admin.sign(&admin_command_bytes(&c)).to_bytes();
        c
    }
    #[test]
    fn enrollment_and_request_replay_state_survive_restart() {
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let store = open(&path, &admin);
        assert_eq!(
            store
                .apply_admin_command(&enroll(&admin, &device), 200)
                .unwrap(),
            1
        );
        let body = b"tenant-scoped lease request";
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [3; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:acquire".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest(body).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        assert_eq!(
            store.authenticate_request(&signed, b"tampered body", 250),
            Err(DurableDeviceTrustError::Trust(
                DeviceTrustError::BodyDigestMismatch
            ))
        );
        assert_eq!(
            store.authenticate_request_for(&signed, "POST", "lease:renew", body, 250),
            Err(DurableDeviceTrustError::Trust(
                DeviceTrustError::RequestTargetMismatch
            ))
        );
        let authenticated = store
            .authenticate_request_for(&signed, "POST", "lease:acquire", body, 250)
            .unwrap();
        assert_eq!(authenticated.workload_id(), "workload-1");
        assert_eq!(authenticated.resource_id(), "lease:acquire");
        assert_eq!(authenticated.expires_at_unix_ms(), 500);
        drop(store);
        let reopened = open(&path, &admin);
        assert_eq!(reopened.device_count().unwrap(), 1);
        assert_eq!(
            reopened.authenticate_request(&signed, body, 251),
            Err(DurableDeviceTrustError::Trust(
                DeviceTrustError::ReplayDetected
            ))
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(suffix(&path, ".lock"));
    }
    #[cfg(unix)]
    #[test]
    fn registry_pins_symlinked_parent_to_its_canonical_directory() {
        use std::os::unix::fs::symlink;
        let root = path();
        fs::create_dir(&root).unwrap();
        let real_parent = root.join("real");
        let alias_parent = root.join("alias");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &alias_parent).unwrap();

        let admin = SigningKey::from_bytes(&[7; 32]);
        let registry_path = alias_parent.join("registry.db");
        let canonical_parent = fs::canonicalize(&real_parent).unwrap();
        let store = open(&registry_path, &admin);
        assert_eq!(store.path, canonical_parent.join("registry.db"));
        assert_eq!(store.lock_path, canonical_parent.join("registry.db.lock"));
        drop(store);

        assert!(real_parent.join("registry.db").is_file());
        assert!(real_parent.join("registry.db.lock").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn registry_rejects_symlinked_primary_lock_and_temp_paths() {
        use std::os::unix::fs::symlink;
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let target = path.with_extension("outside");
        fs::write(&target, b"do not modify").unwrap();

        symlink(&target, &path).unwrap();
        assert!(
            DurableDeviceRegistry::open(
                &path,
                vec![("admin-v1".into(), admin.verifying_key())],
                DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32])
            )
            .is_err_and(|error| matches!(
                error,
                DurableDeviceTrustError::Io(message)
                    if message.contains("refusing non-regular registry path")
            )),
            "primary snapshot symlink must be rejected"
        );
        fs::remove_file(&path).unwrap();

        symlink(&target, suffix(&path, ".lock")).unwrap();
        assert!(
            DurableDeviceRegistry::open(
                &path,
                vec![("admin-v1".into(), admin.verifying_key())],
                DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32])
            )
            .is_err_and(|error| matches!(
                error,
                DurableDeviceTrustError::Io(message)
                    if message.contains("refusing non-regular registry path")
            )),
            "lock symlink must be rejected"
        );
        fs::remove_file(suffix(&path, ".lock")).unwrap();

        symlink(&target, suffix(&path, ".tmp")).unwrap();
        let result = atomic_write(&path, b"replacement", false);
        assert!(
            result.is_err(),
            "temporary snapshot symlink must be rejected"
        );
        assert_eq!(fs::read(&target).unwrap(), b"do not modify");

        let _ = fs::remove_file(suffix(&path, ".tmp"));

        symlink(&target, suffix(&path, ".anchor-restore.tmp")).unwrap();
        assert!(restore_snapshot_from_backup(&path, b"authenticated backup").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do not modify");

        let _ = fs::remove_file(suffix(&path, ".anchor-restore.tmp"));
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn modified_snapshot_fails_closed() {
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let store = open(&path, &admin);
        store
            .apply_admin_command(&enroll(&admin, &device), 200)
            .unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.windows(3).position(|w| w == b"|E|").unwrap() + 1;
        bytes[index] = b'R';
        fs::write(&path, bytes).unwrap();
        assert!(DurableDeviceRegistry::open(
            &path,
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32])
        )
        .is_err());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(suffix(&path, ".lock"));
    }
    #[derive(Default)]
    struct MemoryAnchor {
        record: std::sync::Mutex<Option<SnapshotAnchorRecord>>,
        fail_next_cas: std::sync::atomic::AtomicBool,
    }

    impl MonotonicSnapshotAnchor for MemoryAnchor {
        fn load(&self, _registry_id: &str) -> Result<Option<SnapshotAnchorRecord>, String> {
            Ok(self.record.lock().map_err(|e| e.to_string())?.clone())
        }

        fn compare_and_set(
            &self,
            _registry_id: &str,
            expected_generation: Option<u64>,
            next: SnapshotAnchorRecord,
        ) -> Result<bool, String> {
            use std::sync::atomic::Ordering;
            if self.fail_next_cas.swap(false, Ordering::SeqCst) {
                return Err("simulated external anchor outage".into());
            }
            let mut current = self.record.lock().map_err(|e| e.to_string())?;
            if current.as_ref().map(SnapshotAnchorRecord::generation) != expected_generation
                || next.generation() != expected_generation.unwrap_or(0).saturating_add(1)
            {
                return Ok(false);
            }
            *current = Some(next);
            Ok(true)
        }
    }

    #[test]
    fn external_anchor_detects_rollback_to_an_older_valid_hmac_snapshot() {
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let anchor = std::sync::Arc::new(MemoryAnchor::default());
        let store = DurableDeviceRegistry::open_with_anchor(
            &path,
            "tenant-a-device-registry",
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32]),
            anchor.clone(),
        )
        .unwrap();
        store
            .apply_admin_command(&enroll(&admin, &device), 200)
            .unwrap();

        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [8; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:acquire".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest([]).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        store.authenticate_request(&signed, b"", 250).unwrap();
        assert_eq!(
            anchor
                .load("tenant-a-device-registry")
                .unwrap()
                .unwrap()
                .generation(),
            3
        );
        drop(store);

        // The backup is a valid, correctly HMAC-authenticated but older snapshot.
        let old_snapshot = fs::read(suffix(&path, ".bak")).unwrap();
        fs::write(&path, old_snapshot).unwrap();
        let reopened = DurableDeviceRegistry::open_with_anchor(
            &path,
            "tenant-a-device-registry",
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32]),
            anchor,
        );
        assert!(matches!(
            reopened,
            Err(DurableDeviceTrustError::AnchorMismatch)
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(suffix(&path, ".bak"));
        let _ = fs::remove_file(suffix(&path, ".lock"));
        let _ = fs::remove_file(suffix(&path, ".anchor-restore.tmp"));
    }

    #[test]
    fn external_anchor_outage_restores_the_last_committed_backup() {
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let anchor = std::sync::Arc::new(MemoryAnchor::default());
        let store = DurableDeviceRegistry::open_with_anchor(
            &path,
            "tenant-a-device-registry",
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32]),
            anchor.clone(),
        )
        .unwrap();
        store
            .apply_admin_command(&enroll(&admin, &device), 200)
            .unwrap();

        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [10; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:acquire".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest([]).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        anchor
            .fail_next_cas
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            store.authenticate_request(&signed, b"", 250),
            Err(DurableDeviceTrustError::AnchorUnavailable(_))
        ));
        drop(store);

        // The local write happened, but the external CAS did not. Reopen must
        // restore the backup that still matches the last committed anchor.
        let reopened = DurableDeviceRegistry::open_with_anchor(
            &path,
            "tenant-a-device-registry",
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1", [0x42; 32]),
            anchor,
        )
        .unwrap();
        assert!(reopened.authenticate_request(&signed, b"", 251).is_ok());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(suffix(&path, ".bak"));
        let _ = fs::remove_file(suffix(&path, ".lock"));
    }

    #[test]
    fn authenticated_request_cannot_verify_evidence_after_device_key_rotation() {
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let store = open(&path, &admin);
        store
            .apply_admin_command(&enroll(&admin, &device), 200)
            .unwrap();

        let body = b"canonical worker telemetry claims";
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [8; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "worker-telemetry:admission".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: Sha256::digest(b"manifest-v1").into(),
            body_sha256: Sha256::digest(body).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        let authenticated = store
            .authenticate_request_for(
                &signed,
                "POST",
                "worker-telemetry:admission",
                body,
                250,
            )
            .unwrap();
        assert!(store
            .verifying_key_for_authenticated_request(&authenticated)
            .is_ok());

        let replacement = SigningKey::from_bytes(&[11; 32]);
        let mut rotate = SignedDeviceAdminCommand {
            action: DeviceCommandAction::RotateKey,
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            admin_key_id: "admin-v1".into(),
            target_key_id: "device-key-v2".into(),
            target_public_key: Some(replacement.verifying_key().to_bytes()),
            issued_at_unix_ms: 300,
            expires_at_unix_ms: 1_000,
            nonce: [9; 16],
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        rotate.old_device_signature =
            Some(device.sign(&rotation_proof_bytes(&rotate)).to_bytes());
        rotate.new_device_signature =
            Some(replacement.sign(&enrollment_proof_bytes(&rotate)).to_bytes());
        rotate.signature = admin.sign(&admin_command_bytes(&rotate)).to_bytes();
        assert_eq!(store.apply_admin_command(&rotate, 350), Ok(2));

        assert_eq!(
            store.verifying_key_for_authenticated_request(&authenticated),
            Err(DurableDeviceTrustError::Trust(
                DeviceTrustError::StaleKeyGeneration
            ))
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(suffix(&path, ".lock"));
        let _ = fs::remove_file(suffix(&path, ".bak"));
    }

    #[test]
    fn concurrent_handles_consume_a_request_nonce_once() {
        let path = path();
        let admin = SigningKey::from_bytes(&[7; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let first = open(&path, &admin);
        first
            .apply_admin_command(&enroll(&admin, &device), 200)
            .unwrap();
        let second = open(&path, &admin);
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [6; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:acquire".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest([]).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        let signed2 = signed.clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b1 = barrier.clone();
        let t1 = std::thread::spawn(move || {
            b1.wait();
            first.authenticate_request(&signed, b"", 250)
        });
        let b2 = barrier.clone();
        let t2 = std::thread::spawn(move || {
            b2.wait();
            second.authenticate_request(&signed2, b"", 250)
        });
        let results = [t1.join().unwrap(), t2.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| r.as_ref().err()
                    == Some(&DurableDeviceTrustError::Trust(
                        DeviceTrustError::ReplayDetected
                    )))
                .count(),
            1
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(suffix(&path, ".lock"));
    }
}
