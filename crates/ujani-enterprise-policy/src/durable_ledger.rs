//! Durable, cross-thread and cross-process reservation ledger.
//!
//! Each transaction reloads the latest snapshot under an OS file lock, applies
//! one policy operation, and commits an HMAC-authenticated snapshot using a same-directory
//! temp file plus backup/rename recovery. The raw lease capability is never
//! persisted; only its domain-separated digest is stored.
use crate::device_trust::durable::{MonotonicSnapshotAnchor, SnapshotAnchorRecord};
use crate::{
    Admission, ClassPolicy, Device, Ledger, SchedulingContext, VerifiedAdminApproval, Workload,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

const LEDGER_HEADER: &str = "UJANI-ENTERPRISE-LEDGER-V2";
const LEDGER_MAC_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-LEDGER-HMAC-SHA256-V2\0";
const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableLedgerError {
    Io(String),
    CorruptState,
    InvalidRecord,
    CapacityExceeded,
    LockPoisoned,
    AnchorUnavailable(String),
    AnchorMismatch,
    AnchorConflict,
    AnchorGenerationExhausted,
}

impl std::fmt::Display for DurableLedgerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "durable ledger I/O failed: {message}"),
            Self::CorruptState => write!(
                formatter,
                "durable ledger is corrupt or has an invalid checksum"
            ),
            Self::InvalidRecord => write!(
                formatter,
                "durable ledger contains an invalid or duplicate record"
            ),
            Self::CapacityExceeded => write!(
                formatter,
                "durable ledger snapshot would exceed the 16 MiB safety limit; committed state was not changed"
            ),
            Self::LockPoisoned => write!(formatter, "durable ledger thread lock is poisoned"),
            Self::AnchorUnavailable(message) => write!(formatter, "external ledger monotonic anchor unavailable: {message}"),
            Self::AnchorMismatch => write!(formatter, "durable ledger snapshot does not match its external monotonic anchor"),
            Self::AnchorConflict => write!(formatter, "external ledger anchor rejected a stale generation"),
            Self::AnchorGenerationExhausted => write!(formatter, "external ledger anchor generation exhausted"),
        }
    }
}

impl std::error::Error for DurableLedgerError {}

impl From<std::io::Error> for DurableLedgerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableLedgerSnapshot {
    pub active_jobs: usize,
    pub reserved_cpu_millis: u64,
    pub reserved_memory_mb: u64,
}

/// An integrity key supplied by a trusted secret provider (for example, an
/// OS keyring, TPM-backed service, or HSM adapter). Never store this key beside
/// the ledger file. Debug output intentionally redacts key bytes.
#[derive(Clone)]
pub struct LedgerIntegrityKey {
    key_id: String,
    key: [u8; 32],
}

impl LedgerIntegrityKey {
    /// Creates an integrity key from a protected key-provider result.
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key,
        }
    }

    /// Returns the non-secret identifier associated with this key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl std::fmt::Debug for LedgerIntegrityKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LedgerIntegrityKey")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for LedgerIntegrityKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A durable reservation store. Separate instances pointing to the same path
/// coordinate through an OS advisory file lock. Integrity keys are injected by
/// the trusted caller and must be held outside the writable ledger directory.
#[derive(Clone)]
pub struct DurableLedger {
    path: PathBuf,
    lock_path: PathBuf,
    thread_lock: Arc<Mutex<()>>,
    integrity_keys: Arc<HashMap<String, LedgerIntegrityKey>>,
    active_key_id: String,
    anchor_namespace: Option<String>,
    anchor: Option<Arc<dyn MonotonicSnapshotAnchor>>,
}

impl std::fmt::Debug for DurableLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableLedger")
            .field("path", &self.path)
            .field("active_key_id", &self.active_key_id)
            .field("anchor_enabled", &self.anchor.is_some())
            .finish()
    }
}

impl DurableLedger {
    /// Opens a V2 authenticated ledger. The key set must contain the active key
    /// and any previous keys still needed to verify snapshots during rotation.
    /// The caller must load keys from protected storage. Legacy checksum-only
    /// V1 ledgers are rejected rather than silently trusted.
    pub fn open_with_integrity_keys(
        path: impl AsRef<Path>,
        active_key_id: &str,
        keys: Vec<LedgerIntegrityKey>,
    ) -> Result<Self, DurableLedgerError> {
        Self::open_internal(path, active_key_id, keys, None)
    }

    /// Open a V2 ledger whose snapshot digest and generation are pinned by an
    /// external linearizable monotonic anchor. Existing unanchored files are
    /// rejected; migration must be explicit and separately audited.
    ///
    /// `registry_id` must be unique for this ledger within the provider namespace;
    /// do not reuse the identifier used by the device-trust registry or another
    /// ledger sharing the same anchor, because their records would collide.
    pub fn open_with_anchor(
        path: impl AsRef<Path>,
        registry_id: impl Into<String>,
        active_key_id: &str,
        keys: Vec<LedgerIntegrityKey>,
        anchor: Arc<dyn MonotonicSnapshotAnchor>,
    ) -> Result<Self, DurableLedgerError> {
        let registry_id = registry_id.into();
        if !valid_stored_identifier(&registry_id, 128) {
            return Err(DurableLedgerError::InvalidRecord);
        }
        Self::open_internal(path, active_key_id, keys, Some((registry_id, anchor)))
    }

    fn open_internal(
        path: impl AsRef<Path>,
        active_key_id: &str,
        keys: Vec<LedgerIntegrityKey>,
        anchor: Option<(String, Arc<dyn MonotonicSnapshotAnchor>)>,
    ) -> Result<Self, DurableLedgerError> {
        if !valid_stored_identifier(active_key_id, 128) || keys.is_empty() {
            return Err(DurableLedgerError::InvalidRecord);
        }
        let mut integrity_keys = HashMap::new();
        for key in keys {
            if !valid_stored_identifier(key.key_id(), 128)
                || integrity_keys.insert(key.key_id.clone(), key).is_some()
            {
                return Err(DurableLedgerError::InvalidRecord);
            }
        }
        if !integrity_keys.contains_key(active_key_id) {
            return Err(DurableLedgerError::InvalidRecord);
        }

        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let (anchor_namespace, anchor) = match anchor {
            Some((namespace, provider)) => (Some(namespace), Some(provider)),
            None => (None, None),
        };
        let store = Self {
            lock_path: append_suffix(&path, ".lock"),
            path,
            thread_lock: Arc::new(Mutex::new(())),
            integrity_keys: Arc::new(integrity_keys),
            active_key_id: active_key_id.to_string(),
            anchor_namespace,
            anchor,
        };
        store.transact(|_| Ok(()))?;
        Ok(store)
    }

    /// Reserve capacity with an opaque capability. The caller must generate
    /// the 32-byte token using an OS CSPRNG and keep it outside the workload.
    /// This raw-context method is crate-private; public callers should use the
    /// signed-evidence wrapper in scheduling_evidence.
    #[allow(clippy::too_many_arguments)] // Keep all admission and capability inputs explicit.
    pub(crate) fn admit_and_reserve_with_lease(
        &self,
        device: &Device,
        workload: &Workload,
        context: &SchedulingContext,
        policies: &[ClassPolicy],
        approvals: &[VerifiedAdminApproval],
        now_unix_ms: u64,
        lease_token: &[u8; 32],
    ) -> Result<Admission, DurableLedgerError> {
        self.transact(|ledger| {
            Ok(ledger.admit_and_reserve_with_lease(
                device,
                workload,
                context,
                policies,
                approvals,
                now_unix_ms,
                lease_token,
            ))
        })
    }

    pub(crate) fn consume_challenge_nonce(
        &self,
        nonce: [u8; 16],
        expires_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<bool, DurableLedgerError> {
        self.transact(|ledger| {
            Ok(ledger.consume_challenge_nonce(nonce, expires_unix_ms, now_unix_ms))
        })
    }

    /// Renews a workload lease only when the supplied capability matches.
    pub fn renew_lease(
        &self,
        workload_id: &str,
        lease_token: &[u8; 32],
        now_unix_ms: u64,
    ) -> Result<bool, DurableLedgerError> {
        self.transact(|ledger| Ok(ledger.renew_lease(workload_id, lease_token, now_unix_ms)))
    }

    /// Releases a workload lease only when the supplied capability matches.
    pub fn release_lease(
        &self,
        workload_id: &str,
        lease_token: &[u8; 32],
    ) -> Result<bool, DurableLedgerError> {
        self.transact(|ledger| Ok(ledger.release_lease(workload_id, lease_token)))
    }

    /// Removes expired leases and returns the number of removed jobs.
    pub fn expire_leases(&self, now_unix_ms: u64) -> Result<usize, DurableLedgerError> {
        self.transact(|ledger| {
            let before = ledger.jobs.len();
            ledger.expire(now_unix_ms);
            Ok(before.saturating_sub(ledger.jobs.len()))
        })
    }

    /// Returns aggregate reservations from the latest committed ledger snapshot.
    pub fn snapshot(&self) -> Result<DurableLedgerSnapshot, DurableLedgerError> {
        self.transact(|ledger| {
            let mut cpu = 0u64;
            let mut memory = 0u64;
            for (reserved_cpu, reserved_memory) in ledger.used.values() {
                cpu = cpu.saturating_add(u64::from(*reserved_cpu));
                memory = memory.saturating_add(*reserved_memory);
            }
            Ok(DurableLedgerSnapshot {
                active_jobs: ledger.jobs.len(),
                reserved_cpu_millis: cpu,
                reserved_memory_mb: memory,
            })
        })
    }

    fn load_anchored_ledger(
        &self,
        anchor_record: Option<&SnapshotAnchorRecord>,
    ) -> Result<Ledger, DurableLedgerError> {
        let backup = append_suffix(&self.path, ".bak");
        match anchor_record {
            Some(record) => {
                if self.path.exists() {
                    let bytes = read_snapshot(&self.path)?;
                    if snapshot_sha256(&bytes) == record.snapshot_sha256() {
                        return deserialize_snapshot(&bytes, &self.integrity_keys);
                    }
                }
                if backup.exists() {
                    let bytes = read_snapshot(&backup)?;
                    if snapshot_sha256(&bytes) == record.snapshot_sha256() {
                        restore_anchored_backup(&self.path, &backup)?;
                        return deserialize_snapshot(&bytes, &self.integrity_keys);
                    }
                }
                Err(DurableLedgerError::AnchorMismatch)
            }
            None => {
                if self.path.exists() || backup.exists() {
                    return Err(DurableLedgerError::AnchorMismatch);
                }
                Ok(Ledger::default())
            }
        }
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut Ledger) -> Result<T, DurableLedgerError>,
    ) -> Result<T, DurableLedgerError> {
        let _thread_guard = self
            .thread_lock
            .lock()
            .map_err(|_| DurableLedgerError::LockPoisoned)?;
        let mut lock_options = OpenOptions::new();
        lock_options
            .create(true)
            .truncate(false)
            .read(true)
            .write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock_file = lock_options.open(&self.lock_path)?;
        lock_file.lock()?;

        let anchor_record = match (&self.anchor, &self.anchor_namespace) {
            (Some(anchor), Some(namespace)) => anchor
                .load(namespace)
                .map_err(DurableLedgerError::AnchorUnavailable)?,
            (None, None) => None,
            _ => return Err(DurableLedgerError::AnchorMismatch),
        };
        let mut ledger = if self.anchor.is_some() {
            self.load_anchored_ledger(anchor_record.as_ref())?
        } else {
            load_or_recover(&self.path, &self.integrity_keys)?
        };
        let result = operation(&mut ledger)?;
        let active_key = self
            .integrity_keys
            .get(&self.active_key_id)
            .ok_or(DurableLedgerError::InvalidRecord)?;
        let bytes = serialize_snapshot(&ledger, &self.active_key_id, &active_key.key);
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(DurableLedgerError::CapacityExceeded);
        }
        // Read-only transactions do not advance the external monotonic generation.
        if anchor_record
            .as_ref()
            .is_some_and(|record| record.snapshot_sha256() == snapshot_sha256(&bytes))
        {
            return Ok(result);
        }

        if let (Some(anchor), Some(namespace)) = (&self.anchor, &self.anchor_namespace) {
            persist_snapshot(
                &self.path,
                &ledger,
                &self.active_key_id,
                &active_key.key,
                true,
            )?;
            let expected_generation = anchor_record.as_ref().map(SnapshotAnchorRecord::generation);
            let generation = expected_generation
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(DurableLedgerError::AnchorGenerationExhausted)?;
            let next = SnapshotAnchorRecord::new(generation, snapshot_sha256(&bytes))
                .ok_or(DurableLedgerError::AnchorGenerationExhausted)?;
            match anchor.compare_and_set(namespace, expected_generation, next.clone()) {
                Ok(true) => {
                    let backup = append_suffix(&self.path, ".bak");
                    if backup.exists() {
                        let _ = fs::remove_file(backup);
                    }
                    let _ = sync_parent_directory(&self.path);
                }
                Ok(false) => {
                    restore_previous_snapshot(&self.path)?;
                    return Err(DurableLedgerError::AnchorConflict);
                }
                Err(error) => {
                    // Resolve an ambiguous transport result before rolling back: the
                    // anchor may have committed even if its response was lost.
                    match anchor.load(namespace) {
                        Ok(Some(observed)) if observed == next => {
                            let backup = append_suffix(&self.path, ".bak");
                            if backup.exists() {
                                let _ = fs::remove_file(backup);
                            }
                            sync_parent_directory(&self.path);
                        }
                        Ok(_) => {
                            restore_previous_snapshot(&self.path)?;
                            return Err(DurableLedgerError::AnchorUnavailable(error));
                        }
                        Err(load_error) => {
                            return Err(DurableLedgerError::AnchorUnavailable(format!(
                                "{error}; commit outcome could not be verified: {load_error}"
                            )));
                        }
                    }
                }
            }
        } else {
            persist_snapshot(
                &self.path,
                &ledger,
                &self.active_key_id,
                &active_key.key,
                false,
            )?;
        }
        Ok(result)
    }
}

fn snapshot_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Renames a snapshot and makes the directory-entry update durable when anchored.
fn rename_snapshot_path(
    from: &Path,
    to: &Path,
    require_durability: bool,
) -> Result<(), DurableLedgerError> {
    #[cfg(unix)]
    {
        fs::rename(from, to)?;
        if require_durability {
            sync_parent_directory(to)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if require_durability {
            return Err(DurableLedgerError::Io(
                "anchored snapshot durability is unavailable on Windows in this safe-code build; the external anchor was not advanced".into(),
            ));
        }
        fs::rename(from, to).map_err(DurableLedgerError::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        if require_durability {
            return Err(DurableLedgerError::Io(
                "anchored snapshot directory durability is unsupported on this platform".into(),
            ));
        }
        fs::rename(from, to).map_err(DurableLedgerError::from)
    }
}

/// Syncs the directory entry containing a snapshot, including paths relative to the current directory.
fn sync_parent_directory(path: &Path) -> Result<(), DurableLedgerError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Restore the backup whose digest was already verified against the anchor.
fn restore_anchored_backup(path: &Path, backup: &Path) -> Result<(), DurableLedgerError> {
    let temp = append_suffix(path, ".anchor-restore.tmp");
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    fs::copy(backup, &temp)?;
    OpenOptions::new().write(true).open(&temp)?.sync_all()?;
    rename_snapshot_path(&temp, path, true)?;
    // The primary snapshot is now durable and matches the anchor. A stale backup
    // after a crash is harmless because the primary digest is checked first.
    let _ = fs::remove_file(backup);
    sync_parent_directory(path)?;
    Ok(())
}

/// Roll back a local snapshot if the external anchor refused to advance.
fn restore_previous_snapshot(path: &Path) -> Result<(), DurableLedgerError> {
    let backup = append_suffix(path, ".bak");
    if backup.exists() {
        restore_anchored_backup(path, &backup)
    } else if path.exists() {
        // Move the uncommitted candidate out of the primary name with the same
        // durability guarantee as a rename. A leftover orphan is ignored on load.
        let orphan = append_suffix(path, ".rollback-orphan");
        if orphan.exists() {
            let _ = fs::remove_file(&orphan);
        }
        rename_snapshot_path(path, &orphan, true)?;
        let _ = fs::remove_file(orphan);
        Ok(())
    } else {
        Ok(())
    }
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(*byte >> 4) as usize] as char);
        output.push(HEX[(*byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, DurableLedgerError> {
    if !value.len().is_multiple_of(2) {
        return Err(DurableLedgerError::InvalidRecord);
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(DurableLedgerError::InvalidRecord)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(DurableLedgerError::InvalidRecord)?;
        output.push(((high << 4) | low) as u8);
    }
    Ok(output)
}

fn decode_hex_string(value: &str) -> Result<String, DurableLedgerError> {
    String::from_utf8(hex_decode(value)?).map_err(|_| DurableLedgerError::InvalidRecord)
}

fn valid_stored_identifier(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
}

type LedgerHmacSha256 = hmac::Hmac<Sha256>;

fn ledger_mac(key: &[u8; 32], key_id: &str, body: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = LedgerHmacSha256::new_from_slice(key).expect("HMAC accepts a fixed-size key");
    mac.update(LEDGER_MAC_DOMAIN);
    mac.update(&(key_id.len() as u32).to_be_bytes());
    mac.update(key_id.as_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

fn verify_ledger_mac(key: &[u8; 32], key_id: &str, body: &[u8], expected: &[u8]) -> bool {
    use hmac::Mac;
    let Ok(mut mac) = LedgerHmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(LEDGER_MAC_DOMAIN);
    mac.update(&(key_id.len() as u32).to_be_bytes());
    mac.update(key_id.as_bytes());
    mac.update(body);
    mac.verify_slice(expected).is_ok()
}

fn serialize_snapshot(ledger: &Ledger, key_id: &str, key: &[u8; 32]) -> Vec<u8> {
    let mut body = format!("{LEDGER_HEADER}\n");
    let mut workload_ids = ledger.jobs.keys().collect::<Vec<_>>();
    workload_ids.sort();
    for workload_id in workload_ids {
        let (device_id, cpu, memory, expires, approval_id) = ledger
            .jobs
            .get(workload_id)
            .expect("key collected from jobs");
        let approval = approval_id
            .as_deref()
            .map(|value| hex_encode(value.as_bytes()))
            .unwrap_or_else(|| "-".into());
        let token = ledger
            .lease_token_hashes
            .get(workload_id)
            .map(|value| hex_encode(value))
            .unwrap_or_else(|| "-".into());
        body.push_str(&format!(
            "J\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            hex_encode(workload_id.as_bytes()),
            hex_encode(device_id.as_bytes()),
            cpu,
            memory,
            expires,
            approval,
            token,
        ));
    }
    let mut approvals = ledger.consumed_approvals.iter().collect::<Vec<_>>();
    approvals.sort();
    for approval_id in approvals {
        body.push_str(&format!("A\t{}\n", hex_encode(approval_id.as_bytes())));
    }
    let mut challenges = ledger.consumed_challenges.iter().collect::<Vec<_>>();
    challenges.sort_by_key(|(nonce, _)| **nonce);
    for (nonce, expires) in challenges {
        body.push_str(&format!("C\t{}\t{}\n", hex_encode(nonce), expires));
    }
    let mac = ledger_mac(key, key_id, body.as_bytes());
    body.push_str(&format!("M\t{}\t{}\n", key_id, hex_encode(&mac)));
    body.into_bytes()
}

fn deserialize_snapshot(
    bytes: &[u8],
    integrity_keys: &HashMap<String, LedgerIntegrityKey>,
) -> Result<Ledger, DurableLedgerError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DurableLedgerError::CorruptState)?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES || !text.ends_with('\n') {
        return Err(DurableLedgerError::CorruptState);
    }
    let mac_start = text.rfind("M\t").ok_or(DurableLedgerError::CorruptState)?;
    let body = &text[..mac_start];
    let mac_line = &text[mac_start..];
    let mut mac_fields = mac_line
        .strip_suffix('\n')
        .ok_or(DurableLedgerError::CorruptState)?
        .split('\t');
    if mac_fields.next() != Some("M") {
        return Err(DurableLedgerError::CorruptState);
    }
    let key_id = mac_fields.next().ok_or(DurableLedgerError::CorruptState)?;
    let encoded_mac = mac_fields.next().ok_or(DurableLedgerError::CorruptState)?;
    if mac_fields.next().is_some() || !valid_stored_identifier(key_id, 128) {
        return Err(DurableLedgerError::CorruptState);
    }
    let key = integrity_keys
        .get(key_id)
        .ok_or(DurableLedgerError::CorruptState)?;
    let expected_mac = hex_decode(encoded_mac)?;
    if !verify_ledger_mac(&key.key, key_id, body.as_bytes(), &expected_mac) {
        return Err(DurableLedgerError::CorruptState);
    }

    let mut lines = body.lines();
    if lines.next() != Some(LEDGER_HEADER) {
        return Err(DurableLedgerError::CorruptState);
    }
    let mut ledger = Ledger::default();
    let mut token_hashes = HashSet::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        match fields.first().copied() {
            Some("J") if fields.len() == 8 => {
                let workload_id = decode_hex_string(fields[1])?;
                let device_id = decode_hex_string(fields[2])?;
                let cpu = fields[3]
                    .parse::<u32>()
                    .map_err(|_| DurableLedgerError::InvalidRecord)?;
                let memory = fields[4]
                    .parse::<u64>()
                    .map_err(|_| DurableLedgerError::InvalidRecord)?;
                let expires = fields[5]
                    .parse::<u64>()
                    .map_err(|_| DurableLedgerError::InvalidRecord)?;
                let approval_id = if fields[6] == "-" {
                    None
                } else {
                    Some(decode_hex_string(fields[6])?)
                };
                if !valid_stored_identifier(&workload_id, 128)
                    || !valid_stored_identifier(&device_id, 128)
                    || cpu == 0
                    || memory == 0
                    || expires == 0
                    || approval_id
                        .as_deref()
                        .is_some_and(|value| !valid_stored_identifier(value, 128))
                    || ledger.jobs.contains_key(&workload_id)
                {
                    return Err(DurableLedgerError::InvalidRecord);
                }
                ledger.jobs.insert(
                    workload_id.clone(),
                    (device_id.clone(), cpu, memory, expires, approval_id),
                );
                let used = ledger.used.entry(device_id).or_insert((0, 0));
                used.0 = used
                    .0
                    .checked_add(cpu)
                    .ok_or(DurableLedgerError::InvalidRecord)?;
                used.1 = used
                    .1
                    .checked_add(memory)
                    .ok_or(DurableLedgerError::InvalidRecord)?;
                if fields[7] != "-" {
                    let token = hex_decode(fields[7])?;
                    let token: [u8; 32] = token
                        .try_into()
                        .map_err(|_| DurableLedgerError::InvalidRecord)?;
                    if !token_hashes.insert(token) {
                        return Err(DurableLedgerError::InvalidRecord);
                    }
                    ledger.lease_token_hashes.insert(workload_id, token);
                }
            }
            Some("A") if fields.len() == 2 => {
                let approval_id = decode_hex_string(fields[1])?;
                if !valid_stored_identifier(&approval_id, 128)
                    || !ledger.consumed_approvals.insert(approval_id)
                {
                    return Err(DurableLedgerError::InvalidRecord);
                }
            }
            Some("C") if fields.len() == 3 => {
                let nonce = hex_decode(fields[1])?
                    .try_into()
                    .map_err(|_| DurableLedgerError::InvalidRecord)?;
                let expires = fields[2]
                    .parse::<u64>()
                    .map_err(|_| DurableLedgerError::InvalidRecord)?;
                if expires == 0 || ledger.consumed_challenges.insert(nonce, expires).is_some() {
                    return Err(DurableLedgerError::InvalidRecord);
                }
            }
            _ => return Err(DurableLedgerError::InvalidRecord),
        }
    }
    Ok(ledger)
}

fn read_snapshot(path: &Path) -> Result<Vec<u8>, DurableLedgerError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_LEDGER_BYTES {
        return Err(DurableLedgerError::CorruptState);
    }
    Ok(fs::read(path)?)
}

fn load_or_recover(
    path: &Path,
    integrity_keys: &HashMap<String, LedgerIntegrityKey>,
) -> Result<Ledger, DurableLedgerError> {
    let backup = append_suffix(path, ".bak");
    if !path.exists() {
        if backup.exists() {
            fs::rename(&backup, path)?;
        } else {
            return Ok(Ledger::default());
        }
    }
    let current = read_snapshot(path);
    match current.and_then(|bytes| deserialize_snapshot(&bytes, integrity_keys)) {
        Ok(ledger) => {
            if backup.exists() {
                let _ = fs::remove_file(backup);
            }
            Ok(ledger)
        }
        Err(current_error) => {
            if !backup.exists() {
                return Err(current_error);
            }
            let backup_bytes = read_snapshot(&backup)?;
            let recovered = deserialize_snapshot(&backup_bytes, integrity_keys)?;
            let corrupt = append_suffix(path, ".corrupt");
            if corrupt.exists() {
                fs::remove_file(&corrupt)?;
            }
            if path.exists() {
                fs::rename(path, &corrupt)?;
            }
            fs::rename(&backup, path)?;
            Ok(recovered)
        }
    }
}

fn persist_snapshot(
    path: &Path,
    ledger: &Ledger,
    key_id: &str,
    key: &[u8; 32],
    preserve_backup: bool,
) -> Result<(), DurableLedgerError> {
    // This crate forbids unsafe code. Until a reviewed safe Windows durability
    // adapter is available, do not write a candidate that could be anchored
    // before its directory entry is known to be durable.
    #[cfg(windows)]
    if preserve_backup {
        return Err(DurableLedgerError::Io(
            "anchored snapshot writes are disabled on Windows until a safe durable-rename adapter is available".into(),
        ));
    }
    let temp = append_suffix(path, ".tmp");
    let backup = append_suffix(path, ".bak");
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let bytes = serialize_snapshot(ledger, key_id, key);
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(DurableLedgerError::CapacityExceeded);
    }
    let mut temp_options = OpenOptions::new();
    temp_options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        temp_options.mode(0o600);
    }
    let mut file = temp_options.open(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;

    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup)?;
        }
        rename_snapshot_path(path, &backup, preserve_backup)?;
    }
    if let Err(error) = rename_snapshot_path(&temp, path, preserve_backup) {
        if backup.exists() && !path.exists() {
            let _ = rename_snapshot_path(&backup, path, preserve_backup);
        }
        return Err(error);
    }
    if preserve_backup {
        // The caller advances the external monotonic anchor only after this succeeds.
        sync_parent_directory(path)?;
    } else {
        // Unanchored operation retains best-effort durability behavior.
        let _ = sync_parent_directory(path);
    }
    if !preserve_backup && backup.exists() {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{workload_from_manifest, DataClassification, WorkloadManifest};
    use sha2::Digest;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn device() -> Device {
        Device {
            device_id: "worker-durable-01".into(),
            enrolled: true,
            admin_approved: true,
            available: true,
            allowed_workload_classes: vec!["inference".into()],
            remaining_cpu_millis: 1000,
            remaining_memory_mb: 1024,
        }
    }

    fn workload(workload_id: &str) -> Workload {
        workload_from_manifest(&WorkloadManifest {
            schema_version: 1,
            workload_id: workload_id.into(),
            class: "inference".into(),
            model: "llama3.2".into(),
            requested_cpu_millis: 1000,
            requested_memory_mb: 1024,
            max_runtime_ms: 60_000,
            data_classification: DataClassification::Internal,
            network_access: false,
        })
        .unwrap()
    }

    fn context() -> SchedulingContext {
        SchedulingContext {
            owner_opted_in: true,
            within_admin_schedule: true,
            interactive_user_present: false,
            on_ac_power: true,
            device_already_running: true,
            thermal_state_safe: true,
            network_policy_allows: true,
            data_classification_allows: true,
            telemetry_fresh: true,
        }
    }

    fn policies() -> Vec<ClassPolicy> {
        vec![ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 1000,
            max_memory_mb: 1024,
        }]
    }

    fn integrity_key(id: &str, byte: u8) -> LedgerIntegrityKey {
        LedgerIntegrityKey::new(id, [byte; 32])
    }

    fn open_ledger(path: &Path) -> Result<DurableLedger, DurableLedgerError> {
        DurableLedger::open_with_integrity_keys(
            path,
            "test-v1",
            vec![integrity_key("test-v1", 0xA5)],
        )
    }

    #[derive(Default)]
    struct MemoryAnchor {
        records: Mutex<HashMap<String, SnapshotAnchorRecord>>,
        reject_next: std::sync::atomic::AtomicBool,
        lose_next_response_after_commit: std::sync::atomic::AtomicBool,
    }

    impl MonotonicSnapshotAnchor for MemoryAnchor {
        fn load(&self, registry_id: &str) -> Result<Option<SnapshotAnchorRecord>, String> {
            Ok(self
                .records
                .lock()
                .map_err(|_| "anchor lock poisoned".to_string())?
                .get(registry_id)
                .cloned())
        }

        fn compare_and_set(
            &self,
            registry_id: &str,
            expected_generation: Option<u64>,
            next: SnapshotAnchorRecord,
        ) -> Result<bool, String> {
            if self
                .reject_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Ok(false);
            }
            let mut records = self
                .records
                .lock()
                .map_err(|_| "anchor lock poisoned".to_string())?;
            let current = records
                .get(registry_id)
                .map(SnapshotAnchorRecord::generation);
            if current != expected_generation
                || next.generation() != expected_generation.unwrap_or(0).saturating_add(1)
            {
                return Ok(false);
            }
            records.insert(registry_id.to_string(), next);
            if self
                .lose_next_response_after_commit
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err("simulated lost compare-and-set response".into());
            }
            Ok(true)
        }
    }

    fn open_anchored(
        path: &Path,
        anchor: Arc<dyn MonotonicSnapshotAnchor>,
    ) -> Result<DurableLedger, DurableLedgerError> {
        DurableLedger::open_with_anchor(
            path,
            "registry-test-a",
            "test-v1",
            vec![integrity_key("test-v1", 0xA5)],
            anchor,
        )
    }

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ujani-enterprise-{label}-{}-{nonce}.ledger",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        for suffix in [".lock", ".tmp", ".bak", ".corrupt"] {
            let candidate = append_suffix(path, suffix);
            let _ = fs::remove_file(candidate);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn anchored_open_rejects_existing_unanchored_ledger_without_migration() {
        let path = temp_path("anchor-reject-unanchored");
        let legacy = open_ledger(&path).unwrap();
        drop(legacy);
        let original = fs::read(&path).unwrap();
        let anchor = Arc::new(MemoryAnchor::default());
        assert!(matches!(
            open_anchored(&path, anchor),
            Err(DurableLedgerError::AnchorMismatch)
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
        cleanup(&path);
    }

    #[cfg(windows)]
    #[test]
    fn anchored_mode_fails_closed_without_safe_directory_durability_adapter() {
        let path = temp_path("anchor-windows-fail-closed");
        let anchor = Arc::new(MemoryAnchor::default());
        let error = open_anchored(&path, anchor.clone()).unwrap_err();
        assert!(matches!(
            error,
            DurableLedgerError::Io(message) if message.contains("Windows")
        ));
        assert!(anchor.load("registry-test-a").unwrap().is_none());
        assert!(!path.exists());
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn external_anchor_rejects_rollback_to_an_older_valid_hmac_snapshot() {
        let path = temp_path("anchor-rollback");
        let anchor = Arc::new(MemoryAnchor::default());
        let ledger = open_anchored(&path, anchor.clone()).unwrap();
        let older = fs::read(&path).unwrap();
        assert_eq!(
            anchor
                .load("registry-test-a")
                .unwrap()
                .unwrap()
                .generation(),
            1
        );
        assert_eq!(
            ledger
                .admit_and_reserve_with_lease(
                    &device(),
                    &workload("job-anchored"),
                    &context(),
                    &policies(),
                    &[],
                    1_000,
                    &[0x71u8; 32],
                )
                .unwrap(),
            Admission::Accept
        );
        let current = fs::read(&path).unwrap();
        assert_ne!(older, current);
        fs::write(&path, &older).unwrap();
        assert_eq!(
            ledger.snapshot().unwrap_err(),
            DurableLedgerError::AnchorMismatch
        );
        assert_eq!(fs::read(&path).unwrap(), older);
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn ambiguous_anchor_response_is_resolved_by_reading_back_committed_record() {
        let path = temp_path("anchor-ambiguous-response");
        let anchor = Arc::new(MemoryAnchor::default());
        let ledger = open_anchored(&path, anchor.clone()).unwrap();
        anchor
            .lose_next_response_after_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);

        assert_eq!(
            ledger
                .admit_and_reserve_with_lease(
                    &device(),
                    &workload("job-ambiguous-anchor"),
                    &context(),
                    &policies(),
                    &[],
                    1_000,
                    &[0x73u8; 32],
                )
                .unwrap(),
            Admission::Accept
        );

        let committed = anchor.load("registry-test-a").unwrap().unwrap();
        assert_eq!(committed.generation(), 2);
        assert_eq!(
            snapshot_sha256(&fs::read(&path).unwrap()),
            committed.snapshot_sha256()
        );
        assert!(!append_suffix(&path, ".bak").exists());
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn anchored_open_restores_only_a_backup_matching_the_external_digest() {
        let path = temp_path("anchor-backup");
        let anchor = Arc::new(MemoryAnchor::default());
        let ledger = open_anchored(&path, anchor.clone()).unwrap();
        let committed = fs::read(&path).unwrap();
        let backup = append_suffix(&path, ".bak");
        fs::write(&backup, &committed).unwrap();
        fs::write(&path, b"stale or corrupt primary").unwrap();
        drop(ledger);

        let restored = open_anchored(&path, anchor).unwrap();
        assert_eq!(restored.snapshot().unwrap().active_jobs, 0);
        assert_eq!(fs::read(&path).unwrap(), committed);
        assert!(!backup.exists());
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn anchor_conflict_rolls_back_the_unanchored_local_candidate() {
        let path = temp_path("anchor-conflict");
        let anchor = Arc::new(MemoryAnchor::default());
        let ledger = open_anchored(&path, anchor.clone()).unwrap();
        let committed = fs::read(&path).unwrap();
        anchor
            .reject_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            ledger
                .admit_and_reserve_with_lease(
                    &device(),
                    &workload("job-conflict"),
                    &context(),
                    &policies(),
                    &[],
                    1_000,
                    &[0x72u8; 32],
                )
                .unwrap_err(),
            DurableLedgerError::AnchorConflict
        );
        assert_eq!(fs::read(&path).unwrap(), committed);
        assert_eq!(
            anchor
                .load("registry-test-a")
                .unwrap()
                .unwrap()
                .generation(),
            1
        );
        cleanup(&path);
    }

    #[test]
    fn reservation_and_capability_survive_process_restart() {
        let path = temp_path("restart");
        let token = [0x51u8; 32];
        {
            let ledger = open_ledger(&path).unwrap();
            assert_eq!(
                ledger
                    .admit_and_reserve_with_lease(
                        &device(),
                        &workload("job-restart"),
                        &context(),
                        &policies(),
                        &[],
                        1_000,
                        &token,
                    )
                    .unwrap(),
                Admission::Accept
            );
            assert_eq!(ledger.snapshot().unwrap().active_jobs, 1);
        }
        {
            let ledger = open_ledger(&path).unwrap();
            assert!(ledger.renew_lease("job-restart", &token, 2_000).unwrap());
            assert!(!ledger.release_lease("job-restart", &[0x33u8; 32]).unwrap());
            assert!(ledger.release_lease("job-restart", &token).unwrap());
            assert_eq!(ledger.snapshot().unwrap().active_jobs, 0);
        }
        cleanup(&path);
    }

    #[test]
    fn corrupt_current_snapshot_recovers_last_committed_backup() {
        let path = temp_path("backup");
        let token = [0x52u8; 32];
        {
            let ledger = open_ledger(&path).unwrap();
            assert_eq!(
                ledger
                    .admit_and_reserve_with_lease(
                        &device(),
                        &workload("job-backup"),
                        &context(),
                        &policies(),
                        &[],
                        1_000,
                        &token,
                    )
                    .unwrap(),
                Admission::Accept
            );
        }
        let snapshot = fs::read(&path).unwrap();
        fs::write(append_suffix(&path, ".bak"), snapshot).unwrap();
        fs::write(&path, b"corrupt").unwrap();
        let ledger = open_ledger(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 1);
        cleanup(&path);
    }

    #[test]
    fn oversized_snapshot_is_rejected_without_replacing_committed_file() {
        let path = temp_path("capacity");
        fs::write(&path, b"previous committed snapshot").unwrap();

        let mut ledger = Ledger::default();
        let prefix = "a".repeat(120);
        for index in 0..70_000 {
            ledger
                .consumed_approvals
                .insert(format!("{prefix}-{index:06}"));
        }
        assert!(
            serialize_snapshot(&ledger, "test-v1", &[0xA5; 32]).len() as u64 > MAX_LEDGER_BYTES
        );

        assert_eq!(
            persist_snapshot(&path, &ledger, "test-v1", &[0xA5; 32], false),
            Err(DurableLedgerError::CapacityExceeded)
        );
        assert_eq!(fs::read(&path).unwrap(), b"previous committed snapshot");
        cleanup(&path);
    }

    #[test]
    fn separate_store_instances_serialize_capacity_reservations() {
        let path = temp_path("concurrent");
        let first = open_ledger(&path).unwrap();
        let second = open_ledger(&path).unwrap();
        let first_thread = thread::spawn(move || {
            first
                .admit_and_reserve_with_lease(
                    &device(),
                    &workload("job-concurrent-a"),
                    &context(),
                    &policies(),
                    &[],
                    1_000,
                    &[0x61u8; 32],
                )
                .unwrap()
        });
        let second_thread = thread::spawn(move || {
            second
                .admit_and_reserve_with_lease(
                    &device(),
                    &workload("job-concurrent-b"),
                    &context(),
                    &policies(),
                    &[],
                    1_000,
                    &[0x62u8; 32],
                )
                .unwrap()
        });
        let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, &&Admission::Accept))
                .count(),
            1
        );
        let ledger = open_ledger(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 1);
        cleanup(&path);
    }
    #[test]
    fn missing_primary_restores_the_last_committed_backup() {
        let path = temp_path("missing-primary");
        let ledger = open_ledger(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 0);
        let committed = fs::read(&path).unwrap();
        let backup = append_suffix(&path, ".bak");
        fs::write(&backup, committed).unwrap();
        fs::remove_file(&path).unwrap();

        let restored = open_ledger(&path).unwrap();
        assert_eq!(restored.snapshot().unwrap().active_jobs, 0);
        assert!(path.exists());
        assert!(!backup.exists());
        cleanup(&path);
    }

    #[test]
    fn corrupt_primary_without_backup_fails_closed_and_preserves_bytes() {
        let path = temp_path("corrupt-primary-no-backup");
        let corrupt = b"uncommitted or damaged state";
        fs::write(&path, corrupt).unwrap();

        assert_eq!(
            open_ledger(&path).err(),
            Some(DurableLedgerError::CorruptState)
        );
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        cleanup(&path);
    }

    #[test]
    fn corrupt_primary_and_backup_fail_closed_without_overwriting_either() {
        let path = temp_path("corrupt-both");
        let corrupt_primary = b"damaged primary snapshot";
        let corrupt_backup = b"damaged backup snapshot";
        let backup = append_suffix(&path, ".bak");
        fs::write(&path, corrupt_primary).unwrap();
        fs::write(&backup, corrupt_backup).unwrap();

        assert_eq!(
            open_ledger(&path).err(),
            Some(DurableLedgerError::CorruptState)
        );
        assert_eq!(fs::read(&path).unwrap(), corrupt_primary);
        assert_eq!(fs::read(&backup).unwrap(), corrupt_backup);
        cleanup(&path);
    }

    #[test]
    fn orphaned_temp_file_is_not_treated_as_committed_state() {
        let path = temp_path("orphaned-temp");
        let temp = append_suffix(&path, ".tmp");
        fs::write(&temp, b"uncommitted temporary snapshot").unwrap();

        let ledger = open_ledger(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 0);
        assert!(path.exists());
        assert!(!temp.exists());
        let keys = HashMap::from([("test-v1".to_string(), integrity_key("test-v1", 0xA5))]);
        assert_eq!(
            deserialize_snapshot(&fs::read(&path).unwrap(), &keys)
                .unwrap()
                .jobs
                .len(),
            0
        );
        cleanup(&path);
    }
    #[test]
    fn attacker_cannot_rewrite_snapshot_and_recompute_an_unkeyed_checksum() {
        let path = temp_path("mac-tamper");
        let ledger = open_ledger(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 0);
        drop(ledger);

        let mut bytes = fs::read(&path).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("UJANI-ENTERPRISE-LEDGER-V2\n"));
        // Even a writer who knows the file format and can recompute SHA-256
        // cannot produce the required MAC without the external integrity key.
        let mac_line = text.rfind("M\t").unwrap();
        let body = &text[..mac_line];
        let forged = format!(
            "{body}M\ttest-v1\t{}\n",
            hex_encode(&Sha256::digest(body.as_bytes()))
        );
        bytes = forged.into_bytes();
        fs::write(&path, &bytes).unwrap();

        assert_eq!(
            open_ledger(&path).err(),
            Some(DurableLedgerError::CorruptState)
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        cleanup(&path);
    }

    #[test]
    fn key_rotation_accepts_previous_key_then_rewrites_with_active_key() {
        let path = temp_path("key-rotation");
        {
            let old = DurableLedger::open_with_integrity_keys(
                &path,
                "key-v1",
                vec![integrity_key("key-v1", 0x11)],
            )
            .unwrap();
            assert_eq!(old.snapshot().unwrap().active_jobs, 0);
        }
        {
            let rotated = DurableLedger::open_with_integrity_keys(
                &path,
                "key-v2",
                vec![integrity_key("key-v1", 0x11), integrity_key("key-v2", 0x22)],
            )
            .unwrap();
            assert_eq!(rotated.snapshot().unwrap().active_jobs, 0);
        }
        {
            let only_new_key = DurableLedger::open_with_integrity_keys(
                &path,
                "key-v2",
                vec![integrity_key("key-v2", 0x22)],
            )
            .unwrap();
            assert_eq!(only_new_key.snapshot().unwrap().active_jobs, 0);
        }
        cleanup(&path);
    }

    #[test]
    fn key_material_is_redacted_from_debug_output() {
        let key = integrity_key("secret-key", 0xA5);
        let debug = format!("{key:?}");
        assert!(debug.contains("secret-key"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("165"));
    }

    #[test]
    fn legacy_checksum_only_v1_snapshot_is_rejected() {
        let path = temp_path("legacy-v1");
        fs::write(&path, b"UJANI-ENTERPRISE-LEDGER-V1\\nH\\tdeadbeef\\n").unwrap();
        assert_eq!(
            open_ledger(&path).err(),
            Some(DurableLedgerError::CorruptState)
        );
        cleanup(&path);
    }
}
