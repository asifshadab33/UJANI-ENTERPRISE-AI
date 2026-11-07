//! Durable, cross-thread and cross-process reservation ledger.
//!
//! Each transaction reloads the latest snapshot under an OS file lock, applies
//! one policy operation, and commits a checksummed snapshot using a same-directory
//! temp file plus backup/rename recovery. The raw lease capability is never
//! persisted; only its domain-separated digest is stored.
use crate::{Admission, Device, Ledger, SchedulingContext, VerifiedAdminApproval, Workload, ClassPolicy};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const LEDGER_HEADER: &str = "UJANI-ENTERPRISE-LEDGER-V1";
const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableLedgerError {
    Io(String),
    CorruptState,
    InvalidRecord,
    LockPoisoned,
}

impl std::fmt::Display for DurableLedgerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "durable ledger I/O failed: {message}"),
            Self::CorruptState => write!(formatter, "durable ledger is corrupt or has an invalid checksum"),
            Self::InvalidRecord => write!(formatter, "durable ledger contains an invalid or duplicate record"),
            Self::LockPoisoned => write!(formatter, "durable ledger thread lock is poisoned"),
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

/// A durable reservation store. Separate instances pointing to the same path
/// coordinate through an OS advisory file lock; each operation reloads state
/// while holding that lock, so stale in-memory snapshots cannot overwrite newer
/// reservations from another process.
#[derive(Debug, Clone)]
pub struct DurableLedger {
    path: PathBuf,
    lock_path: PathBuf,
    thread_lock: Arc<Mutex<()>>,
}

impl DurableLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableLedgerError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let store = Self {
            lock_path: append_suffix(&path, ".lock"),
            path,
            thread_lock: Arc::new(Mutex::new(())),
        };
        store.transact(|_| Ok(()))?;
        Ok(store)
    }

    /// Reserve capacity with an opaque capability. The caller must generate
    /// the 32-byte token using an OS CSPRNG and keep it outside the workload.
    /// This raw-context method is crate-private; public callers should use the
    /// signed-evidence wrapper in scheduling_evidence.
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

    pub fn renew_lease(
        &self,
        workload_id: &str,
        lease_token: &[u8; 32],
        now_unix_ms: u64,
    ) -> Result<bool, DurableLedgerError> {
        self.transact(|ledger| Ok(ledger.renew_lease(workload_id, lease_token, now_unix_ms)))
    }

    pub fn release_lease(
        &self,
        workload_id: &str,
        lease_token: &[u8; 32],
    ) -> Result<bool, DurableLedgerError> {
        self.transact(|ledger| Ok(ledger.release_lease(workload_id, lease_token)))
    }

    pub fn expire_leases(&self, now_unix_ms: u64) -> Result<usize, DurableLedgerError> {
        self.transact(|ledger| {
            let before = ledger.jobs.len();
            ledger.expire(now_unix_ms);
            Ok(before.saturating_sub(ledger.jobs.len()))
        })
    }

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

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut Ledger) -> Result<T, DurableLedgerError>,
    ) -> Result<T, DurableLedgerError> {
        let _thread_guard = self
            .thread_lock
            .lock()
            .map_err(|_| DurableLedgerError::LockPoisoned)?;
        let mut lock_options = OpenOptions::new();
        lock_options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock_file = lock_options.open(&self.lock_path)?;
        lock_file.lock()?;

        let mut ledger = load_or_recover(&self.path)?;
        let result = operation(&mut ledger)?;
        persist_snapshot(&self.path, &ledger)?;
        Ok(result)
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
    if value.len() % 2 != 0 {
        return Err(DurableLedgerError::InvalidRecord);
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
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

fn serialize_snapshot(ledger: &Ledger) -> Vec<u8> {
    let mut body = format!("{LEDGER_HEADER}\n");
    let mut workload_ids = ledger.jobs.keys().collect::<Vec<_>>();
    workload_ids.sort();
    for workload_id in workload_ids {
        let (device_id, cpu, memory, expires, approval_id) =
            ledger.jobs.get(workload_id).expect("key collected from jobs");
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
    let digest = Sha256::digest(body.as_bytes());
    body.push_str(&format!("H\t{}\n", hex_encode(&digest)));
    body.into_bytes()
}

fn deserialize_snapshot(bytes: &[u8]) -> Result<Ledger, DurableLedgerError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DurableLedgerError::CorruptState)?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES || !text.ends_with('\n') {
        return Err(DurableLedgerError::CorruptState);
    }
    let hash_start = text
        .rfind("H\t")
        .ok_or(DurableLedgerError::CorruptState)?;
    let body = &text[..hash_start];
    let hash_line = &text[hash_start..];
    let expected_hash = hash_line
        .strip_prefix("H\t")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or(DurableLedgerError::CorruptState)?;
    let actual_hash = hex_encode(&Sha256::digest(body.as_bytes()));
    if actual_hash != expected_hash {
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

fn load_or_recover(path: &Path) -> Result<Ledger, DurableLedgerError> {
    let backup = append_suffix(path, ".bak");
    if !path.exists() {
        if backup.exists() {
            fs::rename(&backup, path)?;
        } else {
            return Ok(Ledger::default());
        }
    }
    let current = read_snapshot(path);
    match current.and_then(|bytes| deserialize_snapshot(&bytes)) {
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
            let recovered = deserialize_snapshot(&backup_bytes)?;
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

fn persist_snapshot(path: &Path, ledger: &Ledger) -> Result<(), DurableLedgerError> {
    let temp = append_suffix(path, ".tmp");
    let backup = append_suffix(path, ".bak");
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let bytes = serialize_snapshot(ledger);
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
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        if backup.exists() && !path.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(DurableLedgerError::from(error));
    }
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    if backup.exists() {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{workload_from_manifest, DataClassification, WorkloadManifest};
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
    fn reservation_and_capability_survive_process_restart() {
        let path = temp_path("restart");
        let token = [0x51u8; 32];
        {
            let ledger = DurableLedger::open(&path).unwrap();
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
            let ledger = DurableLedger::open(&path).unwrap();
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
            let ledger = DurableLedger::open(&path).unwrap();
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
        let ledger = DurableLedger::open(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 1);
        cleanup(&path);
    }

    #[test]
    fn separate_store_instances_serialize_capacity_reservations() {
        let path = temp_path("concurrent");
        let first = DurableLedger::open(&path).unwrap();
        let second = DurableLedger::open(&path).unwrap();
        let first_thread = thread::spawn(move || {
            first.admit_and_reserve_with_lease(
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
            second.admit_and_reserve_with_lease(
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
        let ledger = DurableLedger::open(&path).unwrap();
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 1);
        cleanup(&path);
    }
}
