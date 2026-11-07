//! HMAC-authenticated, cross-process durable device trust registry.
//!
//! The integrity key and administrator verifying keys are injected by the
//! trusted host from protected configuration. Neither is read from this file.
//! This is a persistence primitive, not an HTTP server or a complete RBAC layer.
use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HEADER: &str = "UJANI-DEVICE-TRUST-V1";
const DOMAIN: &[u8] = b"UJANI-DEVICE-TRUST-HMAC-SHA256-V1\0";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = MAX_REPLAY_ENTRIES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableDeviceTrustError {
    Io(String),
    CorruptState,
    CapacityExceeded,
    Trust(DeviceTrustError),
    LockPoisoned,
}
impl std::fmt::Display for DurableDeviceTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(v) => write!(f, "device trust storage I/O failed: {v}"),
            Self::CorruptState => write!(f, "device trust snapshot is corrupt or unauthenticated"),
            Self::CapacityExceeded => write!(f, "device trust snapshot exceeds its safety limit"),
            Self::Trust(v) => write!(f, "device trust operation rejected: {v:?}"),
            Self::LockPoisoned => write!(f, "device trust thread lock is poisoned"),
        }
    }
}
impl std::error::Error for DurableDeviceTrustError {}
impl From<std::io::Error> for DurableDeviceTrustError {
    fn from(v: std::io::Error) -> Self { Self::Io(v.to_string()) }
}
impl From<DeviceTrustError> for DurableDeviceTrustError {
    fn from(v: DeviceTrustError) -> Self { Self::Trust(v) }
}

/// Secret material must come from a protected key provider (OS keyring, TPM,
/// HSM or managed secret service), never from the writable registry directory.
#[derive(Clone)]
pub struct DeviceTrustIntegrityKey {
    key_id: String,
    bytes: [u8; 32],
}
impl DeviceTrustIntegrityKey {
    pub fn new(key_id: impl Into<String>, bytes: [u8; 32]) -> Self {
        Self { key_id: key_id.into(), bytes }
    }
    pub fn key_id(&self) -> &str { &self.key_id }
}
impl std::fmt::Debug for DeviceTrustIntegrityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTrustIntegrityKey")
            .field("key_id", &self.key_id).field("bytes", &"[REDACTED]").finish()
    }
}
impl Drop for DeviceTrustIntegrityKey {
    fn drop(&mut self) { use zeroize::Zeroize; self.bytes.zeroize(); }
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
    /// Open an authenticated registry. The initial file is created only when
    /// absent; malformed, oversized, or MAC-invalid state fails closed.
    pub fn open(
        path: impl AsRef<Path>,
        trusted_admin_keys: Vec<(String, VerifyingKey)>,
        integrity_key: DeviceTrustIntegrityKey,
    ) -> Result<Self, DurableDeviceTrustError> {
        if trusted_admin_keys.is_empty()
            || !valid_id(integrity_key.key_id(), 128)
            || trusted_admin_keys.iter().any(|(id, _)| !valid_id(id, 128))
        {
            return Err(DurableDeviceTrustError::CorruptState);
        }
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let store = Self {
            lock_path: suffix(&path, ".lock"),
            path,
            thread_lock: Arc::new(Mutex::new(())),
            admin_keys: Arc::new(trusted_admin_keys),
            integrity_key: Arc::new(integrity_key),
        };
        store.transact(|_| Ok(()))?;
        Ok(store)
    }

    pub fn apply_admin_command(
        &self, command: &SignedDeviceAdminCommand, now: u64,
    ) -> Result<u64, DurableDeviceTrustError> {
        self.transact(|registry| registry.apply_admin_command(command, now).map_err(Into::into))
    }

    pub fn authenticate_request(
        &self, request: &SignedDeviceRequest, now: u64,
    ) -> Result<AuthenticatedDevice, DurableDeviceTrustError> {
        self.transact(|registry| registry.authenticate_request(request, now).map_err(Into::into))
    }

    pub fn device_count(&self) -> Result<usize, DurableDeviceTrustError> {
        self.transact(|registry| Ok(registry.devices.len()))
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut DeviceRegistry) -> Result<T, DurableDeviceTrustError>,
    ) -> Result<T, DurableDeviceTrustError> {
        let _guard = self.thread_lock.lock().map_err(|_| DurableDeviceTrustError::LockPoisoned)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&self.lock_path)?;
        lock.lock()?;

        let backup = suffix(&self.path, ".bak");
        let mut registry = if self.path.exists() {
            decode_snapshot(&fs::read(&self.path)?, &self.admin_keys, self.integrity_key.key_id(), &self.integrity_key.bytes)?
        } else if backup.exists() {
            // Recover only the interrupted-rename case. A present but invalid
            // primary snapshot is never silently replaced by an older backup.
            let bytes = fs::read(&backup)?;
            let recovered = decode_snapshot(&bytes, &self.admin_keys, self.integrity_key.key_id(), &self.integrity_key.bytes)?;
            atomic_write(&self.path, &bytes)?;
            recovered
        } else {
            DeviceRegistry::new(self.admin_keys.as_ref().clone())?
        };
        let result = operation(&mut registry)?;
        let bytes = encode_snapshot(&registry, self.integrity_key.key_id(), &self.integrity_key.bytes);
        if bytes.len() as u64 > MAX_BYTES { return Err(DurableDeviceTrustError::CapacityExceeded); }
        atomic_write(&self.path, &bytes)?;
        Ok(result)
    }
}

fn suffix(path: &Path, value: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string(); s.push(value); PathBuf::from(s)
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8;16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len()*2);
    for b in bytes { out.push(H[(b>>4) as usize] as char); out.push(H[(b&15) as usize] as char); }
    out
}
fn unhex(v: &str) -> Result<Vec<u8>, DurableDeviceTrustError> {
    if v.len()%2 != 0 { return Err(DurableDeviceTrustError::CorruptState); }
    let mut out=Vec::with_capacity(v.len()/2);
    for p in v.as_bytes().chunks_exact(2) {
        let h=(p[0] as char).to_digit(16).ok_or(DurableDeviceTrustError::CorruptState)?;
        let l=(p[1] as char).to_digit(16).ok_or(DurableDeviceTrustError::CorruptState)?;
        out.push(((h<<4)|l) as u8);
    }
    Ok(out)
}
fn hmac(key: &[u8;32], key_id: &str, body: &[u8]) -> [u8;32] {
    let mut mac=Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(DOMAIN); mac.update(&(key_id.len() as u32).to_be_bytes());
    mac.update(key_id.as_bytes()); mac.update(body);
    mac.finalize().into_bytes().into()
}
fn encode_snapshot(r: &DeviceRegistry, key_id: &str, key: &[u8;32]) -> Vec<u8> {
    let mut body=format!("{HEADER}\n");
    let mut ids=r.devices.keys().collect::<Vec<_>>(); ids.sort();
    for id in ids {
        let d=r.devices.get(id).expect("key came from map");
        body.push_str(&format!("D|{}|{}|{}|{}|{}|{}\n",
            hex(id.as_bytes()),hex(d.tenant_id.as_bytes()),
            if d.state==DeviceTrustState::Enrolled {"E"} else {"R"},
            hex(d.key_id.as_bytes()),hex(&d.key.to_bytes()),d.generation));
    }
    let mut admins=r.admin_nonces.iter().collect::<Vec<_>>(); admins.sort_by_key(|(n,_)| **n);
    for (nonce,expiry) in admins { body.push_str(&format!("A|{}|{}\n",hex(nonce),expiry)); }
    let mut requests=r.request_nonces.iter().collect::<Vec<_>>(); requests.sort_by_key(|(n,_)| **n);
    for (nonce,expiry) in requests { body.push_str(&format!("R|{}|{}\n",hex(nonce),expiry)); }
    let mac=hmac(key,key_id,body.as_bytes());
    body.push_str(&format!("H|{}|{}\n",hex(key_id.as_bytes()),hex(&mac)));
    body.into_bytes()
}
fn decode_snapshot(
    bytes: &[u8], admin_keys: &[(String,VerifyingKey)], expected_key_id: &str, key: &[u8;32],
) -> Result<DeviceRegistry,DurableDeviceTrustError> {
    if bytes.len() as u64 > MAX_BYTES { return Err(DurableDeviceTrustError::CapacityExceeded); }
    let text=std::str::from_utf8(bytes).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    let marker=text.rfind("H|").ok_or(DurableDeviceTrustError::CorruptState)?;
    let (body,tail)=text.split_at(marker);
    let fields=tail.trim_end_matches('\n').split('|').collect::<Vec<_>>();
    if fields.len()!=3 || fields[0]!="H" { return Err(DurableDeviceTrustError::CorruptState); }
    let key_id=String::from_utf8(unhex(fields[1])?).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    if !valid_id(&key_id,128) || key_id != expected_key_id { return Err(DurableDeviceTrustError::CorruptState); }
    let expected=unhex(fields[2])?;
    let mut mac=Hmac::<Sha256>::new_from_slice(key).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    mac.update(DOMAIN); mac.update(&(key_id.len() as u32).to_be_bytes());
    mac.update(key_id.as_bytes()); mac.update(body.as_bytes());
    mac.verify_slice(&expected).map_err(|_| DurableDeviceTrustError::CorruptState)?;
    let mut registry=DeviceRegistry::new(admin_keys.to_vec())?;
    let mut records=0usize;
    let mut lines=body.lines();
    if lines.next()!=Some(HEADER) { return Err(DurableDeviceTrustError::CorruptState); }
    for line in lines {
        let p=line.split('|').collect::<Vec<_>>();
        records+=1;
        if records>MAX_RECORDS*2 { return Err(DurableDeviceTrustError::CapacityExceeded); }
        match p.first().copied() {
            Some("D") if p.len()==7 => {
                let id=String::from_utf8(unhex(p[1])?).map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let tenant=String::from_utf8(unhex(p[2])?).map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let state=match p[3] {"E"=>DeviceTrustState::Enrolled,"R"=>DeviceTrustState::Revoked,_=>return Err(DurableDeviceTrustError::CorruptState)};
                let key_id=String::from_utf8(unhex(p[4])?).map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let pubkey: [u8;32]=unhex(p[5])?.try_into().map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let generation=p[6].parse::<u64>().map_err(|_| DurableDeviceTrustError::CorruptState)?;
                if !valid_id(&id,128)||!valid_id(&tenant,128)||!valid_id(&key_id,128)||generation==0 {
                    return Err(DurableDeviceTrustError::CorruptState);
                }
                let vk=VerifyingKey::from_bytes(&pubkey).map_err(|_| DurableDeviceTrustError::CorruptState)?;
                if registry.devices.insert(id,DeviceRecord{tenant_id:tenant,state,key_id,key:vk,generation}).is_some() {
                    return Err(DurableDeviceTrustError::CorruptState);
                }
            }
            Some("A") | Some("R") if p.len()==3 => {
                let nonce: [u8;16]=unhex(p[1])?.try_into().map_err(|_| DurableDeviceTrustError::CorruptState)?;
                let expiry=p[2].parse::<u64>().map_err(|_| DurableDeviceTrustError::CorruptState)?;
                if nonce.iter().all(|b| *b==0) || expiry==0 { return Err(DurableDeviceTrustError::CorruptState); }
                let map=if p[0]=="A" {&mut registry.admin_nonces} else {&mut registry.request_nonces};
                if map.insert(nonce,expiry).is_some() { return Err(DurableDeviceTrustError::CorruptState); }
            }
            _=>return Err(DurableDeviceTrustError::CorruptState),
        }
    }
    if registry.devices.len()>MAX_RECORDS || registry.admin_nonces.len()>MAX_RECORDS || registry.request_nonces.len()>MAX_RECORDS {
        return Err(DurableDeviceTrustError::CapacityExceeded);
    }
    Ok(registry)
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(),DurableDeviceTrustError> {
    let temp=suffix(path,".tmp");
    let backup=suffix(path,".bak");
    let mut options=OpenOptions::new(); options.create(true).truncate(true).write(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file=options.open(&temp)?;
    file.write_all(bytes)?; file.sync_all()?; drop(file);
    let had_old=path.exists();
    if had_old {
        let _=fs::remove_file(&backup);
        fs::rename(path,&backup)?;
    }
    if let Err(error)=fs::rename(&temp,path) {
        if had_old { let _=fs::rename(&backup,path); }
        let _=fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Some(parent)=path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir)=File::open(parent) { let _=dir.sync_all(); }
    }
    let _=fs::remove_file(backup);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path() -> PathBuf {
        let n=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("ujani-device-trust-{}-{n}.db",std::process::id()))
    }
    fn open(path:&Path, admin:&SigningKey) -> DurableDeviceRegistry {
        DurableDeviceRegistry::open(
            path, vec![("admin-v1".into(),admin.verifying_key())],
            DeviceTrustIntegrityKey::new("integrity-v1",[0x42;32])
        ).unwrap()
    }
    fn enroll(admin:&SigningKey, device:&SigningKey) -> SignedDeviceAdminCommand {
        let mut c=SignedDeviceAdminCommand {
            action:DeviceCommandAction::Enroll, tenant_id:"tenant-a".into(),
            device_id:"device-1".into(), admin_key_id:"admin-v1".into(),
            target_key_id:"device-key-v1".into(), target_public_key:Some(device.verifying_key().to_bytes()),
            issued_at_unix_ms:100, expires_at_unix_ms:1000, nonce:[1;16],
            signature:[0;64], old_device_signature:None, new_device_signature:None,
        };
        c.new_device_signature=Some(device.sign(&enrollment_proof_bytes(&c)).to_bytes());
        c.signature=admin.sign(&admin_command_bytes(&c)).to_bytes();
        c
    }
    #[test]
    fn enrollment_and_request_replay_state_survive_restart() {
        let path=path();
        let admin=SigningKey::from_bytes(&[7;32]);
        let device=SigningKey::from_bytes(&[9;32]);
        let store=open(&path,&admin);
        assert_eq!(store.apply_admin_command(&enroll(&admin,&device),200).unwrap(),1);
        let claims=DeviceRequestClaims {
            tenant_id:"tenant-a".into(), device_id:"device-1".into(),
            key_id:"device-key-v1".into(), key_generation:1, request_id:[3;16],
            issued_at_unix_ms:200, expires_at_unix_ms:500, method:"POST".into(),
            resource_id:"lease:acquire".into(),
        };
        let signed=SignedDeviceRequest {signature:device.sign(&device_request_bytes(&claims)).to_bytes(),claims};
        assert!(store.authenticate_request(&signed,250).is_ok());
        drop(store);
        let reopened=open(&path,&admin);
        assert_eq!(reopened.device_count().unwrap(),1);
        assert_eq!(reopened.authenticate_request(&signed,251),Err(DurableDeviceTrustError::Trust(DeviceTrustError::ReplayDetected)));
        let _=fs::remove_file(&path); let _=fs::remove_file(suffix(&path,".lock"));
    }
    #[test]
    fn modified_snapshot_fails_closed() {
        let path=path();
        let admin=SigningKey::from_bytes(&[7;32]);
        let device=SigningKey::from_bytes(&[9;32]);
        let store=open(&path,&admin);
        store.apply_admin_command(&enroll(&admin,&device),200).unwrap();
        drop(store);
        let mut bytes=fs::read(&path).unwrap();
        let index=bytes.windows(3).position(|w| w==b"|E|").unwrap()+1;
        bytes[index]=b'R';
        fs::write(&path,bytes).unwrap();
        assert!(DurableDeviceRegistry::open(&path,vec![("admin-v1".into(),admin.verifying_key())],DeviceTrustIntegrityKey::new("integrity-v1",[0x42;32])).is_err());
        let _=fs::remove_file(&path); let _=fs::remove_file(suffix(&path,".lock"));
    }
    #[test]
    fn concurrent_handles_consume_a_request_nonce_once() {
        let path=path();
        let admin=SigningKey::from_bytes(&[7;32]);
        let device=SigningKey::from_bytes(&[9;32]);
        let first=open(&path,&admin);
        first.apply_admin_command(&enroll(&admin,&device),200).unwrap();
        let second=open(&path,&admin);
        let claims=DeviceRequestClaims {
            tenant_id:"tenant-a".into(), device_id:"device-1".into(),
            key_id:"device-key-v1".into(), key_generation:1, request_id:[6;16],
            issued_at_unix_ms:200, expires_at_unix_ms:500, method:"POST".into(),
            resource_id:"lease:acquire".into(),
        };
        let signed=SignedDeviceRequest {signature:device.sign(&device_request_bytes(&claims)).to_bytes(),claims};
        let signed2=signed.clone();
        let barrier=std::sync::Arc::new(std::sync::Barrier::new(2));
        let b1=barrier.clone();
        let t1=std::thread::spawn(move || { b1.wait(); first.authenticate_request(&signed,250) });
        let b2=barrier.clone();
        let t2=std::thread::spawn(move || { b2.wait(); second.authenticate_request(&signed2,250) });
        let results=[t1.join().unwrap(),t2.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(),1);
        assert_eq!(results.iter().filter(|r| **r==Err(DurableDeviceTrustError::Trust(DeviceTrustError::ReplayDetected))).count(),1);
        let _=fs::remove_file(&path); let _=fs::remove_file(suffix(&path,".lock"));
    }

}
