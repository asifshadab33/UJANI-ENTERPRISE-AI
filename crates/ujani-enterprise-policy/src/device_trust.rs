//! Device trust primitives for the Enterprise control-plane adapter.
//!
//! The base registry is in-memory; `durable` adds an authenticated persistent adapter.
//!
//! IMPORTANT: `DeviceRegistry` remains an in-memory policy primitive, not a
//! network service. Use the `durable` adapter for authenticated persistence;
//! callers must still bootstrap all trust roots from protected configuration.
#![forbid(unsafe_code)]

pub mod durable;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::Digest;
use std::collections::HashMap;

const ADMIN_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-DEVICE-ADMIN-COMMAND-V1\0";
// V2 signs the exact body digest and explicit workload/manifest binding fields.
const DEVICE_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-DEVICE-REQUEST-V2\0";
const ENROLLMENT_PROOF_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-DEVICE-KEY-PROOF-V1\0";
const CLOCK_SKEW_MS: u64 = 30_000;
const MAX_REPLAY_ENTRIES: usize = 100_000;
pub const MAX_DEVICE_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_DEVICE_REQUEST_TTL_MS: u64 = 30_000;
pub const MAX_ADMIN_COMMAND_TTL_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTrustState {
    Enrolled,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCommandAction {
    Enroll,
    RotateKey,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceTrustError {
    InvalidIdentifier,
    InvalidKey,
    UnknownAdminKey,
    InvalidAdminSignature,
    InvalidDeviceSignature,
    BodyDigestMismatch,
    RequestTargetMismatch,
    BodyTooLarge,
    ExpiredCommand,
    FutureTimestamp,
    InvalidCommand,
    DeviceAlreadyExists,
    DeviceNotFound,
    TenantMismatch,
    DeviceNotEnrolled,
    StaleKeyGeneration,
    ReplayDetected,
    InvalidRequestWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceAdminCommand {
    pub action: DeviceCommandAction,
    pub tenant_id: String,
    pub device_id: String,
    pub admin_key_id: String,
    pub target_key_id: String,
    pub target_public_key: Option<[u8; 32]>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
    /// Proof of possession by the currently enrolled device during key rotation.
    pub old_device_signature: Option<[u8; 64]>,
    /// Proof of possession by the new device key during enrollment or rotation.
    pub new_device_signature: Option<[u8; 64]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRequestClaims {
    pub tenant_id: String,
    pub device_id: String,
    pub key_id: String,
    pub key_generation: u64,
    pub request_id: [u8; 16],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub method: String,
    pub resource_id: String,
    /// Workload this signed request is authorized to acquire, renew or release.
    pub workload_id: String,
    /// Canonical manifest digest claimed by the workload request.
    pub manifest_sha256: [u8; 32],
    /// SHA-256 of the exact raw request body; the transport must pass those same bytes to authentication.
    pub body_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceRequest {
    pub claims: DeviceRequestClaims,
    pub signature: [u8; 64],
}

/// Request-scoped identity and workload binding produced after device signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDeviceRequest {
    device: AuthenticatedDevice,
    workload_id: String,
    manifest_sha256: [u8; 32],
    request_id: [u8; 16],
    method: String,
    resource_id: String,
    expires_at_unix_ms: u64,
}
impl AuthenticatedDeviceRequest {
    /// Returns the authenticated device principal.
    pub fn device(&self) -> &AuthenticatedDevice {
        &self.device
    }
    /// Returns the tenant authenticated by the enrolled device key.
    pub fn tenant_id(&self) -> &str {
        self.device.tenant_id()
    }
    /// Returns the enrolled device identifier.
    pub fn device_id(&self) -> &str {
        self.device.device_id()
    }
    /// Returns the key identifier used to sign this request.
    pub fn key_id(&self) -> &str {
        self.device.key_id()
    }
    /// Returns the enrolled key generation used to sign this request.
    pub fn key_generation(&self) -> u64 {
        self.device.key_generation()
    }
    /// Returns the workload identifier covered by the request signature.
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }
    /// Returns the manifest SHA-256 covered by the request signature.
    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }
    /// Returns the replay-protected request identifier.
    pub fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    /// Returns the HTTP-style method covered by the request signature.
    pub fn method(&self) -> &str {
        &self.method
    }
    /// Returns the resource or lease operation covered by the request signature.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    /// Returns the request expiry in Unix milliseconds.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    /// Validates and confirms that a workload manifest matches the signed request binding.
    pub fn binds_manifest(
        &self,
        manifest: &crate::WorkloadManifest,
    ) -> Result<bool, crate::ManifestError> {
        let digest = crate::workload_manifest_sha256(manifest)?;
        Ok(self.workload_id == manifest.workload_id && self.manifest_sha256 == digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDevice {
    tenant_id: String,
    device_id: String,
    key_id: String,
    key_generation: u64,
}
impl AuthenticatedDevice {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
}

#[derive(Debug, Clone)]
struct DeviceRecord {
    tenant_id: String,
    state: DeviceTrustState,
    key_id: String,
    key: VerifyingKey,
    generation: u64,
}

/// Tenant-scoped, non-secret projection of an enrolled device identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTrustSummary {
    pub tenant_id: String,
    pub device_id: String,
    pub state: DeviceTrustState,
    pub key_generation: u64,
}

pub struct DeviceRegistry {
    admin_keys: HashMap<String, VerifyingKey>,
    devices: HashMap<String, DeviceRecord>,
    admin_nonces: HashMap<[u8; 16], u64>,
    request_nonces: HashMap<[u8; 16], u64>,
}
impl std::fmt::Debug for DeviceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistry")
            .field("admin_key_count", &self.admin_keys.len())
            .field("device_count", &self.devices.len())
            .field("admin_nonce_count", &self.admin_nonces.len())
            .field("request_nonce_count", &self.request_nonces.len())
            .finish()
    }
}

impl DeviceRegistry {
    /// The supplied admin keys are trust roots. Load them from protected,
    /// administrator-controlled bootstrap configuration; never from a request.
    pub fn new(trusted_admin_keys: Vec<(String, VerifyingKey)>) -> Result<Self, DeviceTrustError> {
        if trusted_admin_keys.is_empty() {
            return Err(DeviceTrustError::UnknownAdminKey);
        }
        let mut admin_keys = HashMap::new();
        for (id, key) in trusted_admin_keys {
            if !valid_id(&id, 128) || admin_keys.insert(id, key).is_some() {
                return Err(DeviceTrustError::InvalidIdentifier);
            }
        }
        Ok(Self {
            admin_keys,
            devices: HashMap::new(),
            admin_nonces: HashMap::new(),
            request_nonces: HashMap::new(),
        })
    }

    /// Apply a signed administrator enrollment, rotation or revocation command.
    /// For enrollment and rotation, the target device key must prove possession.
    pub fn apply_admin_command(
        &mut self,
        command: &SignedDeviceAdminCommand,
        now: u64,
    ) -> Result<u64, DeviceTrustError> {
        validate_admin_command(command, now)?;
        self.admin_nonces.retain(|_, expiry| *expiry > now);
        if self.admin_nonces.contains_key(&command.nonce) {
            return Err(DeviceTrustError::ReplayDetected);
        }
        if self.admin_nonces.len() >= MAX_REPLAY_ENTRIES {
            return Err(DeviceTrustError::ReplayDetected);
        }
        let admin = self
            .admin_keys
            .get(&command.admin_key_id)
            .ok_or(DeviceTrustError::UnknownAdminKey)?;
        admin
            .verify_strict(
                &admin_command_bytes(command),
                &Signature::from_bytes(&command.signature),
            )
            .map_err(|_| DeviceTrustError::InvalidAdminSignature)?;

        let next_generation = match command.action {
            DeviceCommandAction::Enroll => {
                if self.devices.contains_key(&command.device_id) {
                    return Err(DeviceTrustError::DeviceAlreadyExists);
                }
                let new_key = target_key(command)?;
                verify_new_key_proof(command, &new_key)?;
                1
            }
            DeviceCommandAction::RotateKey => {
                let current = self
                    .devices
                    .get(&command.device_id)
                    .ok_or(DeviceTrustError::DeviceNotFound)?;
                if current.state != DeviceTrustState::Enrolled {
                    return Err(DeviceTrustError::DeviceNotEnrolled);
                }
                if current.tenant_id != command.tenant_id {
                    return Err(DeviceTrustError::TenantMismatch);
                }
                let new_key = target_key(command)?;
                let old_sig = command
                    .old_device_signature
                    .ok_or(DeviceTrustError::InvalidDeviceSignature)?;
                current
                    .key
                    .verify_strict(
                        &rotation_proof_bytes(command),
                        &Signature::from_bytes(&old_sig),
                    )
                    .map_err(|_| DeviceTrustError::InvalidDeviceSignature)?;
                verify_new_key_proof(command, &new_key)?;
                current
                    .generation
                    .checked_add(1)
                    .ok_or(DeviceTrustError::StaleKeyGeneration)?
            }
            DeviceCommandAction::Revoke => {
                if command.target_public_key.is_some()
                    || !command.target_key_id.is_empty()
                    || command.new_device_signature.is_some()
                    || command.old_device_signature.is_some()
                {
                    return Err(DeviceTrustError::InvalidCommand);
                }
                let current = self
                    .devices
                    .get(&command.device_id)
                    .ok_or(DeviceTrustError::DeviceNotFound)?;
                if current.tenant_id != command.tenant_id {
                    return Err(DeviceTrustError::TenantMismatch);
                }
                current
                    .generation
                    .checked_add(1)
                    .ok_or(DeviceTrustError::StaleKeyGeneration)?
            }
        };

        match command.action {
            DeviceCommandAction::Enroll | DeviceCommandAction::RotateKey => {
                let key = target_key(command)?;
                self.devices.insert(
                    command.device_id.clone(),
                    DeviceRecord {
                        tenant_id: command.tenant_id.clone(),
                        state: DeviceTrustState::Enrolled,
                        key_id: command.target_key_id.clone(),
                        key,
                        generation: next_generation,
                    },
                );
            }
            DeviceCommandAction::Revoke => {
                let current = self
                    .devices
                    .get_mut(&command.device_id)
                    .ok_or(DeviceTrustError::DeviceNotFound)?;
                current.state = DeviceTrustState::Revoked;
                current.generation = next_generation;
            }
        }
        self.admin_nonces
            .insert(command.nonce, command.expires_at_unix_ms);
        Ok(next_generation)
    }

    /// Authenticates a request only for the method and resource selected by the server route.
    ///
    /// A route mismatch is rejected before the replay nonce is consumed.
    pub fn authenticate_request_for(
        &mut self,
        signed: &SignedDeviceRequest,
        expected_method: &str,
        expected_resource_id: &str,
        body: &[u8],
        now: u64,
    ) -> Result<AuthenticatedDeviceRequest, DeviceTrustError> {
        if signed.claims.method != expected_method
            || signed.claims.resource_id != expected_resource_id
        {
            return Err(DeviceTrustError::RequestTargetMismatch);
        }
        self.authenticate_request(signed, body, now)
    }

    /// Authenticate one short-lived device request and consume its replay nonce.
    /// Tenant, enrolled key ID and monotonic key generation are checked here;
    /// downstream APIs must still authorize the authenticated tenant/principal.
    /// Authenticates a signed device request against the exact raw body bytes.
    ///
    /// The body digest is checked before the request nonce is consumed, so a
    /// transport/body mismatch can be rejected without burning a valid request.
    pub fn authenticate_request(
        &mut self,
        signed: &SignedDeviceRequest,
        body: &[u8],
        now: u64,
    ) -> Result<AuthenticatedDeviceRequest, DeviceTrustError> {
        let c = &signed.claims;
        if !valid_id(&c.tenant_id, 128)
            || !valid_id(&c.device_id, 128)
            || !valid_id(&c.key_id, 128)
            || !valid_id(&c.method, 16)
            || !valid_id(&c.resource_id, 256)
            || !valid_id(&c.workload_id, 128)
            || c.request_id.iter().all(|byte| *byte == 0)
            || c.key_generation == 0
        {
            return Err(DeviceTrustError::InvalidIdentifier);
        }
        if body.len() > MAX_DEVICE_REQUEST_BODY_BYTES {
            return Err(DeviceTrustError::BodyTooLarge);
        }
        let body_digest: [u8; 32] = sha2::Sha256::digest(body).into();
        if body_digest != c.body_sha256 {
            return Err(DeviceTrustError::BodyDigestMismatch);
        }
        if c.issued_at_unix_ms > now.saturating_add(CLOCK_SKEW_MS) {
            return Err(DeviceTrustError::FutureTimestamp);
        }
        if c.expires_at_unix_ms <= c.issued_at_unix_ms
            || c.expires_at_unix_ms <= now
            || c.expires_at_unix_ms.saturating_sub(c.issued_at_unix_ms) > MAX_DEVICE_REQUEST_TTL_MS
        {
            return Err(DeviceTrustError::InvalidRequestWindow);
        }
        self.request_nonces.retain(|_, expiry| *expiry > now);
        let record = self
            .devices
            .get(&c.device_id)
            .ok_or(DeviceTrustError::DeviceNotFound)?;
        if record.state != DeviceTrustState::Enrolled {
            return Err(DeviceTrustError::DeviceNotEnrolled);
        }
        if record.tenant_id != c.tenant_id {
            return Err(DeviceTrustError::TenantMismatch);
        }
        if self.request_nonces.contains_key(&c.request_id) {
            return Err(DeviceTrustError::ReplayDetected);
        }
        if self.request_nonces.len() >= MAX_REPLAY_ENTRIES {
            return Err(DeviceTrustError::ReplayDetected);
        }
        if record.key_id != c.key_id || record.generation != c.key_generation {
            return Err(DeviceTrustError::StaleKeyGeneration);
        }
        record
            .key
            .verify_strict(
                &device_request_bytes(c),
                &Signature::from_bytes(&signed.signature),
            )
            .map_err(|_| DeviceTrustError::InvalidDeviceSignature)?;
        self.request_nonces
            .insert(c.request_id, c.expires_at_unix_ms);
        Ok(AuthenticatedDeviceRequest {
            device: AuthenticatedDevice {
                tenant_id: c.tenant_id.clone(),
                device_id: c.device_id.clone(),
                key_id: c.key_id.clone(),
                key_generation: c.key_generation,
            },
            workload_id: c.workload_id.clone(),
            manifest_sha256: c.manifest_sha256,
            request_id: c.request_id,
            method: c.method.clone(),
            resource_id: c.resource_id.clone(),
            expires_at_unix_ms: c.expires_at_unix_ms,
        })
    }

    /// List only the non-secret device identity records belonging to one tenant.
    /// Hardware telemetry and owner consent are separate inputs and must not be
    /// inferred from enrollment alone.
    pub fn tenant_device_summaries(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<DeviceTrustSummary>, DeviceTrustError> {
        if !valid_id(tenant_id, 128) {
            return Err(DeviceTrustError::InvalidIdentifier);
        }
        let mut records: Vec<_> = self
            .devices
            .iter()
            .filter(|(_, record)| record.tenant_id == tenant_id)
            .map(|(device_id, record)| DeviceTrustSummary {
                tenant_id: record.tenant_id.clone(),
                device_id: device_id.clone(),
                state: record.state,
                key_generation: record.generation,
            })
            .collect();
        records.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        Ok(records)
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b':' || b == b'-')
}
fn validate_admin_command(c: &SignedDeviceAdminCommand, now: u64) -> Result<(), DeviceTrustError> {
    if !valid_id(&c.tenant_id, 128)
        || !valid_id(&c.device_id, 128)
        || !valid_id(&c.admin_key_id, 128)
        || c.nonce.iter().all(|b| *b == 0)
    {
        return Err(DeviceTrustError::InvalidIdentifier);
    }
    if c.issued_at_unix_ms > now.saturating_add(CLOCK_SKEW_MS) {
        return Err(DeviceTrustError::FutureTimestamp);
    }
    if c.expires_at_unix_ms <= now
        || c.expires_at_unix_ms <= c.issued_at_unix_ms
        || c.expires_at_unix_ms.saturating_sub(c.issued_at_unix_ms) > MAX_ADMIN_COMMAND_TTL_MS
    {
        return Err(DeviceTrustError::ExpiredCommand);
    }
    match c.action {
        DeviceCommandAction::Enroll | DeviceCommandAction::RotateKey => {
            if !valid_id(&c.target_key_id, 128)
                || c.target_public_key.is_none()
                || c.new_device_signature.is_none()
            {
                return Err(DeviceTrustError::InvalidCommand);
            }
            if c.action == DeviceCommandAction::Enroll && c.old_device_signature.is_some() {
                return Err(DeviceTrustError::InvalidCommand);
            }
            if c.action == DeviceCommandAction::RotateKey && c.old_device_signature.is_none() {
                return Err(DeviceTrustError::InvalidCommand);
            }
        }
        DeviceCommandAction::Revoke => {
            if !c.target_key_id.is_empty()
                || c.target_public_key.is_some()
                || c.old_device_signature.is_some()
                || c.new_device_signature.is_some()
            {
                return Err(DeviceTrustError::InvalidCommand);
            }
        }
    }
    Ok(())
}
fn target_key(c: &SignedDeviceAdminCommand) -> Result<VerifyingKey, DeviceTrustError> {
    VerifyingKey::from_bytes(&c.target_public_key.ok_or(DeviceTrustError::InvalidKey)?)
        .map_err(|_| DeviceTrustError::InvalidKey)
}
fn put_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}
pub(crate) fn admin_command_bytes(c: &SignedDeviceAdminCommand) -> Vec<u8> {
    let mut out = ADMIN_DOMAIN.to_vec();
    out.push(match c.action {
        DeviceCommandAction::Enroll => 1,
        DeviceCommandAction::RotateKey => 2,
        DeviceCommandAction::Revoke => 3,
    });
    for v in [
        &c.tenant_id,
        &c.device_id,
        &c.admin_key_id,
        &c.target_key_id,
    ] {
        put_string(&mut out, v);
    }
    match c.target_public_key {
        Some(key) => {
            out.push(1);
            out.extend_from_slice(&key);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&c.issued_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&c.expires_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&c.nonce);
    out
}
fn rotation_proof_bytes(c: &SignedDeviceAdminCommand) -> Vec<u8> {
    let mut out = b"UJANI-ENTERPRISE-DEVICE-ROTATION-OLD-KEY-V1\0".to_vec();
    out.extend_from_slice(&admin_command_bytes(c));
    out
}
pub(crate) fn enrollment_proof_bytes(c: &SignedDeviceAdminCommand) -> Vec<u8> {
    let mut out = ENROLLMENT_PROOF_DOMAIN.to_vec();
    out.extend_from_slice(&admin_command_bytes(c));
    out
}
fn verify_new_key_proof(
    c: &SignedDeviceAdminCommand,
    key: &VerifyingKey,
) -> Result<(), DeviceTrustError> {
    let sig = c
        .new_device_signature
        .ok_or(DeviceTrustError::InvalidDeviceSignature)?;
    key.verify_strict(&enrollment_proof_bytes(c), &Signature::from_bytes(&sig))
        .map_err(|_| DeviceTrustError::InvalidDeviceSignature)
}
fn device_request_bytes(c: &DeviceRequestClaims) -> Vec<u8> {
    let mut out = DEVICE_DOMAIN.to_vec();
    for v in [
        &c.tenant_id,
        &c.device_id,
        &c.key_id,
        &c.method,
        &c.resource_id,
    ] {
        put_string(&mut out, v);
    }
    put_string(&mut out, &c.workload_id);
    out.extend_from_slice(&c.manifest_sha256);
    out.extend_from_slice(&c.key_generation.to_be_bytes());
    out.extend_from_slice(&c.request_id);
    out.extend_from_slice(&c.body_sha256);
    out.extend_from_slice(&c.issued_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&c.expires_at_unix_ms.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;

    fn registry() -> (DeviceRegistry, SigningKey, SigningKey) {
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let device = SigningKey::from_bytes(&[9u8; 32]);
        let registry =
            DeviceRegistry::new(vec![("admin-v1".into(), admin.verifying_key())]).unwrap();
        (registry, admin, device)
    }
    fn enrollment(admin: &SigningKey, device: &SigningKey, nonce: u8) -> SignedDeviceAdminCommand {
        let mut c = SignedDeviceAdminCommand {
            action: DeviceCommandAction::Enroll,
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            admin_key_id: "admin-v1".into(),
            target_key_id: "device-key-v1".into(),
            target_public_key: Some(device.verifying_key().to_bytes()),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1000,
            nonce: [nonce; 16],
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        c.new_device_signature = Some(device.sign(&enrollment_proof_bytes(&c)).to_bytes());
        c.signature = admin.sign(&admin_command_bytes(&c)).to_bytes();
        c
    }
    #[test]
    fn enrollment_requires_admin_and_device_proof_and_binds_tenant() {
        let (mut r, admin, device) = registry();
        let c = enrollment(&admin, &device, 1);
        assert_eq!(r.apply_admin_command(&c, 200), Ok(1));
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [2; 16],
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
        let auth = r.authenticate_request(&signed, b"", 250).unwrap();
        assert_eq!(auth.tenant_id(), "tenant-a");
        assert_eq!(auth.device_id(), "device-1");
    }
    #[test]
    fn request_replay_revoked_device_and_cross_tenant_are_rejected() {
        let (mut r, admin, device) = registry();
        let c = enrollment(&admin, &device, 1);
        r.apply_admin_command(&c, 200).unwrap();
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [3; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:renew".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest([]).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims: claims.clone(),
        };
        assert!(r.authenticate_request(&signed, b"", 250).is_ok());
        assert_eq!(
            r.authenticate_request(&signed, b"", 251),
            Err(DeviceTrustError::ReplayDetected)
        );
        let mut cross = claims;
        cross.tenant_id = "tenant-b".into();
        let forged = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&cross)).to_bytes(),
            claims: cross,
        };
        assert_eq!(
            r.authenticate_request(&forged, b"", 252),
            Err(DeviceTrustError::TenantMismatch)
        );
    }
    #[test]
    fn all_zero_request_nonce_is_rejected_before_persistence() {
        let (mut r, admin, device) = registry();
        r.apply_admin_command(&enrollment(&admin, &device, 1), 200)
            .unwrap();
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [0; 16],
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
        assert_eq!(
            r.authenticate_request(&signed, b"", 250),
            Err(DeviceTrustError::InvalidIdentifier)
        );
    }

    #[test]
    fn request_body_must_match_the_signed_digest() {
        let (mut r, admin, device) = registry();
        r.apply_admin_command(&enrollment(&admin, &device, 1), 200)
            .unwrap();
        let body = b"tenant-scoped lease request";
        let manifest = crate::WorkloadManifest {
            schema_version: 1,
            workload_id: "workload-1".into(),
            class: "inference".into(),
            model: "test-model".into(),
            requested_cpu_millis: 500,
            requested_memory_mb: 512,
            max_runtime_ms: 30_000,
            data_classification: crate::DataClassification::Public,
            network_access: false,
        };
        let manifest_digest = crate::workload_manifest_sha256(&manifest).unwrap();
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [12; 16],
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:acquire".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: manifest_digest,
            body_sha256: sha2::Sha256::digest(body).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        // A V1 signature must not be accepted after the V2 body/workload binding change.
        let mut legacy_claims = signed.claims.clone();
        legacy_claims.request_id = sha2::Sha256::digest(b"legacy-v1-request-id")[..16]
            .try_into()
            .unwrap();
        let mut legacy_bytes = device_request_bytes(&legacy_claims);
        let legacy_domain = b"UJANI-ENTERPRISE-DEVICE-REQUEST-V1\0";
        assert_eq!(legacy_domain.len(), DEVICE_DOMAIN.len());
        legacy_bytes[..legacy_domain.len()].copy_from_slice(legacy_domain);
        let legacy_signed = SignedDeviceRequest {
            signature: device.sign(&legacy_bytes).to_bytes(),
            claims: legacy_claims,
        };
        assert_eq!(
            r.authenticate_request(&legacy_signed, body, 250),
            Err(DeviceTrustError::InvalidDeviceSignature)
        );
        assert_eq!(
            r.authenticate_request_for(&signed, "POST", "lease:renew", body, 250),
            Err(DeviceTrustError::RequestTargetMismatch)
        );
        assert_eq!(
            r.authenticate_request(&signed, b"tampered body", 250),
            Err(DeviceTrustError::BodyDigestMismatch)
        );
        let authenticated = r
            .authenticate_request_for(&signed, "POST", "lease:acquire", body, 250)
            .unwrap();
        assert_eq!(authenticated.tenant_id(), "tenant-a");
        assert_eq!(authenticated.workload_id(), "workload-1");
        assert_eq!(authenticated.resource_id(), "lease:acquire");
        assert_eq!(authenticated.expires_at_unix_ms(), 500);
        assert!(authenticated.binds_manifest(&manifest).unwrap());
        let mut substituted_manifest = manifest.clone();
        substituted_manifest.workload_id = "workload-other".into();
        assert!(!authenticated.binds_manifest(&substituted_manifest).unwrap());
        let mut changed_manifest = manifest.clone();
        changed_manifest.model = "other-model".into();
        assert!(!authenticated.binds_manifest(&changed_manifest).unwrap());
        let wrong_manifest_digest: [u8; 32] = sha2::Sha256::digest(b"substituted-manifest").into();
        let mut substituted = signed.clone();
        substituted.claims.request_id = sha2::Sha256::digest(b"substituted-workload-id")[..16]
            .try_into()
            .unwrap();
        substituted.claims.workload_id = "workload-other".into();
        assert_eq!(
            r.authenticate_request(&substituted, body, 250),
            Err(DeviceTrustError::InvalidDeviceSignature)
        );
        let mut substituted_digest = signed.clone();
        substituted_digest.claims.request_id = sha2::Sha256::digest(b"substituted-manifest-id")
            [..16]
            .try_into()
            .unwrap();
        substituted_digest.claims.manifest_sha256 = wrong_manifest_digest;
        assert_eq!(
            r.authenticate_request(&substituted_digest, body, 250),
            Err(DeviceTrustError::InvalidDeviceSignature)
        );
    }

    #[test]
    fn oversized_request_body_is_rejected_before_nonce_consumption() {
        let (mut r, admin, device) = registry();
        r.apply_admin_command(&enrollment(&admin, &device, 1), 200)
            .unwrap();
        let body = vec![b'x'; MAX_DEVICE_REQUEST_BODY_BYTES + 1];
        let request_digest = sha2::Sha256::digest(&body);
        let request_id: [u8; 16] = request_digest[..16].try_into().unwrap();
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id,
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:acquire".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest(&body).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&claims)).to_bytes(),
            claims,
        };
        assert_eq!(
            r.authenticate_request(&signed, &body, 250),
            Err(DeviceTrustError::BodyTooLarge)
        );
        assert!(!r.request_nonces.contains_key(&request_id));
    }

    #[test]
    fn signed_revocation_invalidates_the_enrolled_device() {
        let (mut r, admin, device) = registry();
        let enroll = enrollment(&admin, &device, 1);
        r.apply_admin_command(&enroll, 200).unwrap();
        let mut revoke = SignedDeviceAdminCommand {
            action: DeviceCommandAction::Revoke,
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            admin_key_id: "admin-v1".into(),
            target_key_id: String::new(),
            target_public_key: None,
            issued_at_unix_ms: 300,
            expires_at_unix_ms: 1000,
            nonce: [8; 16],
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        revoke.signature = admin.sign(&admin_command_bytes(&revoke)).to_bytes();
        assert_eq!(r.apply_admin_command(&revoke, 350), Ok(2));
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [9; 16],
            issued_at_unix_ms: 350,
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
        assert_eq!(
            r.authenticate_request(&signed, b"", 400),
            Err(DeviceTrustError::DeviceNotEnrolled)
        );
    }

    #[test]
    fn tenant_device_summaries_are_scoped_and_do_not_expose_keys() {
        let (mut registry, admin, device) = registry();
        let enroll = enrollment(&admin, &device, 1);
        registry.apply_admin_command(&enroll, 200).unwrap();
        let summaries = registry.tenant_device_summaries("tenant-a").unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].device_id, "device-1");
        assert_eq!(summaries[0].key_generation, 1);
        assert!(registry
            .tenant_device_summaries("tenant-b")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn stale_key_generation_is_rejected_after_rotation() {
        let (mut r, admin, device) = registry();
        let c = enrollment(&admin, &device, 1);
        r.apply_admin_command(&c, 200).unwrap();
        let new_device = SigningKey::from_bytes(&[11u8; 32]);
        let mut rotate = SignedDeviceAdminCommand {
            action: DeviceCommandAction::RotateKey,
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            admin_key_id: "admin-v1".into(),
            target_key_id: "device-key-v2".into(),
            target_public_key: Some(new_device.verifying_key().to_bytes()),
            issued_at_unix_ms: 300,
            expires_at_unix_ms: 1000,
            nonce: [4; 16],
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        rotate.old_device_signature = Some(device.sign(&rotation_proof_bytes(&rotate)).to_bytes());
        rotate.new_device_signature =
            Some(new_device.sign(&enrollment_proof_bytes(&rotate)).to_bytes());
        rotate.signature = admin.sign(&admin_command_bytes(&rotate)).to_bytes();
        assert_eq!(r.apply_admin_command(&rotate, 350), Ok(2));
        let old_claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: [5; 16],
            issued_at_unix_ms: 350,
            expires_at_unix_ms: 500,
            method: "POST".into(),
            resource_id: "lease:release".into(),
            workload_id: "workload-1".into(),
            manifest_sha256: sha2::Sha256::digest(b"manifest-v1").into(),
            body_sha256: sha2::Sha256::digest([]).into(),
        };
        let old_signed = SignedDeviceRequest {
            signature: device.sign(&device_request_bytes(&old_claims)).to_bytes(),
            claims: old_claims,
        };
        assert_eq!(
            r.authenticate_request(&old_signed, b"", 400),
            Err(DeviceTrustError::StaleKeyGeneration)
        );
    }
}
