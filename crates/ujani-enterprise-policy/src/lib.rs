//! Side-effect-free enterprise workload admission policy.
//! This crate does not enrol devices, schedule jobs, create sandboxes or enforce quotas.

#![forbid(unsafe_code)]

pub mod self_evolution;
pub mod self_evolution_module;

pub mod capability_registry;
pub mod collective_defence_authority;
pub mod collective_defence_consent;
pub mod collective_defence_snapshot;
pub mod connector_contract;
pub mod cpu_capacity;
pub mod device_trust;
pub mod energy;
pub mod fleet_capacity;
pub use fleet_capacity::{
    summarize_fleet_capacity, DeviceCapacity, FleetCapacityError, FleetCapacitySummary,
};
pub mod local_first_placement;
pub mod personal_enterprise_contract;
use ed25519_dalek::{Signature, VerifyingKey};
pub use local_first_placement::{
    plan_local_first_placement, CandidateRejection, LocalFirstPlacementPlan, PlacementCandidate,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const LEASE_MS: u64 = 5 * 60 * 1000;
pub const MAX_ADMIN_APPROVAL_TTL_MS: u64 = 15 * 60 * 1000;
const MANIFEST_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-WORKLOAD-MANIFEST-V1\0";
const APPROVAL_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-ADMIN-APPROVAL-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminApprovalClaims {
    pub approval_id: String,
    pub workload_id: String,
    pub device_id: String,
    pub class: String,
    pub max_cpu_millis: u32,
    pub max_memory_mb: u64,
    pub approver_key_id: String,
    pub manifest_sha256: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAdminApproval {
    pub claims: AdminApprovalClaims,
    pub signature: [u8; 64],
}

/// The private payload prevents callers from manufacturing a verified approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdminApproval(AdminApprovalClaims);

fn admin_approval_bytes(claims: &AdminApprovalClaims) -> Vec<u8> {
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    for value in [
        &claims.approval_id,
        &claims.workload_id,
        &claims.device_id,
        &claims.class,
        &claims.approver_key_id,
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&claims.max_cpu_millis.to_be_bytes());
    bytes.extend_from_slice(&claims.max_memory_mb.to_be_bytes());
    bytes.extend_from_slice(&claims.manifest_sha256);
    bytes.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.expires_unix_ms.to_be_bytes());
    bytes
}

pub fn verify_admin_approval(
    signed: &SignedAdminApproval,
    enrolled_admin_keys: &[(String, VerifyingKey)],
    now_unix_ms: u64,
) -> Result<VerifiedAdminApproval, &'static str> {
    let claims = &signed.claims;
    if !valid_identifier(&claims.approval_id, 128)
        || !valid_identifier(&claims.workload_id, 128)
        || !valid_identifier(&claims.device_id, 128)
        || !valid_identifier(&claims.class, 64)
        || !valid_identifier(&claims.approver_key_id, 128)
        || claims.max_cpu_millis == 0
        || claims.max_memory_mb == 0
        || claims.issued_at_unix_ms > now_unix_ms.saturating_add(30_000)
        || claims.expires_unix_ms <= claims.issued_at_unix_ms
        || claims
            .expires_unix_ms
            .saturating_sub(claims.issued_at_unix_ms)
            > MAX_ADMIN_APPROVAL_TTL_MS
        || claims.expires_unix_ms <= now_unix_ms
    {
        return Err("invalid or expired administrator approval");
    }
    let key = enrolled_admin_keys
        .iter()
        .find(|(key_id, _)| key_id == &claims.approver_key_id)
        .map(|(_, key)| key)
        .ok_or("unknown administrator signing key")?;
    let signature = Signature::from_bytes(&signed.signature);
    key.verify_strict(&admin_approval_bytes(claims), &signature)
        .map_err(|_| "administrator approval signature is invalid")?;
    Ok(VerifiedAdminApproval(claims.clone()))
}

fn approval_covers(
    approval: &VerifiedAdminApproval,
    device: &Device,
    workload: &Workload,
    now_unix_ms: u64,
) -> bool {
    let a = &approval.0;
    a.workload_id == workload.workload_id
        && a.device_id == device.device_id
        && a.class == workload.class
        && a.manifest_sha256 == workload.manifest_sha256
        && workload.requested_cpu_millis <= a.max_cpu_millis
        && workload.requested_memory_mb <= a.max_memory_mb
        && now_unix_ms < a.expires_unix_ms
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    pub enrolled: bool,
    pub admin_approved: bool,
    pub available: bool,
    pub allowed_workload_classes: Vec<String>,
    pub remaining_cpu_millis: u32,
    pub remaining_memory_mb: u64,
}

/// Strict, versioned input contract for a requested workload.
/// Deserializing this type rejects unknown fields; validation is still required
/// and does not itself authorize admission or execution.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadManifest {
    pub schema_version: u16,
    pub workload_id: String,
    pub class: String,
    pub model: String,
    pub requested_cpu_millis: u32,
    pub requested_memory_mb: u64,
    pub max_runtime_ms: u64,
    pub data_classification: DataClassification,
    pub network_access: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    UnsupportedVersion,
    InvalidWorkloadId,
    InvalidClass,
    InvalidModel,
    InvalidCpuLimit,
    InvalidMemoryLimit,
    InvalidRuntimeLimit,
}

pub fn validate_workload_manifest(manifest: &WorkloadManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 {
        return Err(ManifestError::UnsupportedVersion);
    }
    if !valid_identifier(&manifest.workload_id, 128) {
        return Err(ManifestError::InvalidWorkloadId);
    }
    if !valid_identifier(&manifest.class, 64) {
        return Err(ManifestError::InvalidClass);
    }
    if !valid_model_identifier(&manifest.model) {
        return Err(ManifestError::InvalidModel);
    }
    if manifest.requested_cpu_millis == 0 || manifest.requested_cpu_millis > 1_000_000 {
        return Err(ManifestError::InvalidCpuLimit);
    }
    if manifest.requested_memory_mb == 0 || manifest.requested_memory_mb > 4 * 1024 * 1024 {
        return Err(ManifestError::InvalidMemoryLimit);
    }
    if manifest.max_runtime_ms == 0 || manifest.max_runtime_ms > 7 * 24 * 60 * 60 * 1000 {
        return Err(ManifestError::InvalidRuntimeLimit);
    }
    Ok(())
}

/// Model identifiers are library names, never URLs, local paths or registry endpoints.
fn valid_model_identifier(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("..")
    {
        return false;
    }
    let segments: Vec<&str> = value.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty())
        || (segments.len() > 1 && segments[0].contains('.'))
    {
        return false;
    }
    for (index, segment) in segments.iter().enumerate() {
        let mut parts = segment.split(':');
        let name = parts.next().unwrap_or_default();
        let tag = parts.next();
        if parts.next().is_some()
            || name.is_empty()
            || name.bytes().any(|b| {
                !(b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'_'
                    || b == b'-')
            })
        {
            return false;
        }
        if let Some(tag) = tag {
            if index + 1 != segments.len()
                || tag.is_empty()
                || !tag.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'.'
                        || b == b'_'
                        || b == b'-'
                })
            {
                return false;
            }
        }
    }
    true
}
/// Stable, domain-separated digest over every field that affects workload admission.
pub fn workload_manifest_sha256(manifest: &WorkloadManifest) -> Result<[u8; 32], ManifestError> {
    validate_workload_manifest(manifest)?;
    let mut bytes = MANIFEST_DOMAIN.to_vec();
    bytes.extend_from_slice(&manifest.schema_version.to_be_bytes());
    for value in [&manifest.workload_id, &manifest.class, &manifest.model] {
        let len = u32::try_from(value.len()).map_err(|_| ManifestError::InvalidModel)?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&manifest.requested_cpu_millis.to_be_bytes());
    bytes.extend_from_slice(&manifest.requested_memory_mb.to_be_bytes());
    bytes.extend_from_slice(&manifest.max_runtime_ms.to_be_bytes());
    bytes.push(match manifest.data_classification {
        DataClassification::Public => 0,
        DataClassification::Internal => 1,
        DataClassification::Confidential => 2,
        DataClassification::Restricted => 3,
    });
    bytes.push(u8::from(manifest.network_access));
    Ok(Sha256::digest(bytes).into())
}

/// Create the only supported Workload value from a fully validated manifest.
pub fn workload_from_manifest(manifest: &WorkloadManifest) -> Result<Workload, ManifestError> {
    let digest = workload_manifest_sha256(manifest)?;
    Ok(Workload {
        workload_id: manifest.workload_id.clone(),
        class: manifest.class.clone(),
        requested_cpu_millis: manifest.requested_cpu_millis,
        requested_memory_mb: manifest.requested_memory_mb,
        manifest_sha256: digest,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub workload_id: String,
    pub class: String,
    pub requested_cpu_millis: u32,
    pub requested_memory_mb: u64,
    manifest_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPolicy {
    pub class: String,
    pub requires_admin_approval: bool,
    pub max_cpu_millis: u32,
    pub max_memory_mb: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    InvalidIdentifier,
    ZeroBudget,
    DeviceNotApproved,
    DeviceUnavailable,
    ClassNotAllowedOnDevice,
    UnknownClassPolicy,
    ApprovalRequired,
    InvalidClassPolicy,
    ExceedsClassLimit,
    CpuBudget,
    MemoryBudget,
    DuplicateWorkload,
    TelemetryStale,
    OwnerOptInMissing,
    OutsideAdminSchedule,
    InteractiveUserPresent,
    DeviceNotRunning,
    OnBattery,
    ThermalUnsafe,
    NetworkPolicyDenied,
    DataClassificationDenied,
    InvalidLeaseToken,
    SchedulingEvidenceMismatch,
    SchedulingEvidenceExpired,
    WorkerIsolationUnavailable,
    ReservationRevisionExhausted,
    TelemetryWatermarkInvalid,
    TelemetrySuperseded,
}
impl RejectReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid bounded identifier",
            Self::ZeroBudget => "positive CPU and memory budgets required",
            Self::DeviceNotApproved => "device is not enrolled and approved",
            Self::DeviceUnavailable => "device unavailable",
            Self::ClassNotAllowedOnDevice => "class not allowed on device",
            Self::UnknownClassPolicy => "unknown class policy",
            Self::ApprovalRequired => "verified administrator approval required",
            Self::InvalidClassPolicy => "class policy set is invalid or contains duplicates",
            Self::ExceedsClassLimit => "class resource limit exceeded",
            Self::CpuBudget => "CPU budget exceeded",
            Self::MemoryBudget => "memory budget exceeded",
            Self::DuplicateWorkload => "workload identifier is already reserved",
            Self::TelemetryStale => "worker telemetry is missing or stale",
            Self::OwnerOptInMissing => "device owner has not explicitly opted in",
            Self::OutsideAdminSchedule => "outside administrator-approved scheduling window",
            Self::InteractiveUserPresent => "interactive user activity takes priority",
            Self::DeviceNotRunning => {
                "device is sleeping or powered off; UJANI never wakes devices"
            }
            Self::OnBattery => "device is on battery power",
            Self::ThermalUnsafe => "device thermal state is not safe for background work",
            Self::NetworkPolicyDenied => "network or data-egress policy blocks this workload",
            Self::DataClassificationDenied => {
                "workload data classification is not approved for this worker"
            }
            Self::InvalidLeaseToken => "lease capability is invalid or already in use",
            Self::SchedulingEvidenceMismatch => {
                "verified scheduling evidence does not match this device and workload"
            }
            Self::SchedulingEvidenceExpired => "verified scheduling evidence has expired",
            Self::WorkerIsolationUnavailable => "required OS workload isolation is unavailable",
            Self::ReservationRevisionExhausted => "device reservation revision is exhausted",
            Self::TelemetryWatermarkInvalid => "signed telemetry reservation watermark is invalid",
            Self::TelemetrySuperseded => "signed telemetry sample has been superseded",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Accept,
    Reject(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelemetryChallengeError {
    Replayed,
    InvalidReservationWatermark,
}

/// In-memory reservation semantics for tests and single-process prototypes only.
/// Production scheduling must use an atomic transactional ledger in durable storage.
#[derive(Debug, Default)]
pub struct Ledger {
    used: std::collections::HashMap<String, (u32, u64)>,
    jobs: std::collections::HashMap<String, (String, u32, u64, u64, Option<String>)>,
    consumed_approvals: std::collections::HashSet<String>,
    /// Short-lived, single-use dispatch challenges persisted by DurableLedger.
    consumed_challenges: std::collections::HashMap<[u8; 16], u64>,
    /// Highest accepted signed worker telemetry generation per enrolled device.
    telemetry_generations: std::collections::HashMap<String, u64>,
    /// Latest reservation revision for each device, including release and expiry.
    reservation_revisions: std::collections::HashMap<String, u64>,
    /// Reservation revision assigned when each active lease was committed.
    job_reservation_revisions: std::collections::HashMap<String, u64>,
    /// Highest accepted reservation revision reflected by each device telemetry sample.
    telemetry_reservation_watermarks: std::collections::HashMap<String, u64>,
    /// Domain-separated SHA-256 digests of caller-generated 256-bit lease capabilities.
    lease_token_hashes: std::collections::HashMap<String, [u8; 32]>,
}

impl Ledger {
    pub(crate) fn try_reserve(
        &mut self,
        device: &Device,
        workload: &Workload,
        now_unix_ms: u64,
        approval_id: Option<&str>,
    ) -> Result<(), RejectReason> {
        self.expire(now_unix_ms);
        if self.jobs.contains_key(&workload.workload_id) {
            return Err(RejectReason::DuplicateWorkload);
        }
        if let Some(id) = approval_id {
            if self.consumed_approvals.contains(id) {
                return Err(RejectReason::ApprovalRequired);
            }
        }
        let (cpu, memory) = self.used.get(&device.device_id).copied().unwrap_or((0, 0));
        let next_cpu = cpu
            .checked_add(workload.requested_cpu_millis)
            .ok_or(RejectReason::CpuBudget)?;
        let next_memory = memory
            .checked_add(workload.requested_memory_mb)
            .ok_or(RejectReason::MemoryBudget)?;
        if next_cpu > device.remaining_cpu_millis {
            return Err(RejectReason::CpuBudget);
        }
        if next_memory > device.remaining_memory_mb {
            return Err(RejectReason::MemoryBudget);
        }
        let reservation_revision = self
            .reservation_revisions
            .get(&device.device_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RejectReason::ReservationRevisionExhausted)?;
        self.used
            .insert(device.device_id.clone(), (next_cpu, next_memory));
        self.jobs.insert(
            workload.workload_id.clone(),
            (
                device.device_id.clone(),
                workload.requested_cpu_millis,
                workload.requested_memory_mb,
                now_unix_ms.saturating_add(LEASE_MS),
                approval_id.map(str::to_owned),
            ),
        );
        self.reservation_revisions
            .insert(device.device_id.clone(), reservation_revision);
        self.job_reservation_revisions
            .insert(workload.workload_id.clone(), reservation_revision);
        if let Some(id) = approval_id {
            self.consumed_approvals.insert(id.to_owned());
        }
        Ok(())
    }
    pub(crate) fn release(&mut self, workload_id: &str) {
        self.lease_token_hashes.remove(workload_id);
        if let Some((device_id, cpu, memory, _expires, _approval_id)) =
            self.jobs.remove(workload_id)
        {
            self.job_reservation_revisions.remove(workload_id);
            let revision = self
                .reservation_revisions
                .entry(device_id.clone())
                .or_insert(0);
            if let Some(next) = revision.checked_add(1) {
                *revision = next;
            }
            if let Some(used) = self.used.get_mut(&device_id) {
                used.0 = used.0.saturating_sub(cpu);
                used.1 = used.1.saturating_sub(memory);
            }
        }
    }

    /// Reserve capacity and bind it to a caller-generated 256-bit CSPRNG capability.
    #[allow(clippy::too_many_arguments)] // The explicit policy inputs keep authorization dependencies visible.
    /// The raw token is never persisted by this policy crate; only a domain-separated
    /// digest is retained. The control plane must protect the raw token from workloads.
    pub(crate) fn admit_and_reserve_with_lease(
        &mut self,
        device: &Device,
        workload: &Workload,
        context: &SchedulingContext,
        policies: &[ClassPolicy],
        approvals: &[VerifiedAdminApproval],
        now_unix_ms: u64,
        lease_token: &[u8; 32],
    ) -> Admission {
        if lease_token.iter().all(|byte| *byte == 0) {
            return Admission::Reject(RejectReason::InvalidLeaseToken);
        }
        let token_hash = lease_token_hash(lease_token);
        if self
            .lease_token_hashes
            .values()
            .any(|stored| constant_time_eq(stored, &token_hash))
        {
            return Admission::Reject(RejectReason::InvalidLeaseToken);
        }
        let decision = admit_and_reserve(
            self,
            device,
            workload,
            context,
            policies,
            approvals,
            now_unix_ms,
        );
        if decision == Admission::Accept {
            self.lease_token_hashes
                .insert(workload.workload_id.clone(), token_hash);
        }
        decision
    }

    /// Renew a lease only when the caller is the device that owns the reservation.
    /// Authentication of the device request must happen before calling this method.
    pub(crate) fn renew_lease_for_device(
        &mut self,
        workload_id: &str,
        device_id: &str,
        lease_token: &[u8; 32],
        now_unix_ms: u64,
    ) -> bool {
        self.expire(now_unix_ms);
        if !self
            .jobs
            .get(workload_id)
            .is_some_and(|job| job.0 == device_id)
        {
            return false;
        }
        self.renew_lease(workload_id, lease_token, now_unix_ms)
    }

    /// Release a lease only when both the device owner and lease capability match.
    pub(crate) fn release_lease_for_device(
        &mut self,
        workload_id: &str,
        device_id: &str,
        lease_token: &[u8; 32],
    ) -> bool {
        if !self
            .jobs
            .get(workload_id)
            .is_some_and(|job| job.0 == device_id)
        {
            return false;
        }
        self.release_lease(workload_id, lease_token)
    }

    /// Renew only when the caller proves possession of the lease capability.
    pub(crate) fn renew_lease(
        &mut self,
        workload_id: &str,
        lease_token: &[u8; 32],
        now_unix_ms: u64,
    ) -> bool {
        self.expire(now_unix_ms);
        let Some(expected) = self.lease_token_hashes.get(workload_id) else {
            return false;
        };
        if !constant_time_eq(expected, &lease_token_hash(lease_token)) {
            return false;
        }
        let Some(device_id) = self.jobs.get(workload_id).map(|job| job.0.clone()) else {
            return false;
        };
        let current_revision = self
            .reservation_revisions
            .get(&device_id)
            .copied()
            .unwrap_or(0);
        let Some(next_revision) = current_revision.checked_add(1) else {
            return false;
        };
        let Some(job) = self.jobs.get_mut(workload_id) else {
            return false;
        };
        job.3 = now_unix_ms.saturating_add(LEASE_MS);
        self.reservation_revisions.insert(device_id, next_revision);
        true
    }

    /// Release only when the caller proves possession of the lease capability.
    pub(crate) fn release_lease(&mut self, workload_id: &str, lease_token: &[u8; 32]) -> bool {
        let Some(expected) = self.lease_token_hashes.get(workload_id) else {
            return false;
        };
        if !constant_time_eq(expected, &lease_token_hash(lease_token)) {
            return false;
        }
        self.release(workload_id);
        true
    }

    pub(crate) fn consume_challenge_nonce(
        &mut self,
        nonce: [u8; 16],
        expires_unix_ms: u64,
        now_unix_ms: u64,
    ) -> bool {
        self.consumed_challenges
            .retain(|_, expires| *expires > now_unix_ms);
        if expires_unix_ms <= now_unix_ms || self.consumed_challenges.contains_key(&nonce) {
            return false;
        }
        self.consumed_challenges.insert(nonce, expires_unix_ms);
        true
    }

    /// Atomically consume a challenge and advance the device's signed telemetry
    /// generation and reservation watermark.
    pub(crate) fn consume_telemetry_challenge(
        &mut self,
        device_id: &str,
        generation: u64,
        reservation_revision: u64,
        nonce: [u8; 16],
        expires_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), TelemetryChallengeError> {
        self.expire(now_unix_ms);
        if generation == 0
            || self
                .telemetry_generations
                .get(device_id)
                .is_some_and(|previous| generation <= *previous)
        {
            return Err(TelemetryChallengeError::Replayed);
        }
        let current_revision = self
            .reservation_revisions
            .get(device_id)
            .copied()
            .unwrap_or(0);
        if reservation_revision > current_revision
            || self
                .telemetry_reservation_watermarks
                .get(device_id)
                .is_some_and(|previous| reservation_revision < *previous)
        {
            return Err(TelemetryChallengeError::InvalidReservationWatermark);
        }
        if !self.consume_challenge_nonce(nonce, expires_unix_ms, now_unix_ms) {
            return Err(TelemetryChallengeError::Replayed);
        }
        self.telemetry_generations
            .insert(device_id.to_owned(), generation);
        self.telemetry_reservation_watermarks
            .insert(device_id.to_owned(), reservation_revision);
        Ok(())
    }

    /// Reserve against a signed capacity sample without double-counting leases
    /// already reflected in that sample. Reservations committed after the
    /// sample watermark remain charged against its reported free headroom.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_and_reserve_with_lease_and_watermark(
        &mut self,
        device: &Device,
        workload: &Workload,
        context: &SchedulingContext,
        policies: &[ClassPolicy],
        approvals: &[VerifiedAdminApproval],
        now_unix_ms: u64,
        lease_token: &[u8; 32],
        sample_generation: u64,
        reservation_revision: u64,
        signed_cpu_headroom_millis: u32,
        signed_memory_headroom_mb: u64,
    ) -> Admission {
        self.expire(now_unix_ms);
        if self.telemetry_generations.get(&device.device_id) != Some(&sample_generation)
            || self.telemetry_reservation_watermarks.get(&device.device_id)
                != Some(&reservation_revision)
        {
            return Admission::Reject(RejectReason::TelemetrySuperseded);
        }
        let current_revision = self
            .reservation_revisions
            .get(&device.device_id)
            .copied()
            .unwrap_or(0);
        if reservation_revision > current_revision {
            return Admission::Reject(RejectReason::TelemetryWatermarkInvalid);
        }

        let mut accounted_cpu = 0u32;
        let mut accounted_memory = 0u64;
        for (workload_id, job) in &self.jobs {
            if job.0 == device.device_id
                && self
                    .job_reservation_revisions
                    .get(workload_id)
                    .copied()
                    .unwrap_or(0)
                    <= reservation_revision
            {
                accounted_cpu = accounted_cpu.saturating_add(job.1);
                accounted_memory = accounted_memory.saturating_add(job.2);
            }
        }

        let mut reservation_device = device.clone();
        reservation_device.remaining_cpu_millis = device
            .remaining_cpu_millis
            .min(signed_cpu_headroom_millis.saturating_add(accounted_cpu));
        reservation_device.remaining_memory_mb = device
            .remaining_memory_mb
            .min(signed_memory_headroom_mb.saturating_add(accounted_memory));
        self.admit_and_reserve_with_lease(
            &reservation_device,
            workload,
            context,
            policies,
            approvals,
            now_unix_ms,
            lease_token,
        )
    }

    pub fn expire(&mut self, now_unix_ms: u64) {
        let expired: Vec<String> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.3 <= now_unix_ms)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.release(&id);
        }
        self.consumed_challenges
            .retain(|_, expires| *expires > now_unix_ms);
    }
}

/// Hash lease capabilities with a domain separator so they cannot be confused
/// with other SHA-256 values stored by this crate.
fn lease_token_hash(token: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"UJANI-ENTERPRISE-LEASE-CAPABILITY-V1\0");
    hasher.update(token);
    hasher.finalize().into()
}

/// Compare secret-derived digests without an early-exit byte comparison.
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// Conservative pre-scheduling check. Real enforcement must occur on the worker OS.
fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

/// Validate administrator policy before using it for admission. Duplicate class
/// entries are ambiguous and therefore rejected rather than silently taking the first.
pub fn validate_policies(policies: &[ClassPolicy]) -> Result<(), &'static str> {
    let mut seen = std::collections::HashSet::new();
    for policy in policies {
        if !valid_identifier(&policy.class, 64)
            || policy.max_cpu_millis == 0
            || policy.max_memory_mb == 0
        {
            return Err("invalid class policy");
        }
        if !seen.insert(policy.class.as_str()) {
            return Err("duplicate class policy");
        }
    }
    Ok(())
}

/// Pure policy evaluation only. Acceptance is not a reservation or execution grant.
pub fn admit(
    device: &Device,
    workload: &Workload,
    policies: &[ClassPolicy],
    verified_admin_approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
) -> Admission {
    use RejectReason::*;
    if !valid_identifier(&device.device_id, 128)
        || !valid_identifier(&workload.workload_id, 128)
        || !valid_identifier(&workload.class, 64)
    {
        return Admission::Reject(InvalidIdentifier);
    }
    if workload.requested_cpu_millis == 0 || workload.requested_memory_mb == 0 {
        return Admission::Reject(ZeroBudget);
    }
    if !device.enrolled || !device.admin_approved {
        return Admission::Reject(DeviceNotApproved);
    }
    if !device.available {
        return Admission::Reject(DeviceUnavailable);
    }
    if !device
        .allowed_workload_classes
        .iter()
        .any(|c| c == &workload.class)
    {
        return Admission::Reject(ClassNotAllowedOnDevice);
    }
    if validate_policies(policies).is_err() {
        return Admission::Reject(InvalidClassPolicy);
    }
    let Some(policy) = policies.iter().find(|p| p.class == workload.class) else {
        return Admission::Reject(UnknownClassPolicy);
    };
    if policy.requires_admin_approval
        && !verified_admin_approvals
            .iter()
            .any(|approval| approval_covers(approval, device, workload, now_unix_ms))
    {
        return Admission::Reject(ApprovalRequired);
    }
    if workload.requested_cpu_millis > policy.max_cpu_millis
        || workload.requested_memory_mb > policy.max_memory_mb
    {
        return Admission::Reject(ExceedsClassLimit);
    }
    if workload.requested_cpu_millis > device.remaining_cpu_millis {
        return Admission::Reject(CpuBudget);
    }
    if workload.requested_memory_mb > device.remaining_memory_mb {
        return Admission::Reject(MemoryBudget);
    }
    Admission::Accept
}
/// Runtime facts required by the stricter scheduling gate. Missing or stale evidence must fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingContext {
    pub owner_opted_in: bool,
    pub within_admin_schedule: bool,
    pub interactive_user_present: bool,
    pub on_ac_power: bool,
    /// True only when already powered on; UJANI must never wake devices.
    pub device_already_running: bool,
    pub thermal_state_safe: bool,
    pub network_policy_allows: bool,
    pub data_classification_allows: bool,
    pub telemetry_fresh: bool,
}

/// Stronger admission gate for future scheduled workloads.
/// Production workers must independently enforce these conditions immediately before launch.
pub(crate) fn admit_with_context(
    device: &Device,
    workload: &Workload,
    context: &SchedulingContext,
    policies: &[ClassPolicy],
    verified_admin_approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
) -> Admission {
    match admit(
        device,
        workload,
        policies,
        verified_admin_approvals,
        now_unix_ms,
    ) {
        Admission::Accept => {}
        rejection => return rejection,
    }
    if !context.telemetry_fresh {
        return Admission::Reject(RejectReason::TelemetryStale);
    }
    if !context.owner_opted_in {
        return Admission::Reject(RejectReason::OwnerOptInMissing);
    }
    if !context.within_admin_schedule {
        return Admission::Reject(RejectReason::OutsideAdminSchedule);
    }
    if context.interactive_user_present {
        return Admission::Reject(RejectReason::InteractiveUserPresent);
    }
    if !context.device_already_running {
        return Admission::Reject(RejectReason::DeviceNotRunning);
    }
    if !context.on_ac_power {
        return Admission::Reject(RejectReason::OnBattery);
    }
    if !context.thermal_state_safe {
        return Admission::Reject(RejectReason::ThermalUnsafe);
    }
    if !context.network_policy_allows {
        return Admission::Reject(RejectReason::NetworkPolicyDenied);
    }
    if !context.data_classification_allows {
        return Admission::Reject(RejectReason::DataClassificationDenied);
    }
    Admission::Accept
}

/// Atomically apply all admission gates and reserve capacity in the in-memory
/// prototype ledger. Production must perform the same operation in one DB transaction.
pub(crate) fn admit_and_reserve(
    ledger: &mut Ledger,
    device: &Device,
    workload: &Workload,
    context: &SchedulingContext,
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
) -> Admission {
    ledger.expire(now_unix_ms);
    let decision = admit_with_context(device, workload, context, policies, approvals, now_unix_ms);
    if decision != Admission::Accept {
        return decision;
    }
    let approval_id = policies
        .iter()
        .find(|p| p.class == workload.class && p.requires_admin_approval)
        .and_then(|_| {
            approvals
                .iter()
                .find(|a| approval_covers(a, device, workload, now_unix_ms))
        })
        .map(|a| a.0.approval_id.as_str());
    match ledger.try_reserve(device, workload, now_unix_ms, approval_id) {
        Ok(()) => Admission::Accept,
        Err(reason) => Admission::Reject(reason),
    }
}

pub mod durable_ledger;
pub use durable_ledger::{
    DurableLedger, DurableLedgerError, DurableLedgerSnapshot, LedgerIntegrityKey,
};

pub mod scheduling_evidence;
pub use scheduling_evidence::{
    authenticate_verify_and_reserve_worker_telemetry, canonical_worker_telemetry_body,
    AuthenticatedTelemetryAdmissionError, SchedulingEvidenceError, SchedulingPolicyClaims,
    SignedSchedulingPolicy, SignedWorkerTelemetry, WorkerTelemetryClaims,
    WORKER_TELEMETRY_REQUEST_METHOD, WORKER_TELEMETRY_REQUEST_RESOURCE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn device() -> Device {
        Device {
            device_id: "lab-gpu-01".into(),
            enrolled: true,
            admin_approved: true,
            available: true,
            allowed_workload_classes: vec!["inference".into()],
            remaining_cpu_millis: 4000,
            remaining_memory_mb: 8192,
        }
    }

    fn manifest() -> WorkloadManifest {
        WorkloadManifest {
            schema_version: 1,
            workload_id: "job-001".into(),
            class: "inference".into(),
            model: "qwen2.5:3b".into(),
            requested_cpu_millis: 2000,
            requested_memory_mb: 4096,
            max_runtime_ms: 60_000,
            data_classification: DataClassification::Internal,
            network_access: false,
        }
    }

    fn workload() -> Workload {
        workload_from_manifest(&manifest()).unwrap()
    }

    fn safe_context() -> SchedulingContext {
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
            max_cpu_millis: 4000,
            max_memory_mb: 8192,
        }]
    }

    #[test]
    fn workload_manifest_accepts_bounded_versioned_input() {
        assert_eq!(validate_workload_manifest(&manifest()), Ok(()));
    }

    #[test]
    fn manifest_digest_changes_when_any_execution_field_changes() {
        let original = manifest();
        let digest = workload_manifest_sha256(&original).unwrap();
        let mut changed = original.clone();
        changed.model = "qwen2.5:14b".into();
        assert_ne!(digest, workload_manifest_sha256(&changed).unwrap());
        let mut changed = original.clone();
        changed.network_access = true;
        assert_ne!(digest, workload_manifest_sha256(&changed).unwrap());
        let mut changed = original.clone();
        changed.data_classification = DataClassification::Restricted;
        assert_ne!(digest, workload_manifest_sha256(&changed).unwrap());
        let mut changed = original;
        changed.max_runtime_ms += 1;
        assert_ne!(digest, workload_manifest_sha256(&changed).unwrap());
    }

    #[test]
    fn security_manifest_hash_prevents_bait_and_switch_attacks() {
        // 1. Create a legitimate, approved manifest (Public data, no network).
        let mut safe_manifest = manifest();
        safe_manifest.data_classification = DataClassification::Public;
        safe_manifest.network_access = false;
        let safe_hash = workload_manifest_sha256(&safe_manifest).unwrap();

        // 2. Keep the workload ID but increase both the data classification
        // and network privilege: the approved digest must no longer match.
        let mut malicious_manifest = safe_manifest.clone();
        malicious_manifest.data_classification = DataClassification::Restricted;
        malicious_manifest.network_access = true;
        assert_eq!(safe_manifest.workload_id, malicious_manifest.workload_id);

        let malicious_hash = workload_manifest_sha256(&malicious_manifest).unwrap();

        // 3. Any security-sensitive manifest substitution changes the digest.
        assert_ne!(
            safe_hash, malicious_hash,
            "SECURITY FAILURE: Manifest hash did not change when classification and network access changed!"
        );
    }

    #[test]
    fn manifest_rejects_urls_paths_and_untrusted_registry_endpoints_as_models() {
        for model in [
            "https://example.com/model",
            "../local/model",
            "/absolute/model",
            "localhost:5000/model",
            "hf.co/org/model",
        ] {
            let mut value = manifest();
            value.model = model.into();
            assert_eq!(
                validate_workload_manifest(&value),
                Err(ManifestError::InvalidModel)
            );
        }
        let mut library_model = manifest();
        library_model.model = "library/llama3.2".into();
        assert_eq!(validate_workload_manifest(&library_model), Ok(()));
    }

    #[test]
    fn administrator_approval_has_bounded_issue_time_and_lifetime() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let mut claims = AdminApprovalClaims {
            approval_id: "approval-time".into(),
            workload_id: "job-001".into(),
            device_id: "lab-gpu-01".into(),
            class: "inference".into(),
            max_cpu_millis: 2000,
            max_memory_mb: 4096,
            approver_key_id: "admin-key-1".into(),
            manifest_sha256: workload_manifest_sha256(&manifest()).unwrap(),
            issued_at_unix_ms: 1_000,
            expires_unix_ms: 2_000,
        };
        let keys = vec![("admin-key-1".into(), signing.verifying_key())];
        claims.issued_at_unix_ms = 40_000;
        let signed = SignedAdminApproval {
            signature: signing.sign(&admin_approval_bytes(&claims)).to_bytes(),
            claims: claims.clone(),
        };
        assert!(verify_admin_approval(&signed, &keys, 1_000).is_err());
        claims.issued_at_unix_ms = 1_000;
        claims.expires_unix_ms = 1_000 + MAX_ADMIN_APPROVAL_TTL_MS + 1;
        let signed = SignedAdminApproval {
            signature: signing.sign(&admin_approval_bytes(&claims)).to_bytes(),
            claims,
        };
        assert!(verify_admin_approval(&signed, &keys, 1_000).is_err());
    }

    #[test]
    fn workload_manifest_rejects_unknown_versions_and_invalid_limits() {
        let mut value = manifest();
        value.schema_version = 2;
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::UnsupportedVersion)
        );
        let mut value = manifest();
        value.requested_cpu_millis = 0;
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::InvalidCpuLimit)
        );
        let mut value = manifest();
        value.requested_memory_mb = 4 * 1024 * 1024 + 1;
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::InvalidMemoryLimit)
        );
        let mut value = manifest();
        value.max_runtime_ms = 7 * 24 * 60 * 60 * 1000 + 1;
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::InvalidRuntimeLimit)
        );
    }

    #[test]
    fn workload_manifest_rejects_malformed_identifiers_and_model_names() {
        let mut value = manifest();
        value.workload_id = "../job".into();
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::InvalidWorkloadId)
        );
        let mut value = manifest();
        value.class = "inference\nadmin".into();
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::InvalidClass)
        );
        let mut value = manifest();
        value.model = "model\nignore policy".into();
        assert_eq!(
            validate_workload_manifest(&value),
            Err(ManifestError::InvalidModel)
        );
    }

    #[test]
    fn strict_gate_accepts_only_when_all_scheduling_conditions_are_safe() {
        assert_eq!(
            admit_with_context(
                &device(),
                &workload(),
                &safe_context(),
                &policies(),
                &[],
                1_000
            ),
            Admission::Accept
        );
    }

    #[test]
    fn strict_gate_rejects_missing_opt_in_or_outside_schedule() {
        let mut c = safe_context();
        c.owner_opted_in = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.within_admin_schedule = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_prioritizes_interactive_use_and_power_safety() {
        let mut c = safe_context();
        c.interactive_user_present = true;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.on_ac_power = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.thermal_state_safe = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn security_never_wakes_sleeping_devices_even_when_other_conditions_are_safe() {
        // All other admission conditions are safe, but the device is not running.
        let mut sleeping_device_context = safe_context();
        sleeping_device_context.device_already_running = false;

        // Power state alone must reject admission. UJANI never wakes devices.
        let result = admit_with_context(
            &device(),
            &workload(),
            &sleeping_device_context,
            &policies(),
            &[],
            1_000,
        );

        assert_eq!(
            result,
            Admission::Reject(RejectReason::DeviceNotRunning),
            "SECURITY FAILURE: System attempted to wake a sleeping device!"
        );
    }

    #[test]
    fn strict_gate_rejects_stale_telemetry_and_data_policy_violations() {
        let mut c = safe_context();
        c.telemetry_fresh = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.network_policy_allows = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.data_classification_allows = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn approved_available_device_accepts_within_budget() {
        assert_eq!(
            admit(&device(), &workload(), &policies(), &[], 1_000),
            Admission::Accept
        );
    }

    #[test]
    fn unapproved_device_is_rejected() {
        let mut d = device();
        d.admin_approved = false;
        assert!(matches!(
            admit(&d, &workload(), &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn unavailable_device_is_rejected() {
        let mut d = device();
        d.available = false;
        assert!(matches!(
            admit(&d, &workload(), &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn disallowed_class_is_rejected() {
        let mut w = workload();
        w.class = "arbitrary-shell".into();
        assert!(matches!(
            admit(&device(), &w, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn quota_overrun_is_rejected() {
        let mut w = workload();
        w.requested_memory_mb = 9000;
        assert!(matches!(
            admit(&device(), &w, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn rejects_empty_or_malformed_identifiers_and_classes() {
        let mut d = device();
        d.device_id = "   ".into();
        assert!(matches!(
            admit(&d, &workload(), &policies(), &[], 1_000),
            Admission::Reject(_)
        ));

        let mut w = workload();
        w.workload_id = "job/../../escape".into();
        assert!(matches!(
            admit(&device(), &w, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));

        let mut w = workload();
        w.class = "inference\nadmin".into();
        assert!(matches!(
            admit(&device(), &w, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn rejects_zero_resource_requests() {
        let mut w = workload();
        w.requested_cpu_millis = 0;
        assert!(matches!(
            admit(&device(), &w, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));

        let mut w = workload();
        w.requested_memory_mb = 0;
        assert!(matches!(
            admit(&device(), &w, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn submitter_claim_cannot_waive_admin_class_approval() {
        let w = workload();
        let policy = ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: true,
            max_cpu_millis: 4000,
            max_memory_mb: 8192,
        };
        assert_eq!(
            admit(&device(), &w, &[policy], &[], 1_000),
            Admission::Reject(RejectReason::ApprovalRequired)
        );
        assert_eq!(
            admit(
                &device(),
                &w,
                &[ClassPolicy {
                    class: "inference".into(),
                    requires_admin_approval: true,
                    max_cpu_millis: 4000,
                    max_memory_mb: 8192,
                }],
                &[],
                1_000
            ),
            Admission::Reject(RejectReason::ApprovalRequired)
        );
    }

    #[test]
    fn ledger_prevents_oversubscription_and_releases_reservations() {
        let mut ledger = Ledger::default();
        let d = device();
        let first = workload();
        let mut second = workload();
        second.workload_id = "job-002".into();
        let mut third = workload();
        third.workload_id = "job-003".into();
        assert!(ledger.try_reserve(&d, &first, 1_000, None).is_ok());
        assert!(ledger.try_reserve(&d, &second, 1_000, None).is_ok());
        assert_eq!(
            ledger.try_reserve(&d, &third, 1_000, None),
            Err(RejectReason::CpuBudget)
        );
        ledger.release("job-001");
        assert!(ledger.try_reserve(&d, &third, 1_000, None).is_ok());
    }

    #[test]
    fn atomic_admission_reserves_once_and_rejects_replay_after_release() {
        let mut ledger = Ledger::default();
        let d = device();
        let w = workload();
        let context = safe_context();
        assert_eq!(
            admit_and_reserve(&mut ledger, &d, &w, &context, &policies(), &[], 1_000),
            Admission::Accept
        );
        assert_eq!(
            admit_and_reserve(&mut ledger, &d, &w, &context, &policies(), &[], 1_000),
            Admission::Reject(RejectReason::DuplicateWorkload)
        );
        ledger.release("job-001");
        assert_eq!(
            admit_and_reserve(&mut ledger, &d, &w, &context, &policies(), &[], 1_001),
            Admission::Accept
        );
    }

    #[test]
    fn lease_capability_is_required_for_renewal_and_release() {
        let mut ledger = Ledger::default();
        let d = device();
        let w = workload();
        let token = [0x5au8; 32];
        assert_eq!(
            ledger.admit_and_reserve_with_lease(
                &d,
                &w,
                &safe_context(),
                &policies(),
                &[],
                1_000,
                &token
            ),
            Admission::Accept
        );
        let wrong = [0x33u8; 32];
        assert!(!ledger.renew_lease("job-001", &wrong, 2_000));
        assert!(!ledger.release_lease("job-001", &wrong));
        assert!(ledger.renew_lease("job-001", &token, 2_000));
        assert!(ledger.release_lease("job-001", &token));
        assert!(!ledger.renew_lease("job-001", &token, 2_001));
    }

    #[test]
    fn lease_renewal_and_release_are_bound_to_the_enrolled_device() {
        let mut ledger = Ledger::default();
        let d = device();
        let w = workload();
        let token = [0x5au8; 32];
        assert_eq!(
            ledger.admit_and_reserve_with_lease(
                &d,
                &w,
                &safe_context(),
                &policies(),
                &[],
                1_000,
                &token
            ),
            Admission::Accept
        );

        assert!(!ledger.renew_lease_for_device("job-001", "another-device", &token, 2_000));
        assert!(!ledger.release_lease_for_device("job-001", "another-device", &token));
        assert!(ledger.renew_lease_for_device("job-001", &d.device_id, &token, 2_000));
        assert!(ledger.release_lease_for_device("job-001", &d.device_id, &token));
        assert!(!ledger.renew_lease_for_device("job-001", &d.device_id, &token, 2_001));
    }

    #[test]
    fn lease_capabilities_cannot_be_zero_or_reused_for_another_workload() {
        let mut ledger = Ledger::default();
        let d = device();
        let token = [0x5au8; 32];
        let zero = [0u8; 32];
        assert_eq!(
            ledger.admit_and_reserve_with_lease(
                &d,
                &workload(),
                &safe_context(),
                &policies(),
                &[],
                1_000,
                &zero
            ),
            Admission::Reject(RejectReason::InvalidLeaseToken)
        );
        assert_eq!(
            ledger.admit_and_reserve_with_lease(
                &d,
                &workload(),
                &safe_context(),
                &policies(),
                &[],
                1_000,
                &token
            ),
            Admission::Accept
        );
        let mut next = workload();
        next.workload_id = "job-002".into();
        assert_eq!(
            ledger.admit_and_reserve_with_lease(
                &d,
                &next,
                &safe_context(),
                &policies(),
                &[],
                1_001,
                &token
            ),
            Admission::Reject(RejectReason::InvalidLeaseToken)
        );
    }

    #[test]
    fn ledger_leases_expire_and_release_capacity() {
        let mut ledger = Ledger::default();
        let d = device();
        let w = workload();
        let token = [0x5au8; 32];
        assert!(ledger.try_reserve(&d, &w, 1_000, None).is_ok());
        assert!(!ledger.renew_lease("job-001", &token, 1_000 + LEASE_MS));
        ledger.expire(1_000 + LEASE_MS);
        let mut next = workload();
        next.workload_id = "job-002".into();
        assert!(ledger
            .try_reserve(&d, &next, 1_000 + LEASE_MS, None)
            .is_ok());
    }

    #[test]
    fn duplicate_or_zero_limit_class_policies_are_rejected() {
        let duplicate = vec![policies()[0].clone(), policies()[0].clone()];
        assert_eq!(
            admit(&device(), &workload(), &duplicate, &[], 1_000),
            Admission::Reject(RejectReason::InvalidClassPolicy)
        );
        let invalid = vec![ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 0,
            max_memory_mb: 1024,
        }];
        assert_eq!(validate_policies(&invalid), Err("invalid class policy"));
    }

    #[test]
    fn signed_approval_is_bound_to_device_class_limits_and_expiry() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let claims = AdminApprovalClaims {
            approval_id: "approval-001".into(),
            workload_id: "job-001".into(),
            device_id: "lab-gpu-01".into(),
            class: "inference".into(),
            max_cpu_millis: 2000,
            max_memory_mb: 4096,
            approver_key_id: "admin-key-1".into(),
            manifest_sha256: workload_manifest_sha256(&manifest()).unwrap(),
            issued_at_unix_ms: 1_000,
            expires_unix_ms: 2_000,
        };
        let signature = signing.sign(&admin_approval_bytes(&claims)).to_bytes();
        let signed = SignedAdminApproval { claims, signature };
        let keys = vec![("admin-key-1".into(), signing.verifying_key())];
        let verified = verify_admin_approval(&signed, &keys, 1_000).unwrap();
        let approval_policy = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: true,
            max_cpu_millis: 4000,
            max_memory_mb: 8192,
        }];
        assert_eq!(
            admit(
                &device(),
                &workload(),
                &approval_policy,
                std::slice::from_ref(&verified),
                1_000
            ),
            Admission::Accept
        );

        let mut changed_manifest = manifest();
        changed_manifest.model = "qwen2.5:7b".into();
        let changed_workload = workload_from_manifest(&changed_manifest).unwrap();
        assert_eq!(
            admit(
                &device(),
                &changed_workload,
                &approval_policy,
                std::slice::from_ref(&verified),
                1_000
            ),
            Admission::Reject(RejectReason::ApprovalRequired)
        );

        let mut other_device = device();
        other_device.device_id = "lab-gpu-02".into();
        assert_eq!(
            admit(
                &other_device,
                &workload(),
                &approval_policy,
                std::slice::from_ref(&verified),
                1_000
            ),
            Admission::Reject(RejectReason::ApprovalRequired)
        );

        let mut other_class = workload();
        other_class.class = "batch".into();
        assert_eq!(
            admit(
                &device(),
                &other_class,
                &approval_policy,
                std::slice::from_ref(&verified),
                1_000
            ),
            Admission::Reject(RejectReason::ClassNotAllowedOnDevice)
        );

        let mut excessive = workload();
        excessive.requested_cpu_millis = 2500;
        assert_eq!(
            admit(&device(), &excessive, &approval_policy, &[verified], 1_000),
            Admission::Reject(RejectReason::ApprovalRequired)
        );

        assert!(verify_admin_approval(&signed, &keys, 2_000).is_err());
        let mut tampered = signed.clone();
        tampered.claims.class = "batch".into();
        assert!(verify_admin_approval(&tampered, &keys, 1_000).is_err());
    }

    #[test]
    fn approval_gate_is_enforced() {
        let w = workload();
        let policy = ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: true,
            max_cpu_millis: 4000,
            max_memory_mb: 8192,
        };
        assert_eq!(
            admit(&device(), &w, &[policy], &[], 1_000),
            Admission::Reject(RejectReason::ApprovalRequired)
        );
    }
}

pub mod inventory;
pub mod lease_control;
pub mod operator_control_plane;
pub mod operator_http_contract;
/// Fail-closed durable revocation boundary for operator sessions.
pub mod operator_session_revocation;
pub use inventory::{
    summarize_inventory, validate_inventory_record, DeviceInventoryRecord, DevicePowerState,
    InventoryError, InventorySummary, InventoryTrust,
};
pub mod model_inventory;
pub use model_inventory::{
    match_model_to_task, validate_model_runtime_inventory, ModelCapabilityMatch, ModelFitReason,
    ModelFitStatus, ModelInventoryValidationError, ModelRuntimeInventory, ModelTaskRequirements,
};
