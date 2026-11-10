//! Signed, challenge-bound scheduling evidence.
//!
//! Worker telemetry is signed by the enrolled worker device. Scheduling,
//! network-egress and data-classification decisions are signed by an enrolled
//! administrator key and bound to the exact workload manifest. Callers cannot
//! construct a VerifiedSchedulingContext directly.
use crate::cpu_capacity::{
    evaluate_cpu_placement, CpuPlacementRejection, CpuPlacementRequest, CpuWorkerSnapshot,
};
use crate::{
    admit_with_context, Admission, ClassPolicy, Device, DurableLedger, DurableLedgerError, Ledger,
    RejectReason, SchedulingContext, TelemetryChallengeError, VerifiedAdminApproval, Workload,
};
use ed25519_dalek::{Signature, VerifyingKey};

const TELEMETRY_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-WORKER-TELEMETRY-V1\0";
const POLICY_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SCHEDULING-POLICY-V1\0";
const CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;
pub const MAX_WORKER_TELEMETRY_TTL_MS: u64 = 30_000;
pub const MAX_SCHEDULING_POLICY_TTL_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTelemetryClaims {
    pub device_id: String,
    pub challenge_nonce: [u8; 16],
    /// Strictly increasing per-device counter from the enrolled worker agent.
    pub sample_generation: u64,
    /// Ledger reservation revision already reflected in the signed free-capacity sample.
    pub reservation_revision: u64,
    pub issued_at_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub owner_opted_in: bool,
    pub interactive_user_present: bool,
    pub on_ac_power: bool,
    pub device_already_running: bool,
    pub thermal_state_safe: bool,
    pub user_paused: bool,
    pub os_isolation_ready: bool,
    pub effective_cpu_capacity_millis: u32,
    pub available_cpu_millis: u32,
    pub system_reserved_cpu_millis: u32,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub system_reserved_memory_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWorkerTelemetry {
    pub claims: WorkerTelemetryClaims,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingPolicyClaims {
    pub policy_id: String,
    pub policy_key_id: String,
    pub device_id: String,
    pub workload_id: String,
    pub manifest_sha256: [u8; 32],
    pub challenge_nonce: [u8; 16],
    /// Control-plane-signed revision expected in the worker's capacity sample.
    pub reservation_revision: u64,
    pub issued_at_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub within_admin_schedule: bool,
    pub network_policy_allows: bool,
    pub data_classification_allows: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSchedulingPolicy {
    pub claims: SchedulingPolicyClaims,
    pub signature: [u8; 64],
}

/// A non-cloneable, single-use scheduling context. It retains the exact device,
/// workload manifest and expiry that were covered by the signed evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedSchedulingContext {
    context: SchedulingContext,
    device_id: String,
    workload_id: String,
    manifest_sha256: [u8; 32],
    expires_at_unix_ms: u64,
    sample_generation: u64,
    reservation_revision: u64,
    challenge_nonce: [u8; 16],
    challenge_consumed: bool,
    cpu_worker_snapshot: CpuWorkerSnapshot,
}

impl VerifiedSchedulingContext {
    fn rejection_for(
        &self,
        device: &Device,
        workload: &Workload,
        now_unix_ms: u64,
    ) -> Option<RejectReason> {
        if self.device_id != device.device_id
            || self.workload_id != workload.workload_id
            || self.manifest_sha256 != workload.manifest_sha256
        {
            return Some(RejectReason::SchedulingEvidenceMismatch);
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return Some(RejectReason::SchedulingEvidenceExpired);
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingEvidenceError {
    InvalidIdentifier,
    DeviceMismatch,
    WorkloadMismatch,
    ManifestMismatch,
    ChallengeMismatch,
    InvalidTimeWindow,
    UnknownDeviceKey,
    UnknownAdminKey,
    InvalidWorkerSignature,
    InvalidPolicySignature,
    ChallengeReplayed,
    InvalidReservationWatermark,
    ChallengeStoreUnavailable,
    /// The anchor outcome is ambiguous; callers must reconcile before retrying.
    ChallengeStoreOutcomeUnknown,
}

fn append_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn worker_telemetry_bytes(claims: &WorkerTelemetryClaims) -> Vec<u8> {
    let mut bytes = TELEMETRY_DOMAIN.to_vec();
    append_string(&mut bytes, &claims.device_id);
    bytes.extend_from_slice(&claims.challenge_nonce);
    bytes.extend_from_slice(&claims.sample_generation.to_be_bytes());
    bytes.extend_from_slice(&claims.reservation_revision.to_be_bytes());
    bytes.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.expires_unix_ms.to_be_bytes());
    bytes.push(u8::from(claims.owner_opted_in));
    bytes.push(u8::from(claims.interactive_user_present));
    bytes.push(u8::from(claims.on_ac_power));
    bytes.push(u8::from(claims.device_already_running));
    bytes.push(u8::from(claims.thermal_state_safe));
    bytes.push(u8::from(claims.user_paused));
    bytes.push(u8::from(claims.os_isolation_ready));
    bytes.extend_from_slice(&claims.effective_cpu_capacity_millis.to_be_bytes());
    bytes.extend_from_slice(&claims.available_cpu_millis.to_be_bytes());
    bytes.extend_from_slice(&claims.system_reserved_cpu_millis.to_be_bytes());
    bytes.extend_from_slice(&claims.total_memory_mb.to_be_bytes());
    bytes.extend_from_slice(&claims.available_memory_mb.to_be_bytes());
    bytes.extend_from_slice(&claims.system_reserved_memory_mb.to_be_bytes());
    bytes
}

fn scheduling_policy_bytes(claims: &SchedulingPolicyClaims) -> Vec<u8> {
    let mut bytes = POLICY_DOMAIN.to_vec();
    for value in [
        &claims.policy_id,
        &claims.policy_key_id,
        &claims.device_id,
        &claims.workload_id,
    ] {
        append_string(&mut bytes, value);
    }
    bytes.extend_from_slice(&claims.manifest_sha256);
    bytes.extend_from_slice(&claims.challenge_nonce);
    bytes.extend_from_slice(&claims.reservation_revision.to_be_bytes());
    bytes.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.expires_unix_ms.to_be_bytes());
    bytes.push(u8::from(claims.within_admin_schedule));
    bytes.push(u8::from(claims.network_policy_allows));
    bytes.push(u8::from(claims.data_classification_allows));
    bytes
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

fn valid_time_window(issued: u64, expires: u64, now: u64, max_ttl: u64) -> bool {
    issued <= now.saturating_add(CLOCK_SKEW_TOLERANCE_MS)
        && expires > now
        && expires > issued
        && expires.saturating_sub(issued) <= max_ttl
        && now.saturating_sub(issued) <= max_ttl
}

/// Verify fresh worker telemetry and administrator policy for one dispatch.
/// The caller must issue a cryptographically random, single-use challenge and
/// atomically consume it in its control plane; this function verifies equality
/// but does not provide persistent replay storage. The device/admin key slices
/// must come from an authenticated, non-caller-controlled enrollment registry;
/// supplying attacker-controlled keys defeats the trust guarantee. Device CPU/RAM
/// capacity and workload-class allowlists must also come from trusted inventory;
/// these signed claims attest runtime gates and resource capacity telemetry.
/// This crate does not persist enrollment, revocation or the registry's root of trust.
#[allow(clippy::too_many_arguments)] // Keep both trust roots and the dispatch challenge explicit.
pub(crate) fn verify_scheduling_context(
    device: &Device,
    workload: &Workload,
    telemetry: &SignedWorkerTelemetry,
    policy: &SignedSchedulingPolicy,
    enrolled_device_keys: &[(String, VerifyingKey)],
    enrolled_admin_keys: &[(String, VerifyingKey)],
    expected_challenge_nonce: &[u8; 16],
    now_unix_ms: u64,
) -> Result<VerifiedSchedulingContext, SchedulingEvidenceError> {
    let telemetry_claims = &telemetry.claims;
    let policy_claims = &policy.claims;

    if !valid_identifier(&device.device_id, 128)
        || !valid_identifier(&workload.workload_id, 128)
        || !valid_identifier(&policy_claims.policy_id, 128)
        || !valid_identifier(&policy_claims.policy_key_id, 128)
    {
        return Err(SchedulingEvidenceError::InvalidIdentifier);
    }
    if telemetry_claims.device_id != device.device_id || policy_claims.device_id != device.device_id
    {
        return Err(SchedulingEvidenceError::DeviceMismatch);
    }
    if policy_claims.workload_id != workload.workload_id {
        return Err(SchedulingEvidenceError::WorkloadMismatch);
    }
    if policy_claims.manifest_sha256 != workload.manifest_sha256 {
        return Err(SchedulingEvidenceError::ManifestMismatch);
    }
    if telemetry_claims.challenge_nonce != *expected_challenge_nonce
        || policy_claims.challenge_nonce != *expected_challenge_nonce
    {
        return Err(SchedulingEvidenceError::ChallengeMismatch);
    }
    if telemetry_claims.reservation_revision != policy_claims.reservation_revision {
        return Err(SchedulingEvidenceError::InvalidReservationWatermark);
    }
    if telemetry_claims.sample_generation == 0 {
        return Err(SchedulingEvidenceError::InvalidTimeWindow);
    }
    if !valid_time_window(
        telemetry_claims.issued_at_unix_ms,
        telemetry_claims.expires_unix_ms,
        now_unix_ms,
        MAX_WORKER_TELEMETRY_TTL_MS,
    ) || !valid_time_window(
        policy_claims.issued_at_unix_ms,
        policy_claims.expires_unix_ms,
        now_unix_ms,
        MAX_SCHEDULING_POLICY_TTL_MS,
    ) {
        return Err(SchedulingEvidenceError::InvalidTimeWindow);
    }

    let device_key = enrolled_device_keys
        .iter()
        .find(|(device_id, _)| device_id == &device.device_id)
        .map(|(_, key)| key)
        .ok_or(SchedulingEvidenceError::UnknownDeviceKey)?;
    device_key
        .verify_strict(
            &worker_telemetry_bytes(telemetry_claims),
            &Signature::from_bytes(&telemetry.signature),
        )
        .map_err(|_| SchedulingEvidenceError::InvalidWorkerSignature)?;

    let admin_key = enrolled_admin_keys
        .iter()
        .find(|(key_id, _)| key_id == &policy_claims.policy_key_id)
        .map(|(_, key)| key)
        .ok_or(SchedulingEvidenceError::UnknownAdminKey)?;
    admin_key
        .verify_strict(
            &scheduling_policy_bytes(policy_claims),
            &Signature::from_bytes(&policy.signature),
        )
        .map_err(|_| SchedulingEvidenceError::InvalidPolicySignature)?;

    let context = SchedulingContext {
        owner_opted_in: telemetry_claims.owner_opted_in,
        within_admin_schedule: policy_claims.within_admin_schedule,
        interactive_user_present: telemetry_claims.interactive_user_present,
        on_ac_power: telemetry_claims.on_ac_power,
        device_already_running: telemetry_claims.device_already_running,
        thermal_state_safe: telemetry_claims.thermal_state_safe,
        network_policy_allows: policy_claims.network_policy_allows,
        data_classification_allows: policy_claims.data_classification_allows,
        telemetry_fresh: true,
    };
    Ok(VerifiedSchedulingContext {
        context,
        device_id: device.device_id.clone(),
        workload_id: workload.workload_id.clone(),
        manifest_sha256: workload.manifest_sha256,
        cpu_worker_snapshot: CpuWorkerSnapshot {
            sampled_at_unix_ms: telemetry_claims.issued_at_unix_ms,
            effective_cpu_capacity_millis: telemetry_claims.effective_cpu_capacity_millis,
            available_cpu_millis: telemetry_claims.available_cpu_millis,
            system_reserved_cpu_millis: telemetry_claims.system_reserved_cpu_millis,
            total_memory_mb: telemetry_claims.total_memory_mb,
            available_memory_mb: telemetry_claims.available_memory_mb,
            system_reserved_memory_mb: telemetry_claims.system_reserved_memory_mb,
            powered_on: telemetry_claims.device_already_running,
            owner_opted_in: telemetry_claims.owner_opted_in,
            interactive_user_present: telemetry_claims.interactive_user_present,
            user_paused: telemetry_claims.user_paused,
            on_ac_power: telemetry_claims.on_ac_power,
            thermal_state_safe: telemetry_claims.thermal_state_safe,
            telemetry_authenticated: true,
            os_isolation_ready: telemetry_claims.os_isolation_ready,
        },
        expires_at_unix_ms: telemetry_claims
            .expires_unix_ms
            .min(policy_claims.expires_unix_ms),
        sample_generation: telemetry_claims.sample_generation,
        reservation_revision: telemetry_claims.reservation_revision,
        challenge_nonce: telemetry_claims.challenge_nonce,
        challenge_consumed: false,
    })
}

/// Verify signed evidence and atomically consume its dispatch challenge in the
/// durable ledger. This is the only public constructor for VerifiedSchedulingContext.
#[allow(clippy::too_many_arguments)] // Keep both trust roots and the per-dispatch challenge explicit.
pub fn verify_and_consume_scheduling_context(
    ledger: &DurableLedger,
    device: &Device,
    workload: &Workload,
    telemetry: &SignedWorkerTelemetry,
    policy: &SignedSchedulingPolicy,
    enrolled_device_keys: &[(String, VerifyingKey)],
    enrolled_admin_keys: &[(String, VerifyingKey)],
    expected_challenge_nonce: &[u8; 16],
    now_unix_ms: u64,
) -> Result<VerifiedSchedulingContext, SchedulingEvidenceError> {
    let verified = verify_scheduling_context(
        device,
        workload,
        telemetry,
        policy,
        enrolled_device_keys,
        enrolled_admin_keys,
        expected_challenge_nonce,
        now_unix_ms,
    )?;
    let expires_unix_ms = telemetry
        .claims
        .expires_unix_ms
        .min(policy.claims.expires_unix_ms);
    let consumed = ledger
        .consume_telemetry_challenge(
            &telemetry.claims.device_id,
            telemetry.claims.sample_generation,
            telemetry.claims.reservation_revision,
            *expected_challenge_nonce,
            expires_unix_ms,
            now_unix_ms,
        )
        .map_err(|error| match error {
            DurableLedgerError::AnchorUnavailable(_) => {
                SchedulingEvidenceError::ChallengeStoreOutcomeUnknown
            }
            _ => SchedulingEvidenceError::ChallengeStoreUnavailable,
        })?;
    match consumed {
        Ok(()) => {}
        Err(TelemetryChallengeError::Replayed) => {
            return Err(SchedulingEvidenceError::ChallengeReplayed);
        }
        Err(TelemetryChallengeError::InvalidReservationWatermark) => {
            return Err(SchedulingEvidenceError::InvalidReservationWatermark);
        }
    }
    let mut verified = verified;
    verified.challenge_consumed = true;
    Ok(verified)
}

fn capacity_rejection(
    snapshot: &CpuWorkerSnapshot,
    workload: &Workload,
    now_unix_ms: u64,
) -> Option<RejectReason> {
    let request = CpuPlacementRequest::from(workload);
    evaluate_cpu_placement(snapshot, request, now_unix_ms, MAX_WORKER_TELEMETRY_TTL_MS)
        .err()
        .map(|reason| match reason {
            CpuPlacementRejection::CpuHeadroomInsufficient => RejectReason::CpuBudget,
            CpuPlacementRejection::MemoryHeadroomInsufficient => RejectReason::MemoryBudget,
            CpuPlacementRejection::IsolationUnavailable => RejectReason::WorkerIsolationUnavailable,
            CpuPlacementRejection::StaleTelemetry
            | CpuPlacementRejection::FutureTelemetry
            | CpuPlacementRejection::UnauthenticatedTelemetry => RejectReason::TelemetryStale,
            CpuPlacementRejection::DevicePoweredOff => RejectReason::DeviceNotRunning,
            CpuPlacementRejection::OwnerOptOut | CpuPlacementRejection::UserPaused => {
                RejectReason::OwnerOptInMissing
            }
            CpuPlacementRejection::InteractiveUse => RejectReason::InteractiveUserPresent,
            CpuPlacementRejection::BatteryPower => RejectReason::OnBattery,
            CpuPlacementRejection::ThermalUnsafe => RejectReason::ThermalUnsafe,
            CpuPlacementRejection::InvalidCapacity => RejectReason::DeviceUnavailable,
            CpuPlacementRejection::InvalidRequest => RejectReason::ZeroBudget,
        })
}

/// Return authenticated free headroom after protecting OS/service reserves.
/// The durable ledger reconciles this against leases already reflected in the
/// signed sample and charges only newer reservations against the remaining budget.
fn signed_headroom(snapshot: &CpuWorkerSnapshot) -> (u32, u64) {
    (
        snapshot
            .available_cpu_millis
            .saturating_sub(snapshot.system_reserved_cpu_millis),
        snapshot
            .available_memory_mb
            .saturating_sub(snapshot.system_reserved_memory_mb),
    )
}

/// Evaluate policy using only cryptographically verified scheduling evidence.
pub fn admit_with_verified_context(
    device: &Device,
    workload: &Workload,
    context: &VerifiedSchedulingContext,
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
) -> Admission {
    if let Some(reason) = context.rejection_for(device, workload, now_unix_ms) {
        return Admission::Reject(reason);
    }
    if let Some(reason) = capacity_rejection(&context.cpu_worker_snapshot, workload, now_unix_ms) {
        return Admission::Reject(reason);
    }
    admit_with_context(
        device,
        workload,
        &context.context,
        policies,
        approvals,
        now_unix_ms,
    )
}

/// Atomically persist a reservation after verifying signed scheduling evidence.
#[allow(clippy::too_many_arguments)] // Keep all policy, identity and capability inputs explicit.
pub fn admit_and_reserve_durably_with_verified_lease(
    ledger: &DurableLedger,
    device: &Device,
    workload: &Workload,
    context: VerifiedSchedulingContext,
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
    lease_token: &[u8; 32],
) -> Result<Admission, DurableLedgerError> {
    if let Some(reason) = context.rejection_for(device, workload, now_unix_ms) {
        return Ok(Admission::Reject(reason));
    }
    if !context.challenge_consumed {
        return Ok(Admission::Reject(RejectReason::SchedulingEvidenceMismatch));
    }
    let admission =
        admit_with_verified_context(device, workload, &context, policies, approvals, now_unix_ms);
    if admission != Admission::Accept {
        return Ok(admission);
    }
    let (signed_cpu_headroom_millis, signed_memory_headroom_mb) =
        signed_headroom(&context.cpu_worker_snapshot);
    ledger.admit_and_reserve_with_lease_and_watermark(
        device,
        workload,
        &context.context,
        policies,
        approvals,
        now_unix_ms,
        lease_token,
        context.sample_generation,
        context.reservation_revision,
        signed_cpu_headroom_millis,
        signed_memory_headroom_mb,
    )
}

/// Atomically reserve in the in-memory prototype after verified evidence and
/// lease-capability checks. Production still needs a durable transactional ledger.
#[allow(clippy::too_many_arguments)] // Preserve explicit admission evidence and reservation inputs.
pub fn admit_and_reserve_with_verified_lease(
    ledger: &mut Ledger,
    device: &Device,
    workload: &Workload,
    context: VerifiedSchedulingContext,
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
    lease_token: &[u8; 32],
) -> Admission {
    if let Some(reason) = context.rejection_for(device, workload, now_unix_ms) {
        return Admission::Reject(reason);
    }
    if context.challenge_consumed {
        return Admission::Reject(RejectReason::TelemetrySuperseded);
    }
    match ledger.consume_telemetry_challenge(
        &device.device_id,
        context.sample_generation,
        context.reservation_revision,
        context.challenge_nonce,
        context.expires_at_unix_ms,
        now_unix_ms,
    ) {
        Ok(()) => {}
        Err(TelemetryChallengeError::Replayed) => {
            return Admission::Reject(RejectReason::TelemetrySuperseded);
        }
        Err(TelemetryChallengeError::InvalidReservationWatermark) => {
            return Admission::Reject(RejectReason::TelemetryWatermarkInvalid);
        }
    }
    let admission =
        admit_with_verified_context(device, workload, &context, policies, approvals, now_unix_ms);
    if admission != Admission::Accept {
        return admission;
    }
    let (signed_cpu_headroom_millis, signed_memory_headroom_mb) =
        signed_headroom(&context.cpu_worker_snapshot);
    ledger.admit_and_reserve_with_lease_and_watermark(
        device,
        workload,
        &context.context,
        policies,
        approvals,
        now_unix_ms,
        lease_token,
        context.sample_generation,
        context.reservation_revision,
        signed_cpu_headroom_millis,
        signed_memory_headroom_mb,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{workload_from_manifest, DataClassification, LedgerIntegrityKey, WorkloadManifest};
    use ed25519_dalek::{Signer, SigningKey};
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    // Test-only unpredictable challenge values avoid embedding fixed nonces in
    // signed-message fixtures. Production challenges are issued by the trust service.
    fn fresh_test_challenge() -> [u8; 16] {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut challenge = Vec::with_capacity(16);
        for half in 0..2 {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            sequence.hash(&mut hasher);
            std::process::id().hash(&mut hasher);
            half.hash(&mut hasher);
            challenge.extend_from_slice(&hasher.finish().to_le_bytes());
        }
        challenge
            .try_into()
            .expect("two 8-byte test hashes produce a 16-byte challenge")
    }

    fn fresh_test_lease_token() -> [u8; 32] {
        let first = fresh_test_challenge();
        let second = fresh_test_challenge();
        let mut token = [0u8; 32];
        token[..16].copy_from_slice(&first);
        token[16..].copy_from_slice(&second);
        token
    }

    fn next_test_generation() -> u64 {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    fn device() -> Device {
        Device {
            device_id: "worker-01".into(),
            enrolled: true,
            admin_approved: true,
            available: true,
            allowed_workload_classes: vec!["inference".into()],
            remaining_cpu_millis: 4000,
            remaining_memory_mb: 8192,
        }
    }

    fn workload() -> Workload {
        workload_from_manifest(&WorkloadManifest {
            schema_version: 1,
            workload_id: "job-01".into(),
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

    fn workload_with_resources(workload_id: &str, cpu_millis: u32, memory_mb: u64) -> Workload {
        workload_from_manifest(&WorkloadManifest {
            schema_version: 1,
            workload_id: workload_id.into(),
            class: "inference".into(),
            model: "llama3.2".into(),
            requested_cpu_millis: cpu_millis,
            requested_memory_mb: memory_mb,
            max_runtime_ms: 60_000,
            data_classification: DataClassification::Internal,
            network_access: false,
        })
        .unwrap()
    }

    fn signed_evidence(
        challenge: [u8; 16],
        now: u64,
    ) -> (
        SignedWorkerTelemetry,
        SignedSchedulingPolicy,
        SigningKey,
        SigningKey,
    ) {
        let device_key = SigningKey::from_bytes(&[5u8; 32]);
        let admin_key = SigningKey::from_bytes(&[6u8; 32]);
        let telemetry_claims = WorkerTelemetryClaims {
            device_id: "worker-01".into(),
            challenge_nonce: challenge,
            sample_generation: 1,
            reservation_revision: 0,
            issued_at_unix_ms: now,
            expires_unix_ms: now + MAX_WORKER_TELEMETRY_TTL_MS,
            owner_opted_in: true,
            interactive_user_present: false,
            on_ac_power: true,
            device_already_running: true,
            thermal_state_safe: true,
            user_paused: false,
            os_isolation_ready: true,
            effective_cpu_capacity_millis: 8_000,
            available_cpu_millis: 6_000,
            system_reserved_cpu_millis: 2_000,
            total_memory_mb: 32_768,
            available_memory_mb: 20_000,
            system_reserved_memory_mb: 4_096,
        };
        let telemetry = SignedWorkerTelemetry {
            signature: device_key
                .sign(&worker_telemetry_bytes(&telemetry_claims))
                .to_bytes(),
            claims: telemetry_claims,
        };
        let work = workload();
        let policy_claims = SchedulingPolicyClaims {
            policy_id: "policy-01".into(),
            policy_key_id: "admin-key-01".into(),
            device_id: "worker-01".into(),
            workload_id: work.workload_id.clone(),
            manifest_sha256: crate::workload_manifest_sha256(&crate::WorkloadManifest {
                schema_version: 1,
                workload_id: "job-01".into(),
                class: "inference".into(),
                model: "llama3.2".into(),
                requested_cpu_millis: 1000,
                requested_memory_mb: 1024,
                max_runtime_ms: 60_000,
                data_classification: DataClassification::Internal,
                network_access: false,
            })
            .unwrap(),
            challenge_nonce: challenge,
            reservation_revision: 0,
            issued_at_unix_ms: now,
            expires_unix_ms: now + MAX_SCHEDULING_POLICY_TTL_MS,
            within_admin_schedule: true,
            network_policy_allows: true,
            data_classification_allows: true,
        };
        let policy = SignedSchedulingPolicy {
            signature: admin_key
                .sign(&scheduling_policy_bytes(&policy_claims))
                .to_bytes(),
            claims: policy_claims,
        };
        (telemetry, policy, device_key, admin_key)
    }

    #[test]
    fn durable_ledger_rejects_replayed_or_regressed_worker_telemetry_generations() {
        let path = std::env::temp_dir().join(format!(
            "ujani-telemetry-generation-{}.ledger",
            std::process::id()
        ));
        let open = || {
            DurableLedger::open_with_integrity_keys(
                &path,
                "test-key",
                vec![LedgerIntegrityKey::new("test-key", [0x79; 32])],
            )
            .unwrap()
        };
        let device = device();
        let workload = workload();
        let device_keys = [(
            "worker-01".to_owned(),
            SigningKey::from_bytes(&[5u8; 32]).verifying_key(),
        )];
        let admin_keys = [(
            "admin-key-01".to_owned(),
            SigningKey::from_bytes(&[6u8; 32]).verifying_key(),
        )];

        {
            let ledger = open();
            let challenge = fresh_test_challenge();
            let (telemetry, policy, _, _) = signed_evidence(challenge, 1_000);
            assert!(verify_and_consume_scheduling_context(
                &ledger,
                &device,
                &workload,
                &telemetry,
                &policy,
                &device_keys,
                &admin_keys,
                &challenge,
                2_000,
            )
            .is_ok());

            // A fresh challenge cannot make the same or an older signed sample current.
            let challenge = fresh_test_challenge();
            let (mut telemetry, policy, device_key, _) = signed_evidence(challenge, 2_000);
            telemetry.claims.sample_generation = 1;
            telemetry.signature = device_key
                .sign(&worker_telemetry_bytes(&telemetry.claims))
                .to_bytes();
            assert_eq!(
                verify_and_consume_scheduling_context(
                    &ledger,
                    &device,
                    &workload,
                    &telemetry,
                    &policy,
                    &device_keys,
                    &admin_keys,
                    &challenge,
                    3_000,
                ),
                Err(SchedulingEvidenceError::ChallengeReplayed)
            );

            let challenge = fresh_test_challenge();
            let (mut telemetry, policy, device_key, _) = signed_evidence(challenge, 3_000);
            telemetry.claims.sample_generation = 2;
            telemetry.signature = device_key
                .sign(&worker_telemetry_bytes(&telemetry.claims))
                .to_bytes();
            assert!(verify_and_consume_scheduling_context(
                &ledger,
                &device,
                &workload,
                &telemetry,
                &policy,
                &device_keys,
                &admin_keys,
                &challenge,
                4_000,
            )
            .is_ok());
        }

        // Generation state survives reopening the authenticated ledger.
        {
            let ledger = open();
            let challenge = fresh_test_challenge();
            let (mut telemetry, policy, device_key, _) = signed_evidence(challenge, 4_000);
            telemetry.claims.sample_generation = 2;
            telemetry.signature = device_key
                .sign(&worker_telemetry_bytes(&telemetry.claims))
                .to_bytes();
            assert_eq!(
                verify_and_consume_scheduling_context(
                    &ledger,
                    &device,
                    &workload,
                    &telemetry,
                    &policy,
                    &device_keys,
                    &admin_keys,
                    &challenge,
                    5_000,
                ),
                Err(SchedulingEvidenceError::ChallengeReplayed)
            );
        }

        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(lock_path));
        let _ = std::fs::remove_file(path);
    }

    fn verified_context_for(
        workload: &Workload,
        challenge: [u8; 16],
        now: u64,
        available_cpu_millis: u32,
    ) -> VerifiedSchedulingContext {
        let (mut telemetry, mut policy, device_key, admin_key) = signed_evidence(challenge, now);
        telemetry.claims.sample_generation = next_test_generation();
        telemetry.claims.available_cpu_millis = available_cpu_millis;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        policy.claims.workload_id = workload.workload_id.clone();
        policy.claims.manifest_sha256 = workload.manifest_sha256;
        policy.claims.challenge_nonce = challenge;
        policy.signature = admin_key
            .sign(&scheduling_policy_bytes(&policy.claims))
            .to_bytes();
        verify_scheduling_context(
            &device(),
            workload,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            now + 1_000,
        )
        .unwrap()
    }

    fn verified_context_for_durable(
        ledger: &DurableLedger,
        workload: &Workload,
        challenge: [u8; 16],
        now: u64,
        available_cpu_millis: u32,
        available_memory_mb: u64,
        reservation_revision: u64,
    ) -> VerifiedSchedulingContext {
        let (mut telemetry, mut policy, device_key, admin_key) = signed_evidence(challenge, now);
        telemetry.claims.sample_generation = next_test_generation();
        telemetry.claims.reservation_revision = reservation_revision;
        telemetry.claims.available_cpu_millis = available_cpu_millis;
        telemetry.claims.available_memory_mb = available_memory_mb;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        policy.claims.workload_id = workload.workload_id.clone();
        policy.claims.manifest_sha256 = workload.manifest_sha256;
        policy.claims.challenge_nonce = challenge;
        policy.claims.reservation_revision = reservation_revision;
        policy.signature = admin_key
            .sign(&scheduling_policy_bytes(&policy.claims))
            .to_bytes();
        verify_and_consume_scheduling_context(
            ledger,
            &device(),
            workload,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            now + 1_000,
        )
        .unwrap()
    }

    #[test]
    fn signed_headroom_is_cumulative_in_both_reservation_wrappers() {
        let d = device();
        let first_workload = workload();
        let mut second_workload = workload();
        second_workload.workload_id = "job-02".into();
        let class_policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];

        // 3,500 free CPU minus the 2,000 system reserve leaves 1,500.
        // Each job requests 1,000, so the first fits and the second must not.
        let mut memory_ledger = Ledger::default();
        let first_context = verified_context_for(&first_workload, [0x51; 16], 1_000, 3_500);
        assert_eq!(
            admit_and_reserve_with_verified_lease(
                &mut memory_ledger,
                &d,
                &first_workload,
                first_context,
                &class_policies,
                &[],
                2_000,
                &[0x51; 32],
            ),
            Admission::Accept
        );
        let second_context = verified_context_for(&second_workload, [0x52; 16], 1_000, 3_500);
        assert_eq!(
            admit_and_reserve_with_verified_lease(
                &mut memory_ledger,
                &d,
                &second_workload,
                second_context,
                &class_policies,
                &[],
                2_000,
                &[0x52; 32],
            ),
            Admission::Reject(RejectReason::CpuBudget)
        );

        let path = std::env::temp_dir().join(format!(
            "ujani-signed-headroom-{}.ledger",
            std::process::id()
        ));
        let durable = DurableLedger::open_with_integrity_keys(
            &path,
            "test-key",
            vec![LedgerIntegrityKey::new("test-key", [0x71; 32])],
        )
        .unwrap();
        let first_context = verified_context_for_durable(
            &durable,
            &first_workload,
            [0x61; 16],
            1_000,
            3_500,
            20_000,
            0,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &durable,
                &d,
                &first_workload,
                first_context,
                &class_policies,
                &[],
                2_000,
                &[0x61; 32],
            )
            .unwrap(),
            Admission::Accept
        );
        let second_context = verified_context_for_durable(
            &durable,
            &second_workload,
            [0x62; 16],
            1_000,
            3_500,
            20_000,
            0,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &durable,
                &d,
                &second_workload,
                second_context,
                &class_policies,
                &[],
                2_000,
                &[0x62; 32],
            )
            .unwrap(),
            Admission::Reject(RejectReason::CpuBudget)
        );
        assert_eq!(durable.snapshot().unwrap().reserved_cpu_millis, 1_000);
        drop(durable);
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(lock_path));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn durable_telemetry_watermarks_reject_future_rollback_and_superseded_samples() {
        let path = std::env::temp_dir().join(format!(
            "ujani-telemetry-watermark-{}.ledger",
            std::process::id()
        ));
        let ledger = DurableLedger::open_with_integrity_keys(
            &path,
            "test-key",
            vec![LedgerIntegrityKey::new("test-key", [0x7A; 32])],
        )
        .unwrap();
        let d = device();
        let w = workload();
        let device_keys = [(
            "worker-01".to_owned(),
            SigningKey::from_bytes(&[5u8; 32]).verifying_key(),
        )];
        let admin_keys = [(
            "admin-key-01".to_owned(),
            SigningKey::from_bytes(&[6u8; 32]).verifying_key(),
        )];

        // A sample cannot claim a reservation revision the service has not committed.
        let future_challenge = fresh_test_challenge();
        let (mut future, mut policy, device_key, admin_key) =
            signed_evidence(future_challenge, 1_000);
        future.claims.reservation_revision = 1;
        future.signature = device_key
            .sign(&worker_telemetry_bytes(&future.claims))
            .to_bytes();
        policy.claims.reservation_revision = 1;
        policy.signature = admin_key
            .sign(&scheduling_policy_bytes(&policy.claims))
            .to_bytes();
        assert_eq!(
            verify_and_consume_scheduling_context(
                &ledger,
                &d,
                &w,
                &future,
                &policy,
                &device_keys,
                &admin_keys,
                &future_challenge,
                2_000,
            ),
            Err(SchedulingEvidenceError::InvalidReservationWatermark)
        );

        // A newer accepted sample supersedes an older verified context before
        // reservation, even when both samples refer to the same ledger revision.
        let first_challenge = fresh_test_challenge();
        let (mut first, first_policy, first_device_key, _) =
            signed_evidence(first_challenge, 1_000);
        first.claims.sample_generation = 1;
        first.signature = first_device_key
            .sign(&worker_telemetry_bytes(&first.claims))
            .to_bytes();
        let first_context = verify_and_consume_scheduling_context(
            &ledger,
            &d,
            &w,
            &first,
            &first_policy,
            &device_keys,
            &admin_keys,
            &first_challenge,
            2_000,
        )
        .unwrap();

        let second_challenge = fresh_test_challenge();
        let (mut second, second_policy, second_device_key, _) =
            signed_evidence(second_challenge, 1_000);
        second.claims.sample_generation = 2;
        second.signature = second_device_key
            .sign(&worker_telemetry_bytes(&second.claims))
            .to_bytes();
        let second_context = verify_and_consume_scheduling_context(
            &ledger,
            &d,
            &w,
            &second,
            &second_policy,
            &device_keys,
            &admin_keys,
            &second_challenge,
            2_000,
        )
        .unwrap();

        let policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &ledger,
                &d,
                &w,
                first_context,
                &policies,
                &[],
                2_000,
                &[0x71; 32],
            )
            .unwrap(),
            Admission::Reject(RejectReason::TelemetrySuperseded)
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &ledger,
                &d,
                &w,
                second_context,
                &policies,
                &[],
                2_000,
                &[0x72; 32],
            )
            .unwrap(),
            Admission::Accept
        );
        assert_eq!(ledger.reservation_revision("worker-01", 2_000).unwrap(), 1);

        // The next sample may advance to revision 1, but a later sample may
        // not move its signed watermark back to revision 0.
        let fresh_challenge = fresh_test_challenge();
        let (mut fresh, mut fresh_policy, fresh_device_key, fresh_admin_key) =
            signed_evidence(fresh_challenge, 3_000);
        fresh.claims.sample_generation = 3;
        fresh.claims.reservation_revision = 1;
        fresh.signature = fresh_device_key
            .sign(&worker_telemetry_bytes(&fresh.claims))
            .to_bytes();
        fresh_policy.claims.reservation_revision = 1;
        fresh_policy.signature = fresh_admin_key
            .sign(&scheduling_policy_bytes(&fresh_policy.claims))
            .to_bytes();
        assert!(verify_and_consume_scheduling_context(
            &ledger,
            &d,
            &w,
            &fresh,
            &fresh_policy,
            &device_keys,
            &admin_keys,
            &fresh_challenge,
            4_000,
        )
        .is_ok());

        let rollback_challenge = fresh_test_challenge();
        let (mut rollback, rollback_policy, rollback_key, _) =
            signed_evidence(rollback_challenge, 4_000);
        rollback.claims.sample_generation = 4;
        rollback.claims.reservation_revision = 0;
        rollback.signature = rollback_key
            .sign(&worker_telemetry_bytes(&rollback.claims))
            .to_bytes();
        assert_eq!(
            verify_and_consume_scheduling_context(
                &ledger,
                &d,
                &w,
                &rollback,
                &rollback_policy,
                &device_keys,
                &admin_keys,
                &rollback_challenge,
                5_000,
            ),
            Err(SchedulingEvidenceError::InvalidReservationWatermark)
        );

        drop(ledger);
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(lock_path));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn fresh_sample_watermark_does_not_double_count_existing_cpu_or_memory_leases() {
        let policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];

        // CPU: the second sample reports 3,000 free milli-cores after the
        // first 3,000-millicore lease. The lease is already reflected at revision 1.
        let cpu_path =
            std::env::temp_dir().join(format!("ujani-watermark-cpu-{}.ledger", std::process::id()));
        let cpu_ledger = DurableLedger::open_with_integrity_keys(
            &cpu_path,
            "test-key",
            vec![LedgerIntegrityKey::new("test-key", [0x7B; 32])],
        )
        .unwrap();
        let d = device();
        let cpu_first = workload_with_resources("cpu-first", 3_000, 1_024);
        let cpu_second = workload_with_resources("cpu-second", 1_000, 1_024);
        let first_context = verified_context_for_durable(
            &cpu_ledger,
            &cpu_first,
            [0x71; 16],
            1_000,
            6_000,
            20_000,
            0,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &cpu_ledger,
                &d,
                &cpu_first,
                first_context,
                &policies,
                &[],
                2_000,
                &[0x71; 32],
            )
            .unwrap(),
            Admission::Accept
        );
        assert_eq!(
            cpu_ledger.reservation_revision("worker-01", 2_000).unwrap(),
            1
        );
        let second_context = verified_context_for_durable(
            &cpu_ledger,
            &cpu_second,
            [0x72; 16],
            3_000,
            5_000,
            20_000,
            1,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &cpu_ledger,
                &d,
                &cpu_second,
                second_context,
                &policies,
                &[],
                4_000,
                &[0x72; 32],
            )
            .unwrap(),
            Admission::Accept
        );
        assert_eq!(cpu_ledger.snapshot().unwrap().reserved_cpu_millis, 4_000);
        drop(cpu_ledger);
        let mut cpu_lock = cpu_path.as_os_str().to_os_string();
        cpu_lock.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(cpu_lock));
        let _ = std::fs::remove_file(cpu_path);

        // Memory: the OS reports 5,904 MB of free headroom after the first
        // 7,000 MB lease. The revision watermark prevents counting that lease twice.
        let memory_path = std::env::temp_dir().join(format!(
            "ujani-watermark-memory-{}.ledger",
            std::process::id()
        ));
        let memory_ledger = DurableLedger::open_with_integrity_keys(
            &memory_path,
            "test-key",
            vec![LedgerIntegrityKey::new("test-key", [0x7C; 32])],
        )
        .unwrap();
        let memory_first = workload_with_resources("memory-first", 1_000, 7_000);
        let memory_second = workload_with_resources("memory-second", 1_000, 1_000);
        let first_context = verified_context_for_durable(
            &memory_ledger,
            &memory_first,
            [0x73; 16],
            1_000,
            6_000,
            20_000,
            0,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &memory_ledger,
                &d,
                &memory_first,
                first_context,
                &policies,
                &[],
                2_000,
                &[0x73; 32],
            )
            .unwrap(),
            Admission::Accept
        );
        let second_context = verified_context_for_durable(
            &memory_ledger,
            &memory_second,
            [0x74; 16],
            3_000,
            6_000,
            10_000,
            1,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &memory_ledger,
                &d,
                &memory_second,
                second_context,
                &policies,
                &[],
                4_000,
                &[0x74; 32],
            )
            .unwrap(),
            Admission::Accept
        );
        assert_eq!(memory_ledger.snapshot().unwrap().reserved_memory_mb, 8_000);
        drop(memory_ledger);
        let mut memory_lock = memory_path.as_os_str().to_os_string();
        memory_lock.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(memory_lock));
        let _ = std::fs::remove_file(memory_path);
    }

    #[test]
    fn resource_capacity_claims_are_bound_to_the_worker_signature() {
        let d = device();
        let w = workload();
        let challenge = [0x41u8; 16];
        let (mut telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        telemetry.claims.available_cpu_millis = 3_000;
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            ),
            Err(SchedulingEvidenceError::InvalidWorkerSignature)
        );

        // The monotonic generation is part of the signed payload, not caller metadata.
        telemetry.claims.available_cpu_millis = 6_000;
        telemetry.claims.sample_generation = 2;
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            ),
            Err(SchedulingEvidenceError::InvalidWorkerSignature)
        );

        // Even a correctly signed zero generation is invalid.
        telemetry.claims.sample_generation = 0;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            ),
            Err(SchedulingEvidenceError::InvalidTimeWindow)
        );
    }

    #[test]
    fn signed_worker_capacity_and_isolation_gate_admission() {
        let d = device();
        let w = workload();
        let challenge = [0x42u8; 16];
        let (mut telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        telemetry.claims.available_cpu_millis = 2_999;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        let verified = verify_scheduling_context(
            &d,
            &w,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            2_000,
        )
        .unwrap();
        assert_eq!(
            admit_with_verified_context(&d, &w, &verified, &[], &[], 2_000),
            Admission::Reject(RejectReason::CpuBudget)
        );

        let challenge = [0x44u8; 16];
        let (mut telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        telemetry.claims.available_memory_mb = 5_000;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        let verified = verify_scheduling_context(
            &d,
            &w,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            2_000,
        )
        .unwrap();
        assert_eq!(
            admit_with_verified_context(&d, &w, &verified, &[], &[], 2_000),
            Admission::Reject(RejectReason::MemoryBudget)
        );

        let challenge = [0x43u8; 16];
        let (mut telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        telemetry.claims.os_isolation_ready = false;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        let verified = verify_scheduling_context(
            &d,
            &w,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            2_000,
        )
        .unwrap();
        assert_eq!(
            admit_with_verified_context(&d, &w, &verified, &[], &[], 2_000),
            Admission::Reject(RejectReason::WorkerIsolationUnavailable)
        );
    }

    fn verified_context_without_isolation(
        workload: &Workload,
        challenge: [u8; 16],
        now: u64,
    ) -> VerifiedSchedulingContext {
        let (mut telemetry, mut policy, device_key, admin_key) = signed_evidence(challenge, now);
        telemetry.claims.sample_generation = next_test_generation();
        telemetry.claims.os_isolation_ready = false;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        policy.claims.workload_id = workload.workload_id.clone();
        policy.claims.manifest_sha256 = workload.manifest_sha256;
        policy.claims.challenge_nonce = challenge;
        policy.signature = admin_key
            .sign(&scheduling_policy_bytes(&policy.claims))
            .to_bytes();
        verify_scheduling_context(
            &device(),
            workload,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            now + 1_000,
        )
        .unwrap()
    }

    fn verified_context_without_isolation_durable(
        ledger: &DurableLedger,
        workload: &Workload,
        challenge: [u8; 16],
        now: u64,
    ) -> VerifiedSchedulingContext {
        let (mut telemetry, mut policy, device_key, admin_key) = signed_evidence(challenge, now);
        telemetry.claims.sample_generation = next_test_generation();
        telemetry.claims.os_isolation_ready = false;
        telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&telemetry.claims))
            .to_bytes();
        policy.claims.workload_id = workload.workload_id.clone();
        policy.claims.manifest_sha256 = workload.manifest_sha256;
        policy.claims.challenge_nonce = challenge;
        policy.signature = admin_key
            .sign(&scheduling_policy_bytes(&policy.claims))
            .to_bytes();
        verify_and_consume_scheduling_context(
            ledger,
            &device(),
            workload,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            now + 1_000,
        )
        .unwrap()
    }

    #[test]
    fn capacity_rejection_is_enforced_by_both_verified_reservation_wrappers() {
        let d = device();
        let w = workload();

        // 2,999 available CPU minus the 2,000 system reserve leaves 999,
        // one millicore below this workload's 1,000-millicore request.
        let mut memory_ledger = Ledger::default();
        let cpu_challenge = fresh_test_challenge();
        let cpu_token = fresh_test_lease_token();
        let memory_context = verified_context_for(&w, cpu_challenge, 1_000, 2_999);
        assert_eq!(
            admit_and_reserve_with_verified_lease(
                &mut memory_ledger,
                &d,
                &w,
                memory_context,
                &[],
                &[],
                2_000,
                &cpu_token,
            ),
            Admission::Reject(RejectReason::CpuBudget)
        );
        assert!(memory_ledger.jobs.is_empty());

        let isolation_challenge = fresh_test_challenge();
        let isolation_token = fresh_test_lease_token();
        let isolation_context =
            verified_context_without_isolation(&w, isolation_challenge, 1_000);
        assert_eq!(
            admit_and_reserve_with_verified_lease(
                &mut memory_ledger,
                &d,
                &w,
                isolation_context,
                &[],
                &[],
                2_000,
                &isolation_token,
            ),
            Admission::Reject(RejectReason::WorkerIsolationUnavailable)
        );
        assert!(memory_ledger.jobs.is_empty());

        let path = std::env::temp_dir().join(format!(
            "ujani-wrapper-capacity-reject-{}.ledger",
            std::process::id()
        ));
        let durable = DurableLedger::open_with_integrity_keys(
            &path,
            "test-key",
            vec![LedgerIntegrityKey::new("test-key", [0x72; 32])],
        )
        .unwrap();
        let durable_cpu_challenge = fresh_test_challenge();
        let durable_cpu_token = fresh_test_lease_token();
        let durable_context = verified_context_for_durable(
            &durable,
            &w,
            durable_cpu_challenge,
            1_000,
            2_999,
            20_000,
            0,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &durable,
                &d,
                &w,
                durable_context,
                &[],
                &[],
                2_000,
                &durable_cpu_token,
            )
            .unwrap(),
            Admission::Reject(RejectReason::CpuBudget)
        );
        assert_eq!(durable.snapshot().unwrap().active_jobs, 0);

        let durable_isolation_challenge = fresh_test_challenge();
        let durable_isolation_token = fresh_test_lease_token();
        let isolation_context = verified_context_without_isolation_durable(
            &durable,
            &w,
            durable_isolation_challenge,
            1_000,
        );
        assert_eq!(
            admit_and_reserve_durably_with_verified_lease(
                &durable,
                &d,
                &w,
                isolation_context,
                &[],
                &[],
                2_000,
                &durable_isolation_token,
            )
            .unwrap(),
            Admission::Reject(RejectReason::WorkerIsolationUnavailable)
        );
        assert_eq!(durable.snapshot().unwrap().active_jobs, 0);
        drop(durable);
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(lock_path));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn accepts_fresh_dual_signed_challenge_bound_context() {
        let d = device();
        let w = workload();
        let challenge = [9u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        let verified = verify_scheduling_context(
            &d,
            &w,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            2_000,
        )
        .unwrap();
        assert!(verified.context.owner_opted_in);
        assert!(verified.context.within_admin_schedule);
        assert!(verified.context.network_policy_allows);
        assert!(verified.context.data_classification_allows);
        assert!(verified.context.telemetry_fresh);
    }

    #[test]
    fn verified_context_is_bound_to_device_manifest_and_expiry() {
        let d = device();
        let w = workload();
        let challenge = [0x31u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        let verified = verify_scheduling_context(
            &d,
            &w,
            &telemetry,
            &policy,
            &[("worker-01".into(), device_key.verifying_key())],
            &[("admin-key-01".into(), admin_key.verifying_key())],
            &challenge,
            2_000,
        )
        .unwrap();

        let mut other_device = device();
        other_device.device_id = "worker-02".into();
        assert_eq!(
            admit_with_verified_context(&other_device, &w, &verified, &[], &[], 2_000),
            Admission::Reject(RejectReason::SchedulingEvidenceMismatch)
        );

        let mut other_workload = workload();
        other_workload.workload_id = "job-02".into();
        assert_eq!(
            admit_with_verified_context(&d, &other_workload, &verified, &[], &[], 2_000),
            Admission::Reject(RejectReason::SchedulingEvidenceMismatch)
        );

        let mut changed_manifest = workload();
        changed_manifest.manifest_sha256[0] ^= 1;
        assert_eq!(
            admit_with_verified_context(&d, &changed_manifest, &verified, &[], &[], 2_000),
            Admission::Reject(RejectReason::SchedulingEvidenceMismatch)
        );

        assert_eq!(
            admit_with_verified_context(&d, &w, &verified, &[], &[], 31_000),
            Admission::Reject(RejectReason::SchedulingEvidenceExpired)
        );
    }

    #[test]
    fn durable_reservation_rejects_workload_substitution() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let path = std::env::temp_dir().join(format!(
            "ujani-scheduling-binding-{}-{}.ledger",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ledger = DurableLedger::open_with_integrity_keys(
            &path,
            "test-v1",
            vec![crate::LedgerIntegrityKey::new("test-v1", [0xA5; 32])],
        )
        .unwrap();
        let d = device();
        let w = workload();
        let challenge = [0x32u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        let keys = [("worker-01".into(), device_key.verifying_key())];
        let admins = [("admin-key-01".into(), admin_key.verifying_key())];
        let verified = verify_and_consume_scheduling_context(
            &ledger, &d, &w, &telemetry, &policy, &keys, &admins, &challenge, 2_000,
        )
        .unwrap();

        let mut substituted = workload();
        substituted.workload_id = "job-substituted".into();
        let result = admit_and_reserve_durably_with_verified_lease(
            &ledger,
            &d,
            &substituted,
            verified,
            &[],
            &[],
            2_000,
            &[0x41u8; 32],
        )
        .unwrap();
        assert_eq!(
            result,
            Admission::Reject(RejectReason::SchedulingEvidenceMismatch)
        );
        assert_eq!(ledger.snapshot().unwrap().active_jobs, 0);

        drop(ledger);
        let lock_path = {
            let mut value = path.as_os_str().to_os_string();
            value.push(".lock");
            std::path::PathBuf::from(value)
        };
        let _ = std::fs::remove_file(lock_path);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_wrong_challenge_and_tampered_worker_telemetry() {
        let d = device();
        let w = workload();
        let challenge = [9u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &[8u8; 16],
                2_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::ChallengeMismatch
        );
        let mut tampered = telemetry;
        tampered.claims.on_ac_power = false;
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &tampered,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::InvalidWorkerSignature
        );
    }

    #[test]
    fn rejects_stale_evidence_and_manifest_substitution() {
        let d = device();
        let w = workload();
        let challenge = [9u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                40_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::InvalidTimeWindow
        );
        let mut changed = workload();
        changed.workload_id = "job-02".into();
        assert_eq!(
            verify_scheduling_context(
                &d,
                &changed,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::WorkloadMismatch
        );
    }

    #[test]
    fn dispatch_challenge_is_consumed_durably_and_cannot_be_replayed() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let path = std::env::temp_dir().join(format!(
            "ujani-scheduling-challenge-{}-{}.ledger",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ledger = DurableLedger::open_with_integrity_keys(
            &path,
            "test-v1",
            vec![crate::LedgerIntegrityKey::new("test-v1", [0xA5; 32])],
        )
        .unwrap();
        let d = device();
        let w = workload();
        let challenge = [0x77u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);
        let keys = [("worker-01".into(), device_key.verifying_key())];
        let admins = [("admin-key-01".into(), admin_key.verifying_key())];
        assert!(verify_and_consume_scheduling_context(
            &ledger, &d, &w, &telemetry, &policy, &keys, &admins, &challenge, 2_000
        )
        .is_ok());
        assert_eq!(
            verify_and_consume_scheduling_context(
                &ledger, &d, &w, &telemetry, &policy, &keys, &admins, &challenge, 2_001
            )
            .unwrap_err(),
            SchedulingEvidenceError::ChallengeReplayed
        );
        drop(ledger);
        let lock_path = {
            let mut value = path.as_os_str().to_os_string();
            value.push(".lock");
            std::path::PathBuf::from(value)
        };
        let _ = std::fs::remove_file(lock_path);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_tampered_admin_policy_and_unenrolled_keys() {
        let d = device();
        let w = workload();
        let challenge = [9u8; 16];
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, 1_000);

        let mut tampered_policy = policy.clone();
        tampered_policy.claims.network_policy_allows = false;
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &tampered_policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::InvalidPolicySignature
        );
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[],
                &[("admin-key-01".into(), admin_key.verifying_key())],
                &challenge,
                2_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::UnknownDeviceKey
        );
        assert_eq!(
            verify_scheduling_context(
                &d,
                &w,
                &telemetry,
                &policy,
                &[("worker-01".into(), device_key.verifying_key())],
                &[],
                &challenge,
                2_000,
            )
            .unwrap_err(),
            SchedulingEvidenceError::UnknownAdminKey
        );
    }
}
