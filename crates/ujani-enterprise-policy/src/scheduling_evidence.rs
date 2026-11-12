//! Signed, challenge-bound scheduling evidence.
//!
//! Worker telemetry is signed by the enrolled worker device. Scheduling,
//! network-egress and data-classification decisions are signed by an enrolled
//! administrator key and bound to the exact workload manifest. Callers cannot
//! construct a VerifiedSchedulingContext directly.
use crate::cpu_capacity::{
    evaluate_cpu_placement, CpuPlacementRejection, CpuPlacementRequest, CpuWorkerSnapshot,
};
use crate::device_trust::durable::DurableDeviceRegistry;
use crate::device_trust::{AuthenticatedDeviceRequest, SignedDeviceRequest};
use crate::{
    admit_with_context, Admission, ClassPolicy, Device, DurableLedger, DurableLedgerError,
    RejectReason, SchedulingContext, TelemetryChallengeError, VerifiedAdminApproval, Workload,
};
use ed25519_dalek::{Signature, VerifyingKey};

const TELEMETRY_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-WORKER-TELEMETRY-V1\0";
const POLICY_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SCHEDULING-POLICY-V1\0";
const CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;
pub const MAX_WORKER_TELEMETRY_TTL_MS: u64 = 30_000;
pub const MAX_SCHEDULING_POLICY_TTL_MS: u64 = 5 * 60 * 1000;

/// Server-selected route binding for the worker telemetry admission endpoint.
pub const WORKER_TELEMETRY_REQUEST_METHOD: &str = "POST";
pub const WORKER_TELEMETRY_REQUEST_RESOURCE: &str = "worker-telemetry:admission";

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
pub(crate) struct VerifiedSchedulingContext {
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

/// Return the exact versioned canonical body bytes signed by worker telemetry
/// and by the outer device request. HTTP adapters must pass these same bytes to
/// the authentication boundary rather than reserializing the claims as JSON.
pub fn canonical_worker_telemetry_body(claims: &WorkerTelemetryClaims) -> Vec<u8> {
    worker_telemetry_bytes(claims)
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

/// Test-only legacy helper for exercising the isolated challenge-consumption path.
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Keep both trust roots and the per-dispatch challenge explicit.
pub(crate) fn verify_and_consume_scheduling_context(
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

/// Fail-closed errors from the transport-independent authenticated telemetry
/// admission boundary. Authentication details are deliberately not exposed to
/// an untrusted caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedTelemetryAdmissionError {
    DeviceAuthenticationFailed,
    RequestBodyMismatch,
    RequestBindingMismatch,
    SchedulingEvidence(SchedulingEvidenceError),
    ReservationStoreUnavailable,
    ReservationOutcomeUnknown,
}

/// Authenticate a worker request against the durable enrollment registry, verify
/// the exact canonical telemetry body and administrator-signed policy, consume
/// the monotonic telemetry challenge, and run the dual-consent/resource admission
/// plus durable reservation.
///
/// expected_tenant_id, device, and workload must be loaded by the hosting service
/// from the same tenant-scoped repository. The tenant is compared with the identity
/// derived from the enrolled device key, never trusted from the body.
///
/// This is a service-core boundary, not an HTTP listener. Registry replay state
/// and the reservation ledger are separate stores, so this function does not
/// claim cross-store atomicity or production dispatch safety. Keep dispatch
/// disabled until those records share one authoritative transaction and the
/// isolation/result-verification lifecycle is independently proven.
#[allow(clippy::too_many_arguments)] // Keep identity, policy, and resource inputs explicit at the trust boundary.
pub fn authenticate_verify_and_reserve_worker_telemetry(
    registry: &DurableDeviceRegistry,
    ledger: &DurableLedger,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    expected_tenant_id: &str,
    device: &Device,
    workload: &Workload,
    telemetry: &SignedWorkerTelemetry,
    policy: &SignedSchedulingPolicy,
    enrolled_admin_keys: &[(String, VerifyingKey)],
    expected_challenge_nonce: &[u8; 16],
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
    lease_token: &[u8; 32],
) -> Result<(AuthenticatedDeviceRequest, Admission), AuthenticatedTelemetryAdmissionError> {
    if telemetry.claims.device_id.len() > 128
        || raw_body.len() > crate::device_trust::MAX_DEVICE_REQUEST_BODY_BYTES
    {
        return Err(AuthenticatedTelemetryAdmissionError::RequestBodyMismatch);
    }
    let canonical_body = canonical_worker_telemetry_body(&telemetry.claims);
    if raw_body != canonical_body.as_slice() {
        return Err(AuthenticatedTelemetryAdmissionError::RequestBodyMismatch);
    }

    // Reject obvious caller/record mismatches before consuming the durable
    // request nonce. These untrusted claims are only a prefilter; the same
    // bindings are checked again against the authenticated principal below.
    if signed_request.claims.tenant_id != expected_tenant_id
        || signed_request.claims.device_id != device.device_id
        || signed_request.claims.workload_id != workload.workload_id
        || signed_request.claims.manifest_sha256 != workload.manifest_sha256
    {
        return Err(AuthenticatedTelemetryAdmissionError::RequestBindingMismatch);
    }

    let authenticated: AuthenticatedDeviceRequest = registry
        .authenticate_request_for(
            signed_request,
            WORKER_TELEMETRY_REQUEST_METHOD,
            WORKER_TELEMETRY_REQUEST_RESOURCE,
            raw_body,
            now_unix_ms,
        )
        .map_err(|_| AuthenticatedTelemetryAdmissionError::DeviceAuthenticationFailed)?;

    if expected_tenant_id != authenticated.tenant_id()
        || authenticated.device_id() != device.device_id.as_str()
        || telemetry.claims.device_id.as_str() != authenticated.device_id()
        || authenticated.workload_id() != workload.workload_id.as_str()
        || authenticated.manifest_sha256() != &workload.manifest_sha256
    {
        return Err(AuthenticatedTelemetryAdmissionError::RequestBindingMismatch);
    }

    // Hold the trust-registry lock from the authoritative consent/key-generation
    // recheck through the durable ledger commit. Every path that needs both locks
    // must acquire registry first, then ledger; the ledger callback must not re-enter
    // the registry. This closes the opt-out/key-rotation race at admission time.
    let admission = registry
        .with_authenticated_device_status_for_request(
            &authenticated,
            |device_key, owner_opted_in| {
                if !owner_opted_in {
                    return Ok(Admission::Reject(RejectReason::OwnerOptInMissing));
                }
                let enrolled_device_keys = [(
                    authenticated.device_id().to_owned(),
                    (*device_key).clone(),
                )];
                let verified = verify_scheduling_context(
                    device,
                    workload,
                    telemetry,
                    policy,
                    &enrolled_device_keys,
                    enrolled_admin_keys,
                    expected_challenge_nonce,
                    now_unix_ms,
                )
                .map_err(AuthenticatedTelemetryAdmissionError::SchedulingEvidence)?;
                let expires_unix_ms = verified.expires_at_unix_ms;

                // The challenge generation/watermark and any resulting lease
                // reservation now commit in one ledger transaction. A policy
                // rejection consumes the challenge; a storage error aborts both.
                let challenge_result = ledger
                    .consume_telemetry_challenge_and_then(
                        &telemetry.claims.device_id,
                        telemetry.claims.sample_generation,
                        telemetry.claims.reservation_revision,
                        *expected_challenge_nonce,
                        expires_unix_ms,
                        now_unix_ms,
                        |ledger_state| {
                            let mut verified = verified;
                            verified.challenge_consumed = true;
                            Ok(admit_and_reserve_with_verified_lease_in_transaction(
                                ledger_state,
                                device,
                                workload,
                                verified,
                                policies,
                                approvals,
                                now_unix_ms,
                                lease_token,
                            ))
                        },
                    )
                    .map_err(|error| match error {
                        DurableLedgerError::AnchorUnavailable(_) => {
                            AuthenticatedTelemetryAdmissionError::ReservationOutcomeUnknown
                        }
                        _ => AuthenticatedTelemetryAdmissionError::ReservationStoreUnavailable,
                    })?;

                match challenge_result {
                    Ok(admission) => Ok(admission),
                    Err(TelemetryChallengeError::Replayed) => Err(
                        AuthenticatedTelemetryAdmissionError::SchedulingEvidence(
                            SchedulingEvidenceError::ChallengeReplayed,
                        ),
                    ),
                    Err(TelemetryChallengeError::InvalidReservationWatermark) => Err(
                        AuthenticatedTelemetryAdmissionError::SchedulingEvidence(
                            SchedulingEvidenceError::InvalidReservationWatermark,
                        ),
                    ),
                }
            },
        )
        .map_err(|_| AuthenticatedTelemetryAdmissionError::DeviceAuthenticationFailed)??;

    Ok((authenticated, admission))
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
pub(crate) fn admit_with_verified_context(
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

/// Apply the verified policy and reservation mutation inside the caller's
/// already-open durable ledger transaction, after its challenge was consumed.
#[allow(clippy::too_many_arguments)] // Keep all policy, identity and capability inputs explicit.
fn admit_and_reserve_with_verified_lease_in_transaction(
    ledger: &mut crate::Ledger,
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
    if !context.challenge_consumed {
        return Admission::Reject(RejectReason::SchedulingEvidenceMismatch);
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

/// Test-only in-memory prototype; production callers must use the authenticated
/// durable admission boundary.
/// Test-only compatibility helper for the focused durable-admission unit tests.
/// Production authenticated admission uses the atomic challenge-and-reservation path above.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_and_reserve_durably_with_verified_lease(
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

#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Preserve explicit admission evidence and reservation inputs.
pub(crate) fn admit_and_reserve_with_verified_lease(
    ledger: &mut crate::Ledger,
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
    use crate::{
        workload_from_manifest, DataClassification, Ledger, LedgerIntegrityKey, WorkloadManifest,
    };
    use crate::device_trust::durable::{
        MonotonicSnapshotAnchor, SnapshotAnchorRecord,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{mpsc, Arc, Barrier, Mutex, OnceLock};
    use std::time::Duration;
    use std::thread;

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

    fn test_signing_keys() -> (SigningKey, SigningKey) {
        static KEYS: OnceLock<([u8; 32], [u8; 32])> = OnceLock::new();
        let (device_key, admin_key) =
            KEYS.get_or_init(|| (fresh_test_lease_token(), fresh_test_lease_token()));
        (
            SigningKey::from_bytes(device_key),
            SigningKey::from_bytes(admin_key),
        )
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
        let (device_key, admin_key) = test_signing_keys();
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
        let integrity_key = fresh_test_lease_token();
        let open = || {
            DurableLedger::open_with_integrity_keys(
                &path,
                "test-key",
                vec![LedgerIntegrityKey::new("test-key", integrity_key)],
            )
            .unwrap()
        };
        let device = device();
        let workload = workload();
        let device_keys = [(
            "worker-01".to_owned(),
            test_signing_keys().0.verifying_key(),
        )];
        let admin_keys = [(
            "admin-key-01".to_owned(),
            test_signing_keys().1.verifying_key(),
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
        let first_context =
            verified_context_for(&first_workload, fresh_test_challenge(), 1_000, 3_500);
        assert_eq!(
            admit_and_reserve_with_verified_lease(
                &mut memory_ledger,
                &d,
                &first_workload,
                first_context,
                &class_policies,
                &[],
                2_000,
                &fresh_test_lease_token(),
            ),
            Admission::Accept
        );
        let second_context =
            verified_context_for(&second_workload, fresh_test_challenge(), 1_000, 3_500);
        assert_eq!(
            admit_and_reserve_with_verified_lease(
                &mut memory_ledger,
                &d,
                &second_workload,
                second_context,
                &class_policies,
                &[],
                2_000,
                &fresh_test_lease_token(),
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
            vec![LedgerIntegrityKey::new(
                "test-key",
                fresh_test_lease_token(),
            )],
        )
        .unwrap();
        let first_context = verified_context_for_durable(
            &durable,
            &first_workload,
            fresh_test_challenge(),
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
                &fresh_test_lease_token(),
            )
            .unwrap(),
            Admission::Accept
        );
        let second_context = verified_context_for_durable(
            &durable,
            &second_workload,
            fresh_test_challenge(),
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
                &fresh_test_lease_token(),
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
            vec![LedgerIntegrityKey::new(
                "test-key",
                fresh_test_lease_token(),
            )],
        )
        .unwrap();
        let d = device();
        let w = workload();
        let device_keys = [(
            "worker-01".to_owned(),
            test_signing_keys().0.verifying_key(),
        )];
        let admin_keys = [(
            "admin-key-01".to_owned(),
            test_signing_keys().1.verifying_key(),
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
                &fresh_test_lease_token(),
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
                &fresh_test_lease_token(),
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
            vec![LedgerIntegrityKey::new(
                "test-key",
                fresh_test_lease_token(),
            )],
        )
        .unwrap();
        let d = device();
        let cpu_first = workload_with_resources("cpu-first", 3_000, 1_024);
        let cpu_second = workload_with_resources("cpu-second", 1_000, 1_024);
        let first_context = verified_context_for_durable(
            &cpu_ledger,
            &cpu_first,
            fresh_test_challenge(),
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
                &fresh_test_lease_token(),
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
            fresh_test_challenge(),
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
                &fresh_test_lease_token(),
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
            vec![LedgerIntegrityKey::new(
                "test-key",
                fresh_test_lease_token(),
            )],
        )
        .unwrap();
        let memory_first = workload_with_resources("memory-first", 1_000, 7_000);
        let memory_second = workload_with_resources("memory-second", 1_000, 1_000);
        let first_context = verified_context_for_durable(
            &memory_ledger,
            &memory_first,
            fresh_test_challenge(),
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
                &fresh_test_lease_token(),
            )
            .unwrap(),
            Admission::Accept
        );
        let second_context = verified_context_for_durable(
            &memory_ledger,
            &memory_second,
            fresh_test_challenge(),
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
                &fresh_test_lease_token(),
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
        let challenge = fresh_test_challenge();
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
        let challenge = fresh_test_challenge();
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

        let challenge = fresh_test_challenge();
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

        let challenge = fresh_test_challenge();
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
        let isolation_context = verified_context_without_isolation(&w, isolation_challenge, 1_000);
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
            vec![LedgerIntegrityKey::new(
                "test-key",
                fresh_test_lease_token(),
            )],
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
        let challenge = fresh_test_challenge();
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
            vec![crate::LedgerIntegrityKey::new(
                "test-v1",
                fresh_test_lease_token(),
            )],
        )
        .unwrap();
        let d = device();
        let w = workload();
        let challenge = fresh_test_challenge();
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
            &fresh_test_lease_token(),
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
            vec![crate::LedgerIntegrityKey::new(
                "test-v1",
                fresh_test_lease_token(),
            )],
        )
        .unwrap();
        let d = device();
        let w = workload();
        let challenge = fresh_test_challenge();
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

    fn unique_authenticated_test_path(label: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "ujani-authenticated-telemetry-{label}-{}-{}.db",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ))
    }

    fn remove_authenticated_test_files(path: &std::path::Path) {
        for suffix in ["", ".lock", ".bak", ".tmp", ".anchor-restore.tmp"] {
            let mut value = path.as_os_str().to_os_string();
            value.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(value));
        }
    }

    fn open_authenticated_test_registry(
        path: &std::path::Path,
        admin_key: &SigningKey,
        device_key: &SigningKey,
        now: u64,
    ) -> DurableDeviceRegistry {
        use crate::device_trust::durable::DeviceTrustIntegrityKey;
        use crate::device_trust::{
            DeviceCommandAction, SignedDeviceAdminCommand, SignedOwnerConsentCommand,
        };

        let registry = DurableDeviceRegistry::open(
            path,
            vec![("admin-key-01".into(), admin_key.verifying_key())],
            DeviceTrustIntegrityKey::new("test-registry-key", fresh_test_lease_token()),
        )
        .unwrap();
        let mut command = SignedDeviceAdminCommand {
            action: DeviceCommandAction::Enroll,
            tenant_id: "tenant-a".into(),
            device_id: "worker-01".into(),
            admin_key_id: "admin-key-01".into(),
            target_key_id: "worker-key-01".into(),
            target_public_key: Some(device_key.verifying_key().to_bytes()),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + crate::device_trust::MAX_ADMIN_COMMAND_TTL_MS,
            nonce: fresh_test_challenge(),
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        command.new_device_signature = Some(
            device_key
                .sign(&crate::device_trust::enrollment_proof_bytes(&command))
                .to_bytes(),
        );
        command.signature = admin_key
            .sign(&crate::device_trust::admin_command_bytes(&command))
            .to_bytes();
        registry.apply_admin_command(&command, now + 1).unwrap();
        let mut consent = SignedOwnerConsentCommand {
            tenant_id: "tenant-a".into(),
            device_id: "worker-01".into(),
            key_id: "worker-key-01".into(),
            key_generation: 1,
            revision: 1,
            opted_in: true,
            issued_at_unix_ms: now + 1,
            expires_at_unix_ms: now + crate::device_trust::MAX_OWNER_CONSENT_TTL_MS,
            nonce: fresh_test_challenge(),
            signature: [0; 64],
        };
        consent.signature = device_key
            .sign(&crate::device_trust::owner_consent_bytes(&consent))
            .to_bytes();
        registry.apply_owner_consent(&consent, now + 2).unwrap();
        registry
    }

    fn set_authenticated_test_owner_consent(
        registry: &DurableDeviceRegistry,
        device_key: &SigningKey,
        opted_in: bool,
        revision: u64,
        now: u64,
    ) {
        use crate::device_trust::SignedOwnerConsentCommand;
        let mut consent = SignedOwnerConsentCommand {
            tenant_id: "tenant-a".into(),
            device_id: "worker-01".into(),
            key_id: "worker-key-01".into(),
            key_generation: 1,
            revision,
            opted_in,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + crate::device_trust::MAX_OWNER_CONSENT_TTL_MS,
            nonce: fresh_test_challenge(),
            signature: [0; 64],
        };
        consent.signature = device_key
            .sign(&crate::device_trust::owner_consent_bytes(&consent))
            .to_bytes();
        registry.apply_owner_consent(&consent, now + 1).unwrap();
    }

    fn signed_telemetry_request(
        device_key: &SigningKey,
        workload: &Workload,
        telemetry: &SignedWorkerTelemetry,
        now: u64,
    ) -> (SignedDeviceRequest, Vec<u8>) {
        use crate::device_trust::{DeviceRequestClaims, SignedDeviceRequest};
        use sha2::Digest;

        let body = worker_telemetry_bytes(&telemetry.claims);
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: telemetry.claims.device_id.clone(),
            key_id: "worker-key-01".into(),
            key_generation: 1,
            request_id: fresh_test_challenge(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + crate::device_trust::MAX_DEVICE_REQUEST_TTL_MS,
            method: WORKER_TELEMETRY_REQUEST_METHOD.into(),
            resource_id: WORKER_TELEMETRY_REQUEST_RESOURCE.into(),
            workload_id: workload.workload_id.clone(),
            manifest_sha256: workload.manifest_sha256,
            body_sha256: sha2::Sha256::digest(&body).into(),
        };
        let signed = SignedDeviceRequest {
            signature: device_key
                .sign(&crate::device_trust::device_request_bytes(&claims))
                .to_bytes(),
            claims,
        };
        (signed, body)
    }

    fn open_authenticated_test_ledger(path: &std::path::Path) -> DurableLedger {
        DurableLedger::open_with_integrity_keys(
            path,
            "telemetry-ledger-test",
            vec![LedgerIntegrityKey::new(
                "telemetry-ledger-test",
                fresh_test_lease_token(),
            )],
        )
        .unwrap()
    }

    fn open_authenticated_test_ledger_with_anchor(
        path: &std::path::Path,
        anchor: Arc<dyn MonotonicSnapshotAnchor>,
    ) -> DurableLedger {
        DurableLedger::open_with_anchor(
            path,
            "telemetry-ledger-test-anchor",
            "telemetry-ledger-test",
            vec![LedgerIntegrityKey::new(
                "telemetry-ledger-test",
                fresh_test_lease_token(),
            )],
            anchor,
        )
        .unwrap()
    }

    fn unique_authenticated_test_directory(label: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "ujani-authenticated-telemetry-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    struct BlockingAnchor {
        record: Mutex<Option<SnapshotAnchorRecord>>,
        block_next_load: AtomicBool,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl BlockingAnchor {
        fn new() -> Self {
            Self {
                record: Mutex::new(None),
                block_next_load: AtomicBool::new(false),
                entered: Arc::new(Barrier::new(2)),
                release: Arc::new(Barrier::new(2)),
            }
        }

        fn arm(&self) {
            self.block_next_load.store(true, Ordering::SeqCst);
        }
    }

    impl MonotonicSnapshotAnchor for BlockingAnchor {
        fn load(&self, _registry_id: &str) -> Result<Option<SnapshotAnchorRecord>, String> {
            if self.block_next_load.swap(false, Ordering::SeqCst) {
                self.entered.wait();
                self.release.wait();
            }
            self.record
                .lock()
                .map(|record| record.clone())
                .map_err(|_| "test anchor mutex poisoned".to_owned())
        }

        fn compare_and_set(
            &self,
            _registry_id: &str,
            expected_generation: Option<u64>,
            next: SnapshotAnchorRecord,
        ) -> Result<bool, String> {
            let mut record = self
                .record
                .lock()
                .map_err(|_| "test anchor mutex poisoned".to_owned())?;
            let matches = match (expected_generation, record.as_ref()) {
                (None, None) => next.generation() == 1,
                (Some(expected), Some(current)) => {
                    current.generation() == expected
                        && next.generation() == expected.saturating_add(1)
                }
                _ => false,
            };
            if !matches {
                return Ok(false);
            }
            *record = Some(next);
            Ok(true)
        }
    }

    #[test]
    fn authenticated_telemetry_uses_durable_device_identity_and_rejects_replay() {
        let registry_path = unique_authenticated_test_path("registry");
        let ledger_path = unique_authenticated_test_path("ledger");
        let now = 20_000;
        let challenge = fresh_test_challenge();
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, now);
        let registry =
            open_authenticated_test_registry(&registry_path, &admin_key, &device_key, now);
        let ledger = open_authenticated_test_ledger(&ledger_path);
        let device = device();
        let workload = workload();
        let (request, body) = signed_telemetry_request(&device_key, &workload, &telemetry, now);
        let admin_keys = [(
            policy.claims.policy_key_id.clone(),
            admin_key.verifying_key(),
        )];
        let policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];
        let lease_token = fresh_test_lease_token();

        let mut mismatched_body = body.clone();
        mismatched_body.push(0);
        assert_eq!(
            authenticate_verify_and_reserve_worker_telemetry(
                &registry,
                &ledger,
                &request,
                &mismatched_body,
                "tenant-a",
                &device,
                &workload,
                &telemetry,
                &policy,
                &admin_keys,
                &challenge,
                &policies,
                &[],
                now + 2,
                &lease_token,
            ),
            Err(AuthenticatedTelemetryAdmissionError::RequestBodyMismatch)
        );

        let (authenticated, admission) = authenticate_verify_and_reserve_worker_telemetry(
            &registry,
            &ledger,
            &request,
            &body,
            "tenant-a",
            &device,
            &workload,
            &telemetry,
            &policy,
            &admin_keys,
            &challenge,
            &policies,
            &[],
            now + 2,
            &lease_token,
        )
        .unwrap();
        assert_eq!(admission, Admission::Accept);
        assert_eq!(authenticated.tenant_id(), "tenant-a");
        assert_eq!(authenticated.device_id(), "worker-01");
        assert_eq!(authenticated.key_id(), "worker-key-01");
        assert_eq!(authenticated.key_generation(), 1);
        assert_eq!(authenticated.workload_id(), "job-01");
        assert_eq!(
            authenticate_verify_and_reserve_worker_telemetry(
                &registry,
                &ledger,
                &request,
                &body,
                "tenant-a",
                &device,
                &workload,
                &telemetry,
                &policy,
                &admin_keys,
                &challenge,
                &policies,
                &[],
                now + 3,
                &lease_token,
            ),
            Err(AuthenticatedTelemetryAdmissionError::DeviceAuthenticationFailed)
        );

        drop(registry);
        drop(ledger);
        remove_authenticated_test_files(&registry_path);
        remove_authenticated_test_files(&ledger_path);
    }

    #[test]
    fn authenticated_telemetry_rejects_persisted_owner_opt_out_even_if_sample_is_stale() {
        let registry_path = unique_authenticated_test_path("owner-opt-out-registry");
        let ledger_path = unique_authenticated_test_path("owner-opt-out-ledger");
        let now = 40_000;
        let challenge = fresh_test_challenge();
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, now);
        let registry =
            open_authenticated_test_registry(&registry_path, &admin_key, &device_key, now);
        let ledger = open_authenticated_test_ledger(&ledger_path);
        let device = device();
        let workload = workload();
        let (request, body) = signed_telemetry_request(&device_key, &workload, &telemetry, now);
        let admin_keys = [(
            policy.claims.policy_key_id.clone(),
            admin_key.verifying_key(),
        )];
        let policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];

        set_authenticated_test_owner_consent(&registry, &device_key, false, 2, now + 10);
        assert_eq!(
            authenticate_verify_and_reserve_worker_telemetry(
                &registry,
                &ledger,
                &request,
                &body,
                "tenant-a",
                &device,
                &workload,
                &telemetry,
                &policy,
                &admin_keys,
                &challenge,
                &policies,
                &[],
                now + 20,
                &fresh_test_lease_token(),
            )
            .map(|(_, admission)| admission),
            Ok(Admission::Reject(RejectReason::OwnerOptInMissing))
        );

        drop(registry);
        drop(ledger);
        remove_authenticated_test_files(&registry_path);
        remove_authenticated_test_files(&ledger_path);
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_admission_serializes_owner_opt_out_with_lease_commit() {
        let registry_path = unique_authenticated_test_path("consent-race-registry");
        let ledger_directory = unique_authenticated_test_directory("consent-race-ledger");
        let ledger_path = ledger_directory.join("ledger.db");
        let now = 50_000;
        let challenge = fresh_test_challenge();
        let (telemetry, policy, device_key, admin_key) = signed_evidence(challenge, now);
        let registry =
            open_authenticated_test_registry(&registry_path, &admin_key, &device_key, now);
        let anchor = Arc::new(BlockingAnchor::new());
        let ledger = open_authenticated_test_ledger_with_anchor(&ledger_path, anchor.clone());
        let device = device();
        let workload = workload();
        let (request, body) = signed_telemetry_request(&device_key, &workload, &telemetry, now);
        let admin_keys = [(
            policy.claims.policy_key_id.clone(),
            admin_key.verifying_key(),
        )];
        let policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];
        let lease_token = fresh_test_lease_token();

        // Pause the next ledger transaction after it has entered the provider.
        // The admission service must already hold the device-trust lock here.
        anchor.arm();
        let admission_registry = registry.clone();
        let admission_ledger = ledger.clone();
        let admission = thread::spawn(move || {
            authenticate_verify_and_reserve_worker_telemetry(
                &admission_registry,
                &admission_ledger,
                &request,
                &body,
                "tenant-a",
                &device,
                &workload,
                &telemetry,
                &policy,
                &admin_keys,
                &challenge,
                &policies,
                &[],
                now + 2,
                &lease_token,
            )
        });
        anchor.entered.wait();

        let opt_out_registry = registry.clone();
        let opt_out_device_key = device_key.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let opt_out = thread::spawn(move || {
            started_tx.send(()).unwrap();
            set_authenticated_test_owner_consent(
                &opt_out_registry,
                &opt_out_device_key,
                false,
                2,
                now + 10,
            );
            finished_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            finished_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "owner opt-out must wait until the in-flight admission releases the trust lock"
        );

        anchor.release.wait();
        let (_, admission) = admission.join().unwrap().unwrap();
        assert_eq!(admission, Admission::Accept);
        finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        opt_out.join().unwrap();

        assert!(!registry.tenant_device_summaries("tenant-a").unwrap()[0].owner_opted_in);
        let snapshot = ledger.snapshot().unwrap();
        assert_eq!(snapshot.active_jobs, 1);
        assert_eq!(snapshot.reserved_cpu_millis, 1_000);
        assert_eq!(snapshot.reserved_memory_mb, 1_024);

        drop(registry);
        drop(ledger);
        remove_authenticated_test_files(&registry_path);
        std::fs::remove_dir_all(ledger_directory).unwrap();
    }

    #[test]
    fn authenticated_telemetry_requires_both_owner_and_organisation_consent() {
        let registry_path = unique_authenticated_test_path("consent-registry");
        let ledger_path = unique_authenticated_test_path("consent-ledger");
        let now = 30_000;
        let first_challenge = fresh_test_challenge();
        let (mut first_telemetry, first_policy, device_key, admin_key) =
            signed_evidence(first_challenge, now);
        first_telemetry.claims.owner_opted_in = false;
        first_telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&first_telemetry.claims))
            .to_bytes();

        let registry =
            open_authenticated_test_registry(&registry_path, &admin_key, &device_key, now);
        let ledger = open_authenticated_test_ledger(&ledger_path);
        let device = device();
        let workload = workload();
        let admin_keys = [(
            first_policy.claims.policy_key_id.clone(),
            admin_key.verifying_key(),
        )];
        let policies = [ClassPolicy {
            class: "inference".into(),
            requires_admin_approval: false,
            max_cpu_millis: 4_000,
            max_memory_mb: 8_192,
        }];
        let lease_token = fresh_test_lease_token();
        let (first_request, first_body) =
            signed_telemetry_request(&device_key, &workload, &first_telemetry, now);

        assert_eq!(
            authenticate_verify_and_reserve_worker_telemetry(
                &registry,
                &ledger,
                &first_request,
                &first_body,
                "tenant-a",
                &device,
                &workload,
                &first_telemetry,
                &first_policy,
                &admin_keys,
                &first_challenge,
                &policies,
                &[],
                now + 2,
                &lease_token,
            )
            .map(|(_, admission)| admission),
            Ok(Admission::Reject(RejectReason::OwnerOptInMissing))
        );

        let second_challenge = fresh_test_challenge();
        let (mut second_telemetry, mut second_policy, _, _) =
            signed_evidence(second_challenge, now + 10);
        second_telemetry.claims.sample_generation = 2;
        second_telemetry.signature = device_key
            .sign(&worker_telemetry_bytes(&second_telemetry.claims))
            .to_bytes();
        second_policy.claims.within_admin_schedule = false;
        second_policy.signature = admin_key
            .sign(&scheduling_policy_bytes(&second_policy.claims))
            .to_bytes();
        let (second_request, second_body) =
            signed_telemetry_request(&device_key, &workload, &second_telemetry, now + 10);

        assert_eq!(
            authenticate_verify_and_reserve_worker_telemetry(
                &registry,
                &ledger,
                &second_request,
                &second_body,
                "tenant-a",
                &device,
                &workload,
                &second_telemetry,
                &second_policy,
                &admin_keys,
                &second_challenge,
                &policies,
                &[],
                now + 12,
                &lease_token,
            )
            .map(|(_, admission)| admission),
            Ok(Admission::Reject(RejectReason::OutsideAdminSchedule))
        );

        drop(registry);
        drop(ledger);
        remove_authenticated_test_files(&registry_path);
        remove_authenticated_test_files(&ledger_path);
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
