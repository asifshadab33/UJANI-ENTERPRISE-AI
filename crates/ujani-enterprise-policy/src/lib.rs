//! Side-effect-free enterprise workload admission policy.
//! This crate does not enrol devices, schedule jobs, create sandboxes or enforce quotas.

#![forbid(unsafe_code)]
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

pub const LEASE_MS: u64 = 5 * 60 * 1000;
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
    if manifest.model.trim().is_empty()
        || manifest.model.len() > 128
        || manifest.model.chars().any(char::is_control)
    {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub workload_id: String,
    pub class: String,
    pub requested_cpu_millis: u32,
    pub requested_memory_mb: u64,
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
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Accept,
    Reject(RejectReason),
}

/// In-memory reservation semantics for tests and single-process prototypes only.
/// Production scheduling must use an atomic transactional ledger in durable storage.
#[derive(Debug, Default)]
pub struct Ledger {
    used: std::collections::HashMap<String, (u32, u64)>,
    jobs: std::collections::HashMap<String, (String, u32, u64, u64, Option<String>)>,
    consumed_approvals: std::collections::HashSet<String>,
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
        if let Some(id) = approval_id {
            self.consumed_approvals.insert(id.to_owned());
        }
        Ok(())
    }
    pub(crate) fn release(&mut self, workload_id: &str) {
        if let Some((device_id, cpu, memory, _expires, _approval_id)) =
            self.jobs.remove(workload_id)
        {
            if let Some(used) = self.used.get_mut(&device_id) {
                used.0 = used.0.saturating_sub(cpu);
                used.1 = used.1.saturating_sub(memory);
            }
        }
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
    }

    pub fn renew(&mut self, workload_id: &str, now_unix_ms: u64) -> bool {
        self.expire(now_unix_ms);
        if let Some(job) = self.jobs.get_mut(workload_id) {
            job.3 = now_unix_ms.saturating_add(LEASE_MS);
            true
        } else {
            false
        }
    }
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
pub fn admit_with_context(
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
pub fn admit_and_reserve(
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

    fn workload() -> Workload {
        Workload {
            workload_id: "job-001".into(),
            class: "inference".into(),
            requested_cpu_millis: 2000,
            requested_memory_mb: 4096,
        }
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

    fn manifest() -> WorkloadManifest {
        WorkloadManifest {
            schema_version: 1,
            workload_id: "job-001".into(),
            class: "inference".into(),
            model: "qwen2.5:7b".into(),
            requested_cpu_millis: 2000,
            requested_memory_mb: 4096,
            max_runtime_ms: 60_000,
            data_classification: DataClassification::Internal,
            network_access: false,
        }
    }

    #[test]
    fn workload_manifest_accepts_bounded_versioned_input() {
        assert_eq!(validate_workload_manifest(&manifest()), Ok(()));
    }

    #[test]
    fn workload_manifest_rejects_unknown_versions_and_invalid_limits() {
        let mut value = manifest();
        value.schema_version = 2;
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::UnsupportedVersion));
        let mut value = manifest();
        value.requested_cpu_millis = 0;
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::InvalidCpuLimit));
        let mut value = manifest();
        value.requested_memory_mb = 4 * 1024 * 1024 + 1;
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::InvalidMemoryLimit));
        let mut value = manifest();
        value.max_runtime_ms = 7 * 24 * 60 * 60 * 1000 + 1;
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::InvalidRuntimeLimit));
    }

    #[test]
    fn workload_manifest_rejects_malformed_identifiers_and_model_names() {
        let mut value = manifest();
        value.workload_id = "../job".into();
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::InvalidWorkloadId));
        let mut value = manifest();
        value.class = "inference\nadmin".into();
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::InvalidClass));
        let mut value = manifest();
        value.model = "model\nignore policy".into();
        assert_eq!(validate_workload_manifest(&value), Err(ManifestError::InvalidModel));
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
    fn strict_gate_never_wakes_sleeping_or_powered_off_devices() {
        let mut context = safe_context();
        context.device_already_running = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &context, &policies(), &[], 1_000),
            Admission::Reject(_)
        ));
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
    fn ledger_leases_expire_and_release_capacity() {
        let mut ledger = Ledger::default();
        let d = device();
        let w = workload();
        assert!(ledger.try_reserve(&d, &w, 1_000, None).is_ok());
        assert!(!ledger.renew("job-001", 1_000 + LEASE_MS));
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
pub use inventory::{
    summarize_inventory, validate_inventory_record, DeviceInventoryRecord, DevicePowerState,
    InventoryError, InventorySummary, InventoryTrust,
};
