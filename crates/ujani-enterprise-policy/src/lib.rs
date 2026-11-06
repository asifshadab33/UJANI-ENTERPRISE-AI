//! Side-effect-free enterprise workload admission policy.
//! This crate does not enrol devices, schedule jobs, create sandboxes or enforce quotas.

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub workload_id: String,
    pub class: String,
    pub requested_cpu_millis: u32,
    pub requested_memory_mb: u64,
    pub admin_approved: bool,
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
    jobs: std::collections::HashMap<String, (String, u32, u64)>,
}

impl Ledger {
    pub fn try_reserve(
        &mut self,
        device: &Device,
        workload: &Workload,
    ) -> Result<(), RejectReason> {
        if self.jobs.contains_key(&workload.workload_id) {
            return Err(RejectReason::DuplicateWorkload);
        }
        let (cpu, memory) = self.used.get(&device.device_id).copied().unwrap_or((0, 0));
        if cpu.saturating_add(workload.requested_cpu_millis) > device.remaining_cpu_millis {
            return Err(RejectReason::CpuBudget);
        }
        if memory.saturating_add(workload.requested_memory_mb) > device.remaining_memory_mb {
            return Err(RejectReason::MemoryBudget);
        }
        self.used.insert(
            device.device_id.clone(),
            (
                cpu + workload.requested_cpu_millis,
                memory + workload.requested_memory_mb,
            ),
        );
        self.jobs.insert(
            workload.workload_id.clone(),
            (
                device.device_id.clone(),
                workload.requested_cpu_millis,
                workload.requested_memory_mb,
            ),
        );
        Ok(())
    }
    pub fn release(&mut self, workload_id: &str) {
        if let Some((device_id, cpu, memory)) = self.jobs.remove(workload_id) {
            if let Some(used) = self.used.get_mut(&device_id) {
                used.0 = used.0.saturating_sub(cpu);
                used.1 = used.1.saturating_sub(memory);
            }
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

pub fn admit(
    device: &Device,
    workload: &Workload,
    policies: &[ClassPolicy],
    verified_admin_approvals: &[String],
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
    let Some(policy) = policies.iter().find(|p| p.class == workload.class) else {
        return Admission::Reject(UnknownClassPolicy);
    };
    if policy.requires_admin_approval
        && !verified_admin_approvals
            .iter()
            .any(|id| id == &workload.workload_id)
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
    pub device_on_battery: bool,
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
    verified_admin_approvals: &[String],
) -> Admission {
    match admit(device, workload, policies, verified_admin_approvals) {
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
    if context.device_on_battery {
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

#[cfg(test)]
mod tests {
    use super::*;

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
            admin_approved: false,
        }
    }

    fn safe_context() -> SchedulingContext {
        SchedulingContext {
            owner_opted_in: true,
            within_admin_schedule: true,
            interactive_user_present: false,
            device_on_battery: false,
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
    fn strict_gate_accepts_only_when_all_scheduling_conditions_are_safe() {
        assert_eq!(
            admit_with_context(&device(), &workload(), &safe_context(), &policies(), &[]),
            Admission::Accept
        );
    }

    #[test]
    fn strict_gate_rejects_missing_opt_in_or_outside_schedule() {
        let mut c = safe_context();
        c.owner_opted_in = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.within_admin_schedule = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_prioritizes_interactive_use_and_power_safety() {
        let mut c = safe_context();
        c.interactive_user_present = true;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.device_on_battery = true;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.thermal_state_safe = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_never_wakes_sleeping_or_powered_off_devices() {
        let mut context = safe_context();
        context.device_already_running = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &context, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_rejects_stale_telemetry_and_data_policy_violations() {
        let mut c = safe_context();
        c.telemetry_fresh = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.network_policy_allows = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.data_classification_allows = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn approved_available_device_accepts_within_budget() {
        assert_eq!(
            admit(&device(), &workload(), &policies(), &[]),
            Admission::Accept
        );
    }

    #[test]
    fn unapproved_device_is_rejected() {
        let mut d = device();
        d.admin_approved = false;
        assert!(matches!(
            admit(&d, &workload(), &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn unavailable_device_is_rejected() {
        let mut d = device();
        d.available = false;
        assert!(matches!(
            admit(&d, &workload(), &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn disallowed_class_is_rejected() {
        let mut w = workload();
        w.class = "arbitrary-shell".into();
        assert!(matches!(
            admit(&device(), &w, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn quota_overrun_is_rejected() {
        let mut w = workload();
        w.requested_memory_mb = 9000;
        assert!(matches!(
            admit(&device(), &w, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn rejects_empty_or_malformed_identifiers_and_classes() {
        let mut d = device();
        d.device_id = "   ".into();
        assert!(matches!(
            admit(&d, &workload(), &policies(), &[]),
            Admission::Reject(_)
        ));

        let mut w = workload();
        w.workload_id = "job/../../escape".into();
        assert!(matches!(
            admit(&device(), &w, &policies(), &[]),
            Admission::Reject(_)
        ));

        let mut w = workload();
        w.class = "inference\\nadmin".into();
        assert!(matches!(
            admit(&device(), &w, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn rejects_zero_resource_requests() {
        let mut w = workload();
        w.requested_cpu_millis = 0;
        assert!(matches!(
            admit(&device(), &w, &policies(), &[]),
            Admission::Reject(_)
        ));

        let mut w = workload();
        w.requested_memory_mb = 0;
        assert!(matches!(
            admit(&device(), &w, &policies(), &[]),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn submitter_claim_cannot_waive_admin_class_approval() {
        let w = workload();
        let policy = ClassPolicy { class: "inference".into(), requires_admin_approval: true, max_cpu_millis: 4000, max_memory_mb: 8192 };
        assert_eq!(admit(&device(), &w, &[policy], &[]), Admission::Reject(RejectReason::ApprovalRequired));
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
                &["job-001".into()]
            ),
            Admission::Accept
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
        assert!(ledger.try_reserve(&d, &first).is_ok());
        assert!(ledger.try_reserve(&d, &second).is_ok());
        assert_eq!(ledger.try_reserve(&d, &third), Err(RejectReason::CpuBudget));
        ledger.release("job-001");
        assert!(ledger.try_reserve(&d, &third).is_ok());
    }

    #[test]
    fn approval_gate_is_enforced() {
        let w = workload();
        let policy = ClassPolicy { class: "inference".into(), requires_admin_approval: true, max_cpu_millis: 4000, max_memory_mb: 8192 };
        assert_eq!(admit(&device(), &w, &[policy], &[]), Admission::Reject(RejectReason::ApprovalRequired));
    }
}

pub mod inventory;
pub use inventory::{
    summarize_inventory, validate_inventory_record, DeviceInventoryRecord, DevicePowerState,
    InventoryError, InventorySummary, InventoryTrust,
};
