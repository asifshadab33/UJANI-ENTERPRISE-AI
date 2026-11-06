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
    pub requires_admin_approval: bool,
    pub admin_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Accept,
    Reject(&'static str),
}

/// Conservative pre-scheduling check. Real enforcement must occur on the worker OS.
fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

pub fn admit(device: &Device, workload: &Workload) -> Admission {
    if !valid_identifier(&device.device_id, 128)
        || !valid_identifier(&workload.workload_id, 128)
        || !valid_identifier(&workload.class, 64)
    {
        return Admission::Reject(
            "device ID, workload ID, and workload class must be valid bounded identifiers",
        );
    }
    if workload.requested_cpu_millis == 0 || workload.requested_memory_mb == 0 {
        return Admission::Reject("workload must request a positive CPU and memory budget");
    }
    if !device.enrolled || !device.admin_approved {
        return Admission::Reject("device is not explicitly enrolled and approved");
    }
    if !device.available {
        return Admission::Reject("device is not currently available");
    }
    if !device
        .allowed_workload_classes
        .iter()
        .any(|c| c == &workload.class)
    {
        return Admission::Reject("workload class is not allowed on this device");
    }
    if workload.requires_admin_approval && !workload.admin_approved {
        return Admission::Reject("workload requires administrator approval");
    }
    if workload.requested_cpu_millis > device.remaining_cpu_millis {
        return Admission::Reject("CPU budget would be exceeded");
    }
    if workload.requested_memory_mb > device.remaining_memory_mb {
        return Admission::Reject("memory budget would be exceeded");
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
) -> Admission {
    match admit(device, workload) {
        Admission::Accept => {}
        rejection => return rejection,
    }
    if !context.telemetry_fresh {
        return Admission::Reject("worker telemetry is missing or stale");
    }
    if !context.owner_opted_in {
        return Admission::Reject("device owner has not explicitly opted in");
    }
    if !context.within_admin_schedule {
        return Admission::Reject("outside administrator-approved scheduling window");
    }
    if context.interactive_user_present {
        return Admission::Reject("interactive user activity takes priority");
    }
    if !context.device_already_running {
        return Admission::Reject("device is sleeping or powered off; UJANI never wakes devices");
    }
    if context.device_on_battery {
        return Admission::Reject("device is on battery power");
    }
    if !context.thermal_state_safe {
        return Admission::Reject("device thermal state is not safe for background work");
    }
    if !context.network_policy_allows {
        return Admission::Reject("network or data-egress policy blocks this workload");
    }
    if !context.data_classification_allows {
        return Admission::Reject("workload data classification is not approved for this worker");
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
            requires_admin_approval: false,
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

    #[test]
    fn strict_gate_accepts_only_when_all_scheduling_conditions_are_safe() {
        assert_eq!(
            admit_with_context(&device(), &workload(), &safe_context()),
            Admission::Accept
        );
    }

    #[test]
    fn strict_gate_rejects_missing_opt_in_or_outside_schedule() {
        let mut c = safe_context();
        c.owner_opted_in = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.within_admin_schedule = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_prioritizes_interactive_use_and_power_safety() {
        let mut c = safe_context();
        c.interactive_user_present = true;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.device_on_battery = true;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.thermal_state_safe = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_never_wakes_sleeping_or_powered_off_devices() {
        let mut context = safe_context();
        context.device_already_running = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &context),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn strict_gate_rejects_stale_telemetry_and_data_policy_violations() {
        let mut c = safe_context();
        c.telemetry_fresh = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.network_policy_allows = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
        let mut c = safe_context();
        c.data_classification_allows = false;
        assert!(matches!(
            admit_with_context(&device(), &workload(), &c),
            Admission::Reject(_)
        ));
    }

    #[test]
    fn approved_available_device_accepts_within_budget() {
        assert_eq!(admit(&device(), &workload()), Admission::Accept);
    }

    #[test]
    fn unapproved_device_is_rejected() {
        let mut d = device();
        d.admin_approved = false;
        assert!(matches!(admit(&d, &workload()), Admission::Reject(_)));
    }

    #[test]
    fn unavailable_device_is_rejected() {
        let mut d = device();
        d.available = false;
        assert!(matches!(admit(&d, &workload()), Admission::Reject(_)));
    }

    #[test]
    fn disallowed_class_is_rejected() {
        let mut w = workload();
        w.class = "arbitrary-shell".into();
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));
    }

    #[test]
    fn quota_overrun_is_rejected() {
        let mut w = workload();
        w.requested_memory_mb = 9000;
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));
    }

    #[test]
    fn rejects_empty_or_malformed_identifiers_and_classes() {
        let mut d = device();
        d.device_id = "   ".into();
        assert!(matches!(admit(&d, &workload()), Admission::Reject(_)));

        let mut w = workload();
        w.workload_id = "job/../../escape".into();
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));

        let mut w = workload();
        w.class = "inference\\nadmin".into();
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));
    }

    #[test]
    fn rejects_zero_resource_requests() {
        let mut w = workload();
        w.requested_cpu_millis = 0;
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));

        let mut w = workload();
        w.requested_memory_mb = 0;
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));
    }

    #[test]
    fn approval_gate_is_enforced() {
        let mut w = workload();
        w.requires_admin_approval = true;
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));
    }
}

pub mod inventory;
pub use inventory::{summarize_inventory, validate_inventory_record, DeviceInventoryRecord, DevicePowerState, InventoryError, InventorySummary, InventoryTrust};
