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
pub fn admit(device: &Device, workload: &Workload) -> Admission {
    if device.device_id.trim().is_empty() || workload.workload_id.trim().is_empty() {
        return Admission::Reject("device and workload identifiers must be present");
    }
    if !device.enrolled || !device.admin_approved {
        return Admission::Reject("device is not explicitly enrolled and approved");
    }
    if !device.available {
        return Admission::Reject("device is not currently available");
    }
    if !device.allowed_workload_classes.iter().any(|c| c == &workload.class) {
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
    fn approval_gate_is_enforced() {
        let mut w = workload();
        w.requires_admin_approval = true;
        assert!(matches!(admit(&device(), &w), Admission::Reject(_)));
    }
}
