//! Dry-run fleet capacity summary built on the existing fail-closed placement planner.
//!
//! This module aggregates only candidates accepted by the existing admission policy.
//! Aggregate capacity is useful for estimating parallel independent work; it must
//! never be presented as memory or CPU that one workload can consume across devices.
//! The summary does not collect telemetry, reserve capacity, create leases or dispatch work.

use std::collections::BTreeMap;

use crate::{
    plan_local_first_placement, ClassPolicy, Device, ManifestError, PlacementCandidate,
    VerifiedAdminApproval, WorkloadManifest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapacity {
    pub device_id: String,
    pub remaining_cpu_millis: u32,
    pub remaining_memory_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetCapacitySummary {
    /// Number of unique candidate device IDs supplied by the trusted caller, regardless of eligibility.
    pub candidate_device_count: usize,
    /// Devices accepted by the existing workload-specific placement policy.
    pub eligible_device_count: usize,
    /// Rejection records returned by the planner (includes duplicate candidate IDs).
    pub rejected_candidate_count: usize,
    /// Sum of caller-reported remaining capacity across eligible devices; valid for parallel independent work only when inputs already deduct OS reserves and active leases.
    pub aggregate_eligible_cpu_millis: u64,
    /// Sum of caller-reported remaining memory across eligible devices; not a shared memory pool and must already deduct OS reserves and active leases.
    pub aggregate_eligible_memory_mb: u64,
    /// Capacity of the planner's selected device for this exact manifest.
    pub selected_device_capacity: Option<DeviceCapacity>,
    /// The planner is advisory: this summary never starts work or reserves resources.
    pub execution_started: bool,
    pub resources_reserved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetCapacityError {
    Manifest(ManifestError),
    ArithmeticOverflow,
}

/// Summarise capacity using the same policy checks as workload placement.
///
/// The caller must supply fresh, authenticated candidates whose remaining capacities already deduct OS reserves and active durable leases, plus verified approvals. This summary does not reconcile the ledger.
/// The aggregate totals describe separate eligible machines and must not be used
/// to claim that one model can fit across several machines. A single workload's
/// usable capacity is represented only by selected_device_capacity.
pub fn summarize_fleet_capacity(
    manifest: &WorkloadManifest,
    candidates: &[PlacementCandidate],
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
) -> Result<FleetCapacitySummary, FleetCapacityError> {
    let plan = plan_local_first_placement(
        manifest,
        candidates,
        policies,
        approvals,
        now_unix_ms,
    )
    .map_err(FleetCapacityError::Manifest)?;

    // Match the planner's first-candidate-wins duplicate-ID behaviour.
    let mut unique_devices = BTreeMap::<String, Device>::new();
    for candidate in candidates {
        unique_devices
            .entry(candidate.device.device_id.clone())
            .or_insert_with(|| candidate.device.clone());
    }

    let mut aggregate_cpu = 0_u64;
    let mut aggregate_memory = 0_u64;
    for device_id in &plan.eligible_device_ids {
        let device = unique_devices
            .get(device_id)
            .ok_or(FleetCapacityError::ArithmeticOverflow)?;
        aggregate_cpu = aggregate_cpu
            .checked_add(u64::from(device.remaining_cpu_millis))
            .ok_or(FleetCapacityError::ArithmeticOverflow)?;
        aggregate_memory = aggregate_memory
            .checked_add(device.remaining_memory_mb)
            .ok_or(FleetCapacityError::ArithmeticOverflow)?;
    }

    let selected_device_capacity = plan.selected_device_id.as_ref().and_then(|id| {
        unique_devices.get(id).map(|device| DeviceCapacity {
            device_id: id.clone(),
            remaining_cpu_millis: device.remaining_cpu_millis,
            remaining_memory_mb: device.remaining_memory_mb,
        })
    });

    Ok(FleetCapacitySummary {
        candidate_device_count: unique_devices.len(),
        eligible_device_count: plan.eligible_device_ids.len(),
        rejected_candidate_count: plan.rejected.len(),
        aggregate_eligible_cpu_millis: aggregate_cpu,
        aggregate_eligible_memory_mb: aggregate_memory,
        selected_device_capacity,
        execution_started: false,
        resources_reserved: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataClassification, SchedulingContext};

    fn manifest() -> WorkloadManifest {
        WorkloadManifest {
            schema_version: 1,
            workload_id: "fleet-summary-job".into(),
            class: "interactive-low-priority".into(),
            model: "llama3.2".into(),
            requested_cpu_millis: 500,
            requested_memory_mb: 1024,
            max_runtime_ms: 60_000,
            data_classification: DataClassification::Internal,
            network_access: false,
        }
    }

    fn candidate(id: &str, cpu: u32, memory: u64, available: bool) -> PlacementCandidate {
        PlacementCandidate {
            device: Device {
                device_id: id.into(),
                enrolled: true,
                admin_approved: true,
                available,
                allowed_workload_classes: vec!["interactive-low-priority".into()],
                remaining_cpu_millis: cpu,
                remaining_memory_mb: memory,
            },
            context: SchedulingContext {
                owner_opted_in: true,
                within_admin_schedule: true,
                interactive_user_present: false,
                on_ac_power: true,
                device_already_running: true,
                thermal_state_safe: true,
                network_policy_allows: true,
                data_classification_allows: true,
                telemetry_fresh: true,
            },
        }
    }

    fn policies() -> Vec<ClassPolicy> {
        vec![ClassPolicy {
            class: "interactive-low-priority".into(),
            requires_admin_approval: false,
            max_cpu_millis: 2_000,
            max_memory_mb: 8_192,
        }]
    }

    #[test]
    fn reports_registered_eligible_and_busy_devices_separately() {
        let summary = summarize_fleet_capacity(
            &manifest(),
            &[
                candidate("worker-a", 2_000, 4_096, true),
                candidate("worker-b", 1_000, 2_048, true),
                candidate("busy", 8_000, 16_384, false),
            ],
            &policies(),
            &[],
            10_000,
        )
        .unwrap();

        assert_eq!(summary.candidate_device_count, 3);
        assert_eq!(summary.eligible_device_count, 2);
        assert_eq!(summary.rejected_candidate_count, 1);
        assert_eq!(summary.aggregate_eligible_cpu_millis, 3_000);
        assert_eq!(summary.aggregate_eligible_memory_mb, 6_144);
        assert_eq!(
            summary.selected_device_capacity,
            Some(DeviceCapacity {
                device_id: "worker-b".into(),
                remaining_cpu_millis: 1_000,
                remaining_memory_mb: 2_048,
            })
        );
        assert!(!summary.execution_started);
        assert!(!summary.resources_reserved);
    }

    #[test]
    fn aggregate_memory_is_separate_from_single_worker_capacity() {
        let summary = summarize_fleet_capacity(
            &manifest(),
            &[
                candidate("a", 2_000, 2_048, true),
                candidate("b", 2_000, 2_048, true),
            ],
            &policies(),
            &[],
            10_000,
        )
        .unwrap();

        assert_eq!(summary.aggregate_eligible_memory_mb, 4_096);
        assert_eq!(
            summary.selected_device_capacity.unwrap().remaining_memory_mb,
            2_048
        );
    }

    #[test]
    fn duplicate_ids_are_counted_once_and_reported_as_rejected_candidates() {
        let summary = summarize_fleet_capacity(
            &manifest(),
            &[
                candidate("same", 2_000, 4_096, true),
                candidate("same", 8_000, 16_384, true),
            ],
            &policies(),
            &[],
            10_000,
        )
        .unwrap();

        assert_eq!(summary.candidate_device_count, 1);
        assert_eq!(summary.eligible_device_count, 1);
        assert_eq!(summary.rejected_candidate_count, 1);
        assert_eq!(summary.aggregate_eligible_memory_mb, 4_096);
    }

    #[test]
    fn empty_fleet_has_zero_capacity_and_no_selected_worker() {
        let summary =
            summarize_fleet_capacity(&manifest(), &[], &policies(), &[], 10_000).unwrap();
        assert_eq!(summary.candidate_device_count, 0);
        assert_eq!(summary.eligible_device_count, 0);
        assert_eq!(summary.aggregate_eligible_cpu_millis, 0);
        assert_eq!(summary.aggregate_eligible_memory_mb, 0);
        assert!(summary.selected_device_capacity.is_none());
    }
}
