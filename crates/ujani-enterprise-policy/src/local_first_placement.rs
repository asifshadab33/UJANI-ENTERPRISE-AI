//! Dry-run local-first placement across organisation-owned candidate devices.
//!
//! This planner evaluates existing fail-closed admission policy only. It does not
//! reserve resources, create leases, dispatch work or execute a workload.
use crate::{
    admit_with_context, validate_workload_manifest, Admission, ClassPolicy, Device, ManifestError,
    SchedulingContext, VerifiedAdminApproval, WorkloadManifest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementCandidate {
    pub device: Device,
    pub context: SchedulingContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRejection {
    pub device_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFirstPlacementPlan {
    /// Best-fit eligible organisation-owned device. This is advisory, not a lease.
    pub selected_device_id: Option<String>,
    pub eligible_device_ids: Vec<String>,
    pub rejected: Vec<CandidateRejection>,
    pub execution_started: bool,
    pub resources_reserved: bool,
}

/// Evaluate trusted organisation-owned candidates and choose a deterministic best fit.
///
/// Candidates must already be backed by authenticated inventory/evidence from the caller.
pub fn plan_local_first_placement(
    manifest: &WorkloadManifest,
    candidates: &[PlacementCandidate],
    policies: &[ClassPolicy],
    approvals: &[VerifiedAdminApproval],
    now_unix_ms: u64,
) -> Result<LocalFirstPlacementPlan, ManifestError> {
    validate_workload_manifest(manifest)?;
    let workload = crate::workload_from_manifest(manifest)?;
    let mut eligible: Vec<(u32, u64, String)> = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for candidate in candidates {
        let id = candidate.device.device_id.clone();
        if !seen.insert(id.clone()) {
            rejected.push(CandidateRejection {
                device_id: id,
                reason: "duplicate device candidate".into(),
            });
            continue;
        }

        match admit_with_context(
            &candidate.device,
            &workload,
            &candidate.context,
            policies,
            approvals,
            now_unix_ms,
        ) {
            Admission::Accept => {
                // Best-fit packing: prefer the smallest remaining CPU capacity that
                // still satisfies the request, then memory slack, then stable ID.
                let cpu_slack = candidate
                    .device
                    .remaining_cpu_millis
                    .saturating_sub(workload.requested_cpu_millis);
                let memory_slack = candidate
                    .device
                    .remaining_memory_mb
                    .saturating_sub(workload.requested_memory_mb);
                eligible.push((cpu_slack, memory_slack, id));
            }
            Admission::Reject(reason) => rejected.push(CandidateRejection {
                device_id: id,
                reason: reason.as_str().into(),
            }),
        }
    }

    eligible.sort();
    let eligible_device_ids = eligible
        .iter()
        .map(|(_, _, id)| id.clone())
        .collect::<Vec<_>>();
    let selected_device_id = eligible_device_ids.first().cloned();

    Ok(LocalFirstPlacementPlan {
        selected_device_id,
        eligible_device_ids,
        rejected,
        execution_started: false,
        resources_reserved: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataClassification, RejectReason};

    fn manifest() -> WorkloadManifest {
        WorkloadManifest {
            schema_version: 1,
            workload_id: "job-1".into(),
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
            max_cpu_millis: 2000,
            max_memory_mb: 8192,
        }]
    }

    #[test]
    fn selects_best_fit_from_eligible_internal_devices_without_reserving() {
        let plan = plan_local_first_placement(
            &manifest(),
            &[
                candidate("roomy", 4000, 8192, true),
                candidate("best-fit", 700, 2048, true),
            ],
            &policies(),
            &[],
            10_000,
        )
        .unwrap();

        assert_eq!(plan.selected_device_id.as_deref(), Some("best-fit"));
        assert_eq!(
            plan.eligible_device_ids,
            vec!["best-fit".to_string(), "roomy".to_string()]
        );
        assert!(!plan.execution_started);
        assert!(!plan.resources_reserved);
    }

    #[test]
    fn rejects_devices_without_owner_consent_or_fresh_telemetry() {
        let mut no_consent = candidate("no-consent", 2000, 4096, true);
        no_consent.context.owner_opted_in = false;
        let mut stale = candidate("stale", 2000, 4096, true);
        stale.context.telemetry_fresh = false;

        let plan =
            plan_local_first_placement(&manifest(), &[no_consent, stale], &policies(), &[], 10_000)
                .unwrap();

        assert!(plan.selected_device_id.is_none());
        assert_eq!(plan.rejected.len(), 2);
        assert!(plan
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::OwnerOptInMissing.as_str()));
        assert!(plan
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::TelemetryStale.as_str()));
    }

    #[test]
    fn rejects_duplicate_candidate_ids_and_unavailable_devices() {
        let plan = plan_local_first_placement(
            &manifest(),
            &[
                candidate("same", 2000, 4096, true),
                candidate("same", 2000, 4096, true),
                candidate("offline", 2000, 4096, false),
            ],
            &policies(),
            &[],
            10_000,
        )
        .unwrap();

        assert_eq!(plan.eligible_device_ids, vec!["same".to_string()]);
        assert!(plan
            .rejected
            .iter()
            .any(|r| r.reason == "duplicate device candidate"));
        assert!(plan
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::DeviceUnavailable.as_str()));
    }
}
