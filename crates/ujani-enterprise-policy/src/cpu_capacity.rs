//! CPU-only worker capacity admission for the Enterprise scheduler.
//!
//! This is deterministic policy logic, not a telemetry collector, scheduler,
//! sandbox or runtime quota enforcer. A trusted host must supply fresh,
//! authenticated measurements and the worker must re-check limits at launch.
#![forbid(unsafe_code)]

use crate::Workload;

/// Maximum accepted clock skew for a worker telemetry sample, in milliseconds.
pub const MAX_TELEMETRY_FUTURE_SKEW_MS: u64 = 30_000;

/// Authenticated resource and consent snapshot supplied by an enrolled worker.
///
/// CPU quantities use milli-cores (1,000 = one core of schedulable quota).
/// Memory quantities use MiB. `available_*` fields describe currently free
/// resources before the UJANI system reserve is deducted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuWorkerSnapshot {
    /// Unix timestamp in milliseconds when this snapshot was collected.
    pub sampled_at_unix_ms: u64,
    /// Effective CPU quota visible to this worker, in milli-cores.
    /// Use cgroup/job-object limits, not only host logical-core count.
    pub effective_cpu_capacity_millis: u32,
    /// CPU headroom currently free, in milli-cores, before system reserve.
    pub available_cpu_millis: u32,
    /// Configurable capacity reserved for OS/network and non-UJANI services.
    /// CPU headroom, in milli-cores, that UJANI must leave to the OS/services.
    pub system_reserved_cpu_millis: u32,
    /// Total memory visible to the worker, in MiB.
    pub total_memory_mb: u64,
    /// Memory currently free, in MiB, before system reserve.
    pub available_memory_mb: u64,
    /// Memory, in MiB, that UJANI must leave to the OS/services.
    pub system_reserved_memory_mb: u64,
    /// UJANI must never wake a sleeping or powered-off device for a job.
    /// Whether the device is already powered on; UJANI never wakes it.
    pub powered_on: bool,
    /// Whether the device owner explicitly opted into this workload class/window.
    pub owner_opted_in: bool,
    /// Whether interactive user activity is currently detected.
    pub interactive_user_present: bool,
    /// Whether the owner has paused or opted out of workload participation.
    pub user_paused: bool,
    /// Whether the worker is connected to AC power.
    pub on_ac_power: bool,
    /// Whether the trusted thermal monitor reports a safe operating state.
    pub thermal_state_safe: bool,
    /// Whether this snapshot is authenticated and bound to the enrolled device.
    pub telemetry_authenticated: bool,
    /// Whether required OS-level workload isolation is available.
    pub os_isolation_ready: bool,
}

/// CPU and memory resources requested by one workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuPlacementRequest {
    /// Requested CPU quota in milli-cores (1,000 = one core).
    pub requested_cpu_millis: u32,
    /// Requested memory in MiB.
    pub requested_memory_mb: u64,
}

impl From<&Workload> for CpuPlacementRequest {
    fn from(workload: &Workload) -> Self {
        Self {
            requested_cpu_millis: workload.requested_cpu_millis,
            requested_memory_mb: workload.requested_memory_mb,
        }
    }
}

/// Successful, non-reserving estimate of the worker headroom after admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuPlacement {
    /// CPU quota admitted for the workload, in milli-cores.
    pub admitted_cpu_millis: u32,
    /// Memory admitted for the workload, in MiB.
    pub admitted_memory_mb: u64,
    /// Remaining CPU headroom after this request and system reserve, in milli-cores.
    pub remaining_cpu_headroom_millis: u32,
    /// Remaining memory headroom after this request and system reserve, in MiB.
    pub remaining_memory_headroom_mb: u64,
    pub telemetry_sampled_at_unix_ms: u64,
}

/// Fail-closed reason a worker snapshot or workload request was rejected.
///
/// Rejections are evaluated in declaration order: request/capacity validity,
/// telemetry time, device/owner state, safety and isolation, then CPU and memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPlacementRejection {
    /// Resource measurements are inconsistent or exceed physical/effective capacity.
    InvalidCapacity,
    /// Requested CPU or memory is zero.
    InvalidRequest,
    /// Telemetry timestamp is too far in the future.
    FutureTelemetry,
    /// Telemetry is older than the caller's freshness limit.
    StaleTelemetry,
    /// Device is not already powered on.
    DevicePoweredOff,
    /// Device owner has not opted in.
    OwnerOptOut,
    /// Interactive user activity takes priority over batch work.
    InteractiveUse,
    /// Device owner has paused workload participation.
    UserPaused,
    /// Worker is not connected to AC power.
    BatteryPower,
    /// Thermal state is not safe.
    ThermalUnsafe,
    /// Snapshot is not authenticated for the enrolled device.
    UnauthenticatedTelemetry,
    /// Required OS-level isolation is unavailable.
    IsolationUnavailable,
    /// Request would consume the protected CPU reserve or exceed free CPU.
    CpuHeadroomInsufficient,
    /// Request would consume the protected memory reserve or exceed free memory.
    MemoryHeadroomInsufficient,
}

/// Evaluate whether a CPU-only workload fits the reported worker.
///
/// The host supplies the maximum telemetry age as a policy input. This function
/// fails closed for stale/future or unauthenticated measurements. It does not
/// reserve capacity: acquire the durable lease before dispatch, then enforce
/// CPU/RAM limits using OS controls on the worker.
///
/// # Example
/// ```
/// # use ujani_enterprise_policy::cpu_capacity::{
/// #     evaluate_cpu_placement, CpuPlacementRequest, CpuWorkerSnapshot,
/// # };
/// # let snapshot = CpuWorkerSnapshot {
/// #     sampled_at_unix_ms: 10_000, effective_cpu_capacity_millis: 8_000,
/// #     available_cpu_millis: 6_000, system_reserved_cpu_millis: 2_000,
/// #     total_memory_mb: 32_768, available_memory_mb: 20_000,
/// #     system_reserved_memory_mb: 4_096, powered_on: true,
/// #     owner_opted_in: true, interactive_user_present: false,
/// #     user_paused: false, on_ac_power: true, thermal_state_safe: true,
/// #     telemetry_authenticated: true, os_isolation_ready: true,
/// # };
/// let request = CpuPlacementRequest {
///     requested_cpu_millis: 2_000,
///     requested_memory_mb: 6_144,
/// };
/// let placement = evaluate_cpu_placement(&snapshot, request, 10_500, 5_000);
/// assert!(placement.is_ok());
/// ```
pub fn evaluate_cpu_placement(
    snapshot: &CpuWorkerSnapshot,
    request: CpuPlacementRequest,
    now_unix_ms: u64,
    max_telemetry_age_ms: u64,
) -> Result<CpuPlacement, CpuPlacementRejection> {
    if request.requested_cpu_millis == 0 || request.requested_memory_mb == 0 {
        return Err(CpuPlacementRejection::InvalidRequest);
    }
    if snapshot.effective_cpu_capacity_millis == 0
        || snapshot.available_cpu_millis > snapshot.effective_cpu_capacity_millis
        || snapshot.system_reserved_cpu_millis > snapshot.effective_cpu_capacity_millis
        || snapshot.total_memory_mb == 0
        || snapshot.available_memory_mb > snapshot.total_memory_mb
        || snapshot.system_reserved_memory_mb > snapshot.total_memory_mb
    {
        return Err(CpuPlacementRejection::InvalidCapacity);
    }
    if snapshot.sampled_at_unix_ms > now_unix_ms.saturating_add(MAX_TELEMETRY_FUTURE_SKEW_MS) {
        return Err(CpuPlacementRejection::FutureTelemetry);
    }
    if now_unix_ms.saturating_sub(snapshot.sampled_at_unix_ms) > max_telemetry_age_ms {
        return Err(CpuPlacementRejection::StaleTelemetry);
    }
    if !snapshot.powered_on {
        return Err(CpuPlacementRejection::DevicePoweredOff);
    }
    if !snapshot.owner_opted_in {
        return Err(CpuPlacementRejection::OwnerOptOut);
    }
    if snapshot.interactive_user_present {
        return Err(CpuPlacementRejection::InteractiveUse);
    }
    if snapshot.user_paused {
        return Err(CpuPlacementRejection::UserPaused);
    }
    if !snapshot.on_ac_power {
        return Err(CpuPlacementRejection::BatteryPower);
    }
    if !snapshot.thermal_state_safe {
        return Err(CpuPlacementRejection::ThermalUnsafe);
    }
    if !snapshot.telemetry_authenticated {
        return Err(CpuPlacementRejection::UnauthenticatedTelemetry);
    }
    if !snapshot.os_isolation_ready {
        return Err(CpuPlacementRejection::IsolationUnavailable);
    }

    // Respect measured free capacity and the explicit system reserve.
    let cpu_headroom = snapshot
        .available_cpu_millis
        .saturating_sub(snapshot.system_reserved_cpu_millis);
    if request.requested_cpu_millis > cpu_headroom {
        return Err(CpuPlacementRejection::CpuHeadroomInsufficient);
    }
    let memory_headroom = snapshot
        .available_memory_mb
        .saturating_sub(snapshot.system_reserved_memory_mb);
    if request.requested_memory_mb > memory_headroom {
        return Err(CpuPlacementRejection::MemoryHeadroomInsufficient);
    }

    Ok(CpuPlacement {
        admitted_cpu_millis: request.requested_cpu_millis,
        admitted_memory_mb: request.requested_memory_mb,
        remaining_cpu_headroom_millis: cpu_headroom - request.requested_cpu_millis,
        remaining_memory_headroom_mb: memory_headroom - request.requested_memory_mb,
        telemetry_sampled_at_unix_ms: snapshot.sampled_at_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type WorkerStateCase = (fn(&mut CpuWorkerSnapshot), CpuPlacementRejection);

    fn snapshot() -> CpuWorkerSnapshot {
        CpuWorkerSnapshot {
            sampled_at_unix_ms: 10_000,
            effective_cpu_capacity_millis: 8_000,
            available_cpu_millis: 6_000,
            system_reserved_cpu_millis: 2_000,
            total_memory_mb: 32_768,
            available_memory_mb: 20_000,
            system_reserved_memory_mb: 4_096,
            powered_on: true,
            owner_opted_in: true,
            interactive_user_present: false,
            user_paused: false,
            on_ac_power: true,
            thermal_state_safe: true,
            telemetry_authenticated: true,
            os_isolation_ready: true,
        }
    }

    fn request() -> CpuPlacementRequest {
        CpuPlacementRequest {
            requested_cpu_millis: 2_000,
            requested_memory_mb: 6_144,
        }
    }

    #[test]
    fn admits_only_within_measured_capacity_and_system_reserve() {
        let result = evaluate_cpu_placement(&snapshot(), request(), 10_500, 5_000).unwrap();
        assert_eq!(result.remaining_cpu_headroom_millis, 2_000);
        assert_eq!(result.remaining_memory_headroom_mb, 9_760);
    }

    #[test]
    fn existing_ujani_cpu_usage_cannot_consume_the_system_reserve() {
        let mut sample = snapshot();
        // Other work has already consumed 2,000 milli-cores, reducing free
        // CPU below effective capacity minus the reserve.
        sample.available_cpu_millis = 4_000;
        let mut oversized = request();
        oversized.requested_cpu_millis = 2_001;
        assert_eq!(
            evaluate_cpu_placement(&sample, oversized, 10_500, 5_000),
            Err(CpuPlacementRejection::CpuHeadroomInsufficient)
        );
        let placement = evaluate_cpu_placement(&sample, request(), 10_500, 5_000).unwrap();
        assert_eq!(placement.remaining_cpu_headroom_millis, 0);
    }

    #[test]
    fn reserve_is_configurable_and_not_hard_coded_to_two_cores() {
        let mut sample = snapshot();
        sample.system_reserved_cpu_millis = 7_000;
        assert_eq!(
            evaluate_cpu_placement(&sample, request(), 10_500, 5_000),
            Err(CpuPlacementRejection::CpuHeadroomInsufficient)
        );
    }

    #[test]
    fn rejects_stale_or_future_telemetry() {
        assert_eq!(
            evaluate_cpu_placement(&snapshot(), request(), 20_001, 5_000),
            Err(CpuPlacementRejection::StaleTelemetry)
        );
        let mut sample = snapshot();
        sample.sampled_at_unix_ms = 50_000;
        assert_eq!(
            evaluate_cpu_placement(&sample, request(), 10_000, 5_000),
            Err(CpuPlacementRejection::FutureTelemetry)
        );
    }

    #[test]
    fn rejects_untrusted_or_disruptive_worker_states() {
        let cases: [WorkerStateCase; 8] = [
            (
                |s| s.powered_on = false,
                CpuPlacementRejection::DevicePoweredOff,
            ),
            (
                |s| s.owner_opted_in = false,
                CpuPlacementRejection::OwnerOptOut,
            ),
            (
                |s| s.interactive_user_present = true,
                CpuPlacementRejection::InteractiveUse,
            ),
            (|s| s.user_paused = true, CpuPlacementRejection::UserPaused),
            (
                |s| s.on_ac_power = false,
                CpuPlacementRejection::BatteryPower,
            ),
            (
                |s| s.thermal_state_safe = false,
                CpuPlacementRejection::ThermalUnsafe,
            ),
            (
                |s| s.telemetry_authenticated = false,
                CpuPlacementRejection::UnauthenticatedTelemetry,
            ),
            (
                |s| s.os_isolation_ready = false,
                CpuPlacementRejection::IsolationUnavailable,
            ),
        ];
        for (mutate, expected) in cases {
            let mut sample = snapshot();
            mutate(&mut sample);
            assert_eq!(
                evaluate_cpu_placement(&sample, request(), 10_500, 5_000),
                Err(expected)
            );
        }
    }

    #[test]
    fn rejects_cpu_and_memory_overcommit() {
        let mut cpu = request();
        cpu.requested_cpu_millis = 4_001;
        assert_eq!(
            evaluate_cpu_placement(&snapshot(), cpu, 10_500, 5_000),
            Err(CpuPlacementRejection::CpuHeadroomInsufficient)
        );
        let mut memory = request();
        memory.requested_memory_mb = 16_000;
        assert_eq!(
            evaluate_cpu_placement(&snapshot(), memory, 10_500, 5_000),
            Err(CpuPlacementRejection::MemoryHeadroomInsufficient)
        );
    }

    #[test]
    fn rejects_invalid_measurements_and_zero_requests() {
        let mut sample = snapshot();
        sample.available_cpu_millis = sample.effective_cpu_capacity_millis + 1;
        assert_eq!(
            evaluate_cpu_placement(&sample, request(), 10_500, 5_000),
            Err(CpuPlacementRejection::InvalidCapacity)
        );
        let mut empty = request();
        empty.requested_memory_mb = 0;
        assert_eq!(
            evaluate_cpu_placement(&snapshot(), empty, 10_500, 5_000),
            Err(CpuPlacementRejection::InvalidRequest)
        );
    }
}
