//! CPU-only worker capacity admission for the Enterprise scheduler.
//!
//! This is deterministic policy logic, not a telemetry collector, scheduler,
//! sandbox or runtime quota enforcer. A trusted host must supply fresh,
//! authenticated measurements and the worker must re-check limits at launch.
#![forbid(unsafe_code)]

use crate::Workload;

pub const MAX_TELEMETRY_FUTURE_SKEW_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuWorkerSnapshot {
    pub sampled_at_unix_ms: u64,
    /// Effective CPU quota visible to this worker, in milli-cores.
    /// Use cgroup/job-object limits, not only host logical-core count.
    pub effective_cpu_capacity_millis: u32,
    pub available_cpu_millis: u32,
    /// Configurable capacity reserved for OS/network and non-UJANI services.
    pub system_reserved_cpu_millis: u32,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub system_reserved_memory_mb: u64,
    /// UJANI must never wake a sleeping or powered-off device for a job.
    pub powered_on: bool,
    pub owner_opted_in: bool,
    pub interactive_user_present: bool,
    pub user_paused: bool,
    pub on_ac_power: bool,
    pub thermal_state_safe: bool,
    pub telemetry_authenticated: bool,
    pub os_isolation_ready: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuPlacementRequest {
    pub requested_cpu_millis: u32,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuPlacement {
    pub admitted_cpu_millis: u32,
    pub admitted_memory_mb: u64,
    pub remaining_cpu_headroom_millis: u32,
    pub remaining_memory_headroom_mb: u64,
    pub telemetry_sampled_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPlacementRejection {
    InvalidCapacity,
    InvalidRequest,
    FutureTelemetry,
    StaleTelemetry,
    DevicePoweredOff,
    OwnerOptOut,
    InteractiveUse,
    UserPaused,
    BatteryPower,
    ThermalUnsafe,
    UnauthenticatedTelemetry,
    IsolationUnavailable,
    CpuHeadroomInsufficient,
    MemoryHeadroomInsufficient,
}

/// Evaluate whether a CPU-only workload fits the reported worker.
///
/// The host supplies the maximum telemetry age as a policy input. This function
/// fails closed for stale/future or unauthenticated measurements. It does not
/// reserve capacity: acquire the durable lease before dispatch, then enforce
/// CPU/RAM limits using OS controls on the worker.
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
        .min(snapshot.effective_cpu_capacity_millis - snapshot.system_reserved_cpu_millis);
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
    fn reserve_is_configurable_and_not_hard_coded_to_two_cores() {
        let mut sample = snapshot();
        sample.system_reserved_cpu_millis = 5_000;
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
        let cases: [(fn(&mut CpuWorkerSnapshot), CpuPlacementRejection); 8] = [
            (|s| s.powered_on = false, CpuPlacementRejection::DevicePoweredOff),
            (|s| s.owner_opted_in = false, CpuPlacementRejection::OwnerOptOut),
            (|s| s.interactive_user_present = true, CpuPlacementRejection::InteractiveUse),
            (|s| s.user_paused = true, CpuPlacementRejection::UserPaused),
            (|s| s.on_ac_power = false, CpuPlacementRejection::BatteryPower),
            (|s| s.thermal_state_safe = false, CpuPlacementRejection::ThermalUnsafe),
            (|s| s.telemetry_authenticated = false, CpuPlacementRejection::UnauthenticatedTelemetry),
            (|s| s.os_isolation_ready = false, CpuPlacementRejection::IsolationUnavailable),
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
        cpu.requested_cpu_millis = 6_001;
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
