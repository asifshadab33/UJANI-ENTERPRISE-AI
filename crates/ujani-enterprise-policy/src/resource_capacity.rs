//! Authenticated, multi-resource worker admission contract.
//!
//! This is a deterministic policy boundary, not a telemetry collector, lease
//! authority, scheduler or OS quota enforcer. Production callers must provide
//! fresh authenticated measurements and reserve a durable lease before dispatch.
//! Unknown or estimated capacity is never treated as available.

use crate::cpu_capacity::{
    evaluate_cpu_placement, CpuPlacement, CpuPlacementRejection, CpuPlacementRequest,
    CpuWorkerSnapshot, MAX_TELEMETRY_FUTURE_SKEW_MS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementBasis {
    Measured,
    Estimated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceMeasurement<T> {
    pub sampled_at_unix_ms: u64,
    pub authenticated: bool,
    pub basis: MeasurementBasis,
    pub value: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceleratorHeadroom {
    pub available_memory_mb: u64,
    pub available_compute_units: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageHeadroom {
    pub available_scratch_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkHeadroom {
    pub available_bandwidth_kbps: u64,
    pub egress_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedWorkerSnapshot {
    /// CPU/RAM, power, thermal, owner consent and OS-isolation evidence.
    pub cpu: CpuWorkerSnapshot,
    /// None means unknown/unreported, not zero and not unlimited.
    pub gpu: Option<ResourceMeasurement<AcceleratorHeadroom>>,
    pub npu: Option<ResourceMeasurement<AcceleratorHeadroom>>,
    pub storage: Option<ResourceMeasurement<StorageHeadroom>>,
    pub network: Option<ResourceMeasurement<NetworkHeadroom>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedResourceRequest {
    pub cpu: CpuPlacementRequest,
    pub gpu_memory_mb: u64,
    pub gpu_compute_units: u32,
    pub npu_memory_mb: u64,
    pub npu_compute_units: u32,
    pub scratch_storage_bytes: u64,
    pub network_bandwidth_kbps: u64,
    /// Network use is denied unless both the request and authenticated policy permit it.
    pub network_access: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedResourcePlacement {
    pub cpu: CpuPlacement,
    pub admitted_gpu_memory_mb: u64,
    pub admitted_gpu_compute_units: u32,
    pub admitted_npu_memory_mb: u64,
    pub admitted_npu_compute_units: u32,
    pub admitted_scratch_storage_bytes: u64,
    pub admitted_network_bandwidth_kbps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Gpu,
    Npu,
    Storage,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedResourceRejection {
    Cpu(CpuPlacementRejection),
    InvalidRequest,
    MissingMeasurement(ResourceKind),
    UnauthenticatedMeasurement(ResourceKind),
    EstimatedMeasurement(ResourceKind),
    StaleMeasurement(ResourceKind),
    InsufficientCapacity(ResourceKind),
    NetworkPolicyDenied,
}

fn measured_value<T>(
    measurement: Option<&ResourceMeasurement<T>>,
    kind: ResourceKind,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<&T, ExtendedResourceRejection> {
    let measurement = measurement.ok_or(ExtendedResourceRejection::MissingMeasurement(kind))?;
    if !measurement.authenticated {
        return Err(ExtendedResourceRejection::UnauthenticatedMeasurement(kind));
    }
    if measurement.basis != MeasurementBasis::Measured {
        return Err(ExtendedResourceRejection::EstimatedMeasurement(kind));
    }
    if measurement.sampled_at_unix_ms > now_unix_ms.saturating_add(MAX_TELEMETRY_FUTURE_SKEW_MS)
        || now_unix_ms.saturating_sub(measurement.sampled_at_unix_ms) > max_age_ms
    {
        return Err(ExtendedResourceRejection::StaleMeasurement(kind));
    }
    Ok(&measurement.value)
}

/// Evaluate CPU, RAM, optional accelerators, scratch storage and network headroom.
///
/// GPU/NPU/storage/network measurements are required only when the request needs
/// those resources. Requested capacities must be measured, authenticated and fresh.
/// Battery, sleeping/offline and unsafe-thermal devices remain rejected by the CPU
/// admission contract; this function never wakes a device or creates a lease.
pub fn evaluate_extended_resource_placement(
    snapshot: &ExtendedWorkerSnapshot,
    request: ExtendedResourceRequest,
    now_unix_ms: u64,
    max_telemetry_age_ms: u64,
) -> Result<ExtendedResourcePlacement, ExtendedResourceRejection> {
    if (request.gpu_memory_mb == 0) != (request.gpu_compute_units == 0)
        || (request.npu_memory_mb == 0) != (request.npu_compute_units == 0)
        || (!request.network_access && request.network_bandwidth_kbps != 0)
        || (request.network_access && request.network_bandwidth_kbps == 0)
    {
        return Err(ExtendedResourceRejection::InvalidRequest);
    }

    let cpu = evaluate_cpu_placement(
        &snapshot.cpu,
        request.cpu,
        now_unix_ms,
        max_telemetry_age_ms,
    )
    .map_err(ExtendedResourceRejection::Cpu)?;

    if request.gpu_memory_mb > 0 {
        let gpu = measured_value(
            snapshot.gpu.as_ref(),
            ResourceKind::Gpu,
            now_unix_ms,
            max_telemetry_age_ms,
        )?;
        if gpu.available_memory_mb < request.gpu_memory_mb
            || gpu.available_compute_units < request.gpu_compute_units
        {
            return Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Gpu,
            ));
        }
    }

    if request.npu_memory_mb > 0 {
        let npu = measured_value(
            snapshot.npu.as_ref(),
            ResourceKind::Npu,
            now_unix_ms,
            max_telemetry_age_ms,
        )?;
        if npu.available_memory_mb < request.npu_memory_mb
            || npu.available_compute_units < request.npu_compute_units
        {
            return Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Npu,
            ));
        }
    }

    if request.scratch_storage_bytes > 0 {
        let storage = measured_value(
            snapshot.storage.as_ref(),
            ResourceKind::Storage,
            now_unix_ms,
            max_telemetry_age_ms,
        )?;
        if storage.available_scratch_bytes < request.scratch_storage_bytes {
            return Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Storage,
            ));
        }
    }

    if request.network_access {
        let network = measured_value(
            snapshot.network.as_ref(),
            ResourceKind::Network,
            now_unix_ms,
            max_telemetry_age_ms,
        )?;
        if !network.egress_allowed {
            return Err(ExtendedResourceRejection::NetworkPolicyDenied);
        }
        if network.available_bandwidth_kbps < request.network_bandwidth_kbps {
            return Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Network,
            ));
        }
    }

    Ok(ExtendedResourcePlacement {
        cpu,
        admitted_gpu_memory_mb: request.gpu_memory_mb,
        admitted_gpu_compute_units: request.gpu_compute_units,
        admitted_npu_memory_mb: request.npu_memory_mb,
        admitted_npu_compute_units: request.npu_compute_units,
        admitted_scratch_storage_bytes: request.scratch_storage_bytes,
        admitted_network_bandwidth_kbps: request.network_bandwidth_kbps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu_capacity::CpuWorkerSnapshot;

    const NOW: u64 = 100_000;

    fn cpu_snapshot() -> CpuWorkerSnapshot {
        CpuWorkerSnapshot {
            sampled_at_unix_ms: NOW,
            effective_cpu_capacity_millis: 8_000,
            available_cpu_millis: 6_000,
            system_reserved_cpu_millis: 1_000,
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

    fn measured<T>(value: T) -> ResourceMeasurement<T> {
        ResourceMeasurement {
            sampled_at_unix_ms: NOW,
            authenticated: true,
            basis: MeasurementBasis::Measured,
            value,
        }
    }

    fn snapshot() -> ExtendedWorkerSnapshot {
        ExtendedWorkerSnapshot {
            cpu: cpu_snapshot(),
            gpu: Some(measured(AcceleratorHeadroom {
                available_memory_mb: 8_000,
                available_compute_units: 64,
            })),
            npu: Some(measured(AcceleratorHeadroom {
                available_memory_mb: 2_000,
                available_compute_units: 16,
            })),
            storage: Some(measured(StorageHeadroom {
                available_scratch_bytes: 20_000_000_000,
            })),
            network: Some(measured(NetworkHeadroom {
                available_bandwidth_kbps: 100_000,
                egress_allowed: true,
            })),
        }
    }

    fn request() -> ExtendedResourceRequest {
        ExtendedResourceRequest {
            cpu: CpuPlacementRequest {
                requested_cpu_millis: 1_000,
                requested_memory_mb: 2_048,
            },
            gpu_memory_mb: 0,
            gpu_compute_units: 0,
            npu_memory_mb: 0,
            npu_compute_units: 0,
            scratch_storage_bytes: 0,
            network_bandwidth_kbps: 0,
            network_access: false,
        }
    }

    #[test]
    fn cpu_only_request_does_not_require_unrequested_optional_resources() {
        let mut value = snapshot();
        value.gpu = None;
        value.npu = None;
        value.storage = None;
        value.network = None;
        assert!(evaluate_extended_resource_placement(&value, request(), NOW, 5_000).is_ok());
    }

    #[test]
    fn accepts_only_authenticated_measured_fresh_requested_resources() {
        let mut ask = request();
        ask.gpu_memory_mb = 4_000;
        ask.gpu_compute_units = 32;
        ask.npu_memory_mb = 1_000;
        ask.npu_compute_units = 8;
        ask.scratch_storage_bytes = 1_000_000;
        ask.network_access = true;
        ask.network_bandwidth_kbps = 10_000;
        let result = evaluate_extended_resource_placement(&snapshot(), ask, NOW, 5_000).unwrap();
        assert_eq!(result.admitted_gpu_memory_mb, 4_000);
        assert_eq!(result.admitted_npu_compute_units, 8);
        assert_eq!(result.admitted_scratch_storage_bytes, 1_000_000);
        assert_eq!(result.admitted_network_bandwidth_kbps, 10_000);
    }

    #[test]
    fn unknown_gpu_capacity_fails_closed_when_gpu_is_requested() {
        let mut value = snapshot();
        value.gpu = None;
        let mut ask = request();
        ask.gpu_memory_mb = 1_000;
        ask.gpu_compute_units = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::MissingMeasurement(
                ResourceKind::Gpu
            ))
        );
    }

    #[test]
    fn estimated_unauthenticated_and_stale_gpu_measurements_are_rejected() {
        let mut value = snapshot();
        let mut ask = request();
        ask.gpu_memory_mb = 1;
        ask.gpu_compute_units = 1;
        value.gpu = Some(ResourceMeasurement {
            basis: MeasurementBasis::Estimated,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 8_000,
                available_compute_units: 64,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::EstimatedMeasurement(
                ResourceKind::Gpu
            ))
        );
        value.gpu = Some(ResourceMeasurement {
            authenticated: false,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 8_000,
                available_compute_units: 64,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::UnauthenticatedMeasurement(
                ResourceKind::Gpu
            ))
        );
        value.gpu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 10_000,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 8_000,
                available_compute_units: 64,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Gpu
            ))
        );
    }

    #[test]
    fn insufficient_accelerator_memory_or_compute_is_rejected() {
        let mut value = snapshot();
        value.gpu = Some(measured(AcceleratorHeadroom {
            available_memory_mb: 500,
            available_compute_units: 2,
        }));
        let mut ask = request();
        ask.gpu_memory_mb = 1_000;
        ask.gpu_compute_units = 4;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Gpu
            ))
        );
    }

    #[test]
    fn unknown_npu_and_storage_are_not_treated_as_available() {
        let mut value = snapshot();
        value.npu = None;
        let mut ask = request();
        ask.npu_memory_mb = 256;
        ask.npu_compute_units = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::MissingMeasurement(
                ResourceKind::Npu
            ))
        );
        value = snapshot();
        value.storage = None;
        ask = request();
        ask.scratch_storage_bytes = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::MissingMeasurement(
                ResourceKind::Storage
            ))
        );
    }

    #[test]
    fn network_requires_authenticated_capacity_and_egress_policy() {
        let mut value = snapshot();
        let mut ask = request();
        ask.network_access = true;
        ask.network_bandwidth_kbps = 1;
        value.network = Some(measured(NetworkHeadroom {
            available_bandwidth_kbps: 10_000,
            egress_allowed: false,
        }));
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::NetworkPolicyDenied)
        );
        value.network = None;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::MissingMeasurement(
                ResourceKind::Network
            ))
        );
    }

    #[test]
    fn insufficient_npu_storage_and_network_capacity_are_rejected() {
        let mut value = snapshot();
        value.npu = Some(measured(AcceleratorHeadroom {
            available_memory_mb: 100,
            available_compute_units: 1,
        }));
        let mut ask = request();
        ask.npu_memory_mb = 256;
        ask.npu_compute_units = 2;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Npu
            ))
        );

        value = snapshot();
        value.storage = Some(measured(StorageHeadroom {
            available_scratch_bytes: 100,
        }));
        ask = request();
        ask.scratch_storage_bytes = 101;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Storage
            ))
        );

        value = snapshot();
        value.network = Some(measured(NetworkHeadroom {
            available_bandwidth_kbps: 100,
            egress_allowed: true,
        }));
        ask = request();
        ask.network_access = true;
        ask.network_bandwidth_kbps = 101;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::InsufficientCapacity(
                ResourceKind::Network
            ))
        );
    }

    #[test]
    fn unauthenticated_or_stale_storage_and_network_measurements_are_rejected() {
        let mut value = snapshot();
        value.storage = Some(ResourceMeasurement {
            authenticated: false,
            ..measured(StorageHeadroom {
                available_scratch_bytes: 10_000,
            })
        });
        let mut ask = request();
        ask.scratch_storage_bytes = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::UnauthenticatedMeasurement(
                ResourceKind::Storage
            ))
        );

        value = snapshot();
        value.network = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 10_000,
            ..measured(NetworkHeadroom {
                available_bandwidth_kbps: 10_000,
                egress_allowed: true,
            })
        });
        ask = request();
        ask.network_access = true;
        ask.network_bandwidth_kbps = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Network
            ))
        );
    }

    #[test]
    fn inconsistent_resource_requests_are_rejected() {
        let mut ask = request();
        ask.gpu_memory_mb = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&snapshot(), ask, NOW, 5_000),
            Err(ExtendedResourceRejection::InvalidRequest)
        );
        ask = request();
        ask.network_bandwidth_kbps = 1;
        assert_eq!(
            evaluate_extended_resource_placement(&snapshot(), ask, NOW, 5_000),
            Err(ExtendedResourceRejection::InvalidRequest)
        );
    }

    #[test]
    fn sleeping_battery_or_thermally_unsafe_devices_remain_rejected() {
        let mut value = snapshot();
        value.cpu.powered_on = false;
        assert!(matches!(
            evaluate_extended_resource_placement(&value, request(), NOW, 5_000),
            Err(ExtendedResourceRejection::Cpu(
                CpuPlacementRejection::DevicePoweredOff
            ))
        ));
        value = snapshot();
        value.cpu.on_ac_power = false;
        assert!(matches!(
            evaluate_extended_resource_placement(&value, request(), NOW, 5_000),
            Err(ExtendedResourceRejection::Cpu(
                CpuPlacementRejection::BatteryPower
            ))
        ));
        value = snapshot();
        value.cpu.thermal_state_safe = false;
        assert!(matches!(
            evaluate_extended_resource_placement(&value, request(), NOW, 5_000),
            Err(ExtendedResourceRejection::Cpu(
                CpuPlacementRejection::ThermalUnsafe
            ))
        ));
    }

    #[test]
    fn telemetry_freshness_age_boundary_is_inclusive_for_every_resource_kind() {
        let mut value = snapshot();
        let mut ask = request();

        value.gpu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_000,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        ask.gpu_memory_mb = 1;
        ask.gpu_compute_units = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.gpu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_001,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Gpu
            ))
        );

        value = snapshot();
        ask = request();
        value.npu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_000,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        ask.npu_memory_mb = 1;
        ask.npu_compute_units = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.npu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_001,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Npu
            ))
        );

        value = snapshot();
        ask = request();
        value.storage = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_000,
            ..measured(StorageHeadroom {
                available_scratch_bytes: 1,
            })
        });
        ask.scratch_storage_bytes = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.storage = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_001,
            ..measured(StorageHeadroom {
                available_scratch_bytes: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Storage
            ))
        );

        value = snapshot();
        ask = request();
        value.network = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_000,
            ..measured(NetworkHeadroom {
                available_bandwidth_kbps: 1,
                egress_allowed: true,
            })
        });
        ask.network_access = true;
        ask.network_bandwidth_kbps = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.network = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW - 5_001,
            ..measured(NetworkHeadroom {
                available_bandwidth_kbps: 1,
                egress_allowed: true,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Network
            ))
        );
    }
    #[test]
    fn future_resource_measurements_obey_exact_clock_skew_boundary() {
        let mut value = snapshot();
        let mut ask = request();

        value.gpu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        ask.gpu_memory_mb = 1;
        ask.gpu_compute_units = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.gpu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS + 1,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Gpu
            ))
        );
        value.gpu = Some(ResourceMeasurement {
            sampled_at_unix_ms: u64::MAX,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Gpu
            ))
        );

        value = snapshot();
        ask = request();
        value.npu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        ask.npu_memory_mb = 1;
        ask.npu_compute_units = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.npu = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS + 1,
            ..measured(AcceleratorHeadroom {
                available_memory_mb: 1,
                available_compute_units: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Npu
            ))
        );

        value = snapshot();
        ask = request();
        value.storage = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS,
            ..measured(StorageHeadroom {
                available_scratch_bytes: 1,
            })
        });
        ask.scratch_storage_bytes = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.storage = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS + 1,
            ..measured(StorageHeadroom {
                available_scratch_bytes: 1,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Storage
            ))
        );

        value = snapshot();
        ask = request();
        value.network = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS,
            ..measured(NetworkHeadroom {
                available_bandwidth_kbps: 1,
                egress_allowed: true,
            })
        });
        ask.network_access = true;
        ask.network_bandwidth_kbps = 1;
        assert!(evaluate_extended_resource_placement(&value, ask, NOW, 5_000).is_ok());
        value.network = Some(ResourceMeasurement {
            sampled_at_unix_ms: NOW + MAX_TELEMETRY_FUTURE_SKEW_MS + 1,
            ..measured(NetworkHeadroom {
                available_bandwidth_kbps: 1,
                egress_allowed: true,
            })
        });
        assert_eq!(
            evaluate_extended_resource_placement(&value, ask, NOW, 5_000),
            Err(ExtendedResourceRejection::StaleMeasurement(
                ResourceKind::Network
            ))
        );
    }
}
