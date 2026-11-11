"""Conservative reference admission policy; no telemetry or dispatch side effects."""
from dataclasses import dataclass

@dataclass(frozen=True)
class EnergySnapshot:
    fresh: bool
    owner_consented: bool
    device_idle: bool
    on_ac_power: bool
    battery_percent: int | None
    thermal_state: str
    available_cpu_millis: int
    requested_cpu_millis: int
    available_memory_mb: int
    requested_memory_mb: int

def admission_reasons(snapshot: EnergySnapshot, *, allow_battery: bool = False,
                      minimum_battery_percent: int = 50) -> list[str]:
    reasons = []
    if not snapshot.fresh: reasons.append("telemetry_stale")
    if not snapshot.owner_consented: reasons.append("owner_consent_missing")
    if not snapshot.device_idle: reasons.append("device_active")
    if snapshot.thermal_state not in {"nominal", "cool"}: reasons.append("thermal_state_not_safe")
    if not snapshot.on_ac_power:
        if not allow_battery: reasons.append("battery_compute_disabled")
        elif snapshot.battery_percent is None or snapshot.battery_percent < minimum_battery_percent:
            reasons.append("battery_below_minimum")
    if snapshot.requested_cpu_millis <= 0 or snapshot.requested_cpu_millis > snapshot.available_cpu_millis:
        reasons.append("cpu_capacity_insufficient")
    if snapshot.requested_memory_mb <= 0 or snapshot.requested_memory_mb > snapshot.available_memory_mb:
        reasons.append("memory_capacity_insufficient")
    return reasons

def may_admit(snapshot: EnergySnapshot, **policy) -> bool:
    return not admission_reasons(snapshot, **policy)
