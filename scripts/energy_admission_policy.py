"""Fail-closed reference admission policy; no telemetry or dispatch side effects."""
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
    reasons: list[str] = []
    if not isinstance(snapshot, EnergySnapshot):
        return ["invalid_snapshot"]

    if type(allow_battery) is not bool or type(minimum_battery_percent) is not int or not 0 <= minimum_battery_percent <= 100:
        reasons.append("invalid_policy_configuration")

    if snapshot.fresh is not True:
        reasons.append("telemetry_stale")
    if snapshot.owner_consented is not True:
        reasons.append("owner_consent_missing")
    if snapshot.device_idle is not True:
        reasons.append("device_active")

    if type(snapshot.on_ac_power) is not bool:
        reasons.append("invalid_power_telemetry")
    if snapshot.thermal_state not in {"nominal", "cool"}:
        reasons.append("thermal_state_not_safe")

    battery = snapshot.battery_percent
    if battery is not None and (type(battery) is not int or not 0 <= battery <= 100):
        reasons.append("invalid_battery_telemetry")
    if snapshot.on_ac_power is False and type(allow_battery) is bool:
        if allow_battery is not True:
            reasons.append("battery_compute_disabled")
        elif type(battery) is not int or not 0 <= battery <= 100 or battery < minimum_battery_percent:
            reasons.append("battery_below_minimum")

    resources = (
        snapshot.available_cpu_millis, snapshot.requested_cpu_millis,
        snapshot.available_memory_mb, snapshot.requested_memory_mb,
    )
    if any(type(value) is not int or value < 0 for value in resources):
        reasons.append("invalid_resource_telemetry")
    else:
        if snapshot.requested_cpu_millis <= 0 or snapshot.requested_cpu_millis > snapshot.available_cpu_millis:
            reasons.append("cpu_capacity_insufficient")
        if snapshot.requested_memory_mb <= 0 or snapshot.requested_memory_mb > snapshot.available_memory_mb:
            reasons.append("memory_capacity_insufficient")

    return list(dict.fromkeys(reasons))

def may_admit(snapshot: EnergySnapshot, **policy) -> bool:
    return not admission_reasons(snapshot, **policy)
