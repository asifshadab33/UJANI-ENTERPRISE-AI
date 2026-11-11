import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from energy_admission_policy import EnergySnapshot, admission_reasons, may_admit


class EnergyAdmissionPolicyTests(unittest.TestCase):
    def snapshot(self, **changes):
        values = dict(
            fresh=True, owner_consented=True, device_idle=True,
            on_ac_power=True, battery_percent=100, thermal_state="nominal",
            available_cpu_millis=4000, requested_cpu_millis=1000,
            available_memory_mb=8192, requested_memory_mb=1024,
        )
        values.update(changes)
        return EnergySnapshot(**values)

    def test_admits_fresh_consented_idle_capacity(self):
        self.assertTrue(may_admit(self.snapshot()))

    def test_fails_closed_for_stale_active_or_unconsented_device(self):
        reasons = admission_reasons(self.snapshot(
            fresh=False, device_idle=False, owner_consented=False))
        self.assertTrue({"telemetry_stale", "device_active", "owner_consent_missing"}.issubset(reasons))

    def test_battery_disabled_by_default_and_minimum_applies_when_opted_in(self):
        self.assertIn("battery_compute_disabled", admission_reasons(self.snapshot(on_ac_power=False)))
        self.assertIn("battery_below_minimum", admission_reasons(
            self.snapshot(on_ac_power=False, battery_percent=20),
            allow_battery=True, minimum_battery_percent=60))

    def test_rejects_thermal_and_capacity_pressure(self):
        reasons = admission_reasons(self.snapshot(
            thermal_state="hot", requested_cpu_millis=5000, requested_memory_mb=9000))
        self.assertTrue({"thermal_state_not_safe", "cpu_capacity_insufficient",
                         "memory_capacity_insufficient"}.issubset(reasons))

    def test_rejects_malformed_sensor_and_policy_values(self):
        reasons = admission_reasons(self.snapshot(
            on_ac_power=1, battery_percent=150, available_cpu_millis=True))
        self.assertTrue({"invalid_power_telemetry", "invalid_battery_telemetry",
                         "invalid_resource_telemetry"}.issubset(reasons))
        self.assertIn("invalid_policy_configuration", admission_reasons(
            self.snapshot(on_ac_power=False), allow_battery=True, minimum_battery_percent=101))

    def test_unknown_thermal_state_is_not_admitted(self):
        self.assertIn("thermal_state_not_safe",
                      admission_reasons(self.snapshot(thermal_state="unknown")))


if __name__ == "__main__":
    unittest.main()
