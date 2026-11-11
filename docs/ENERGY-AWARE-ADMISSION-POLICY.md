# Energy-aware admission policy

The reference policy fails closed unless telemetry is fresh, the device owner has
consented, the device is idle, thermal state is nominal or cool, and requested CPU
and memory fit verified available capacity.

Battery execution is disabled by default. A customer may explicitly enable it
with a minimum charge threshold. Malformed or out-of-range power, battery,
resource, or policy values are rejected.

This is a deterministic policy primitive and regression suite, not a live
scheduler. It does not read sensors, authenticate telemetry, reserve capacity,
wake devices, dispatch tasks, enforce power limits, or prove energy savings.
Production integration must apply this policy after authenticated telemetry
admission and recheck the conditions immediately before any future workload
reservation. Remote dispatch remains disabled.
