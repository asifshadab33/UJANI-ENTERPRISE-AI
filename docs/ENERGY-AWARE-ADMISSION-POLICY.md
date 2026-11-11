# Energy-aware admission policy (Batch I)

A workload is admitted only when telemetry is fresh, the device owner has
consented, the device is idle, thermal state is nominal or cool, and CPU and
memory requests fit the reported available capacity.

Battery execution is disabled by default. A future customer policy may explicitly
enable it with a minimum charge threshold; that opt-in never bypasses consent,
freshness, idle-state, thermal or capacity checks.

This is a deterministic reference policy and regression suite, not a live
scheduler. It does not read sensors, authenticate telemetry, wake devices,
dispatch tasks, enforce power limits or prove energy savings. Those controls
remain production gates for the customer-hosted agent/control plane.
