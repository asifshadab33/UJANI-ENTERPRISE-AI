# UJANI Enterprise AI — trusted time and clock reliability

## Responsibility and trust boundary

The Enterprise policy crate is deterministic: callers supply `now_unix_ms` and authenticated measurement timestamps. The policy crate does not read a host clock, authenticate an NTP source, or prove that the caller's time is trustworthy.

A production control plane must supply time from a monitored, trusted service clock. A worker's local wall clock is diagnostic input, not the sole authority for lease expiry, admission, replay protection or administrator approval validity.

## Time-source rules

- Use trusted service UTC for signed request validity, telemetry freshness evaluation, lease admission/expiry decisions and durable audit timestamps.
- Use monotonic clocks for in-process timeouts, task budgets, retry intervals and cancellation deadlines.
- Use unique nonce/request identifiers and durable replay claims for replay prevention; timestamps alone are not replay protection.
- Treat a device's reported sample time as an authenticated claim, compare it with trusted service time, and enforce the configured future-skew and maximum-age boundaries.
- Never allow a device clock to renew an expired lease or extend a server-side deadline.
- Keep timezone conversion at the presentation boundary. Database and protocol timestamps represent UTC instants.

## Clock uncertainty and failure

The service must monitor its own clock synchronisation and detect wall-clock steps by comparing wall-clock and monotonic deltas. The comparison detects discontinuities during one process lifetime; it does not prove NTP correctness and must be re-baselined after restart.

If trusted service time is unavailable or outside the accepted confidence window, deny new time-sensitive admission, renewal and dispatch. Do not silently substitute a worker's clock. Already-running workloads must still respect monotonic execution limits and administrator stop controls.

The durable PostgreSQL admission functions currently use `pg_catalog.clock_timestamp()` inside the transaction for lease-expiry, approval-expiry, telemetry-freshness and replay-window decisions. They re-sample database time after lock waits and before committing the audit receipt, so caller-supplied device timestamps do not become the authority for the atomic database admission decision. This is an important existing safeguard.

However, `clock_timestamp()` is still the database host's wall clock, not a monotonic or independently trusted clock. A backward database-clock step can make an expired lease or approval appear current until the clock is corrected; a forward step can expire valid work early. The current SQL does not independently detect or correct such a host-clock step. The production deployment therefore still needs monitored database time synchronisation, a fail-closed response to clock-confidence loss, and controlled forward/backward clock-step tests. The service's clock must also be monitored because it validates operator sessions and invokes the policy layer before the database transaction.

Database wall-clock functions are not monotonic clocks. The production service must define one authoritative time source for each transaction and test behaviour during service/database clock disagreement.

## Existing policy behaviour

- CPU and extended-resource admission accept caller-supplied UTC epoch milliseconds.
- Future telemetry is bounded by `MAX_TELEMETRY_FUTURE_SKEW_MS`; stale telemetry is rejected.
- Extended resource measurements must be authenticated, measured and fresh when the corresponding resource is requested.
- Current boundary tests cover inclusive age/future-skew limits, over-limit rejection and an extreme `u64` timestamp.
- Authenticated lease-renewal tests cover sequential and concurrent replay of the same signed request.

These are policy and regression-test guarantees only. They do not establish a production trusted-time service, authenticated telemetry agent, scheduler, HTTP service, or deployed lease authority.

## Required verification before pilot

- Clock synchronisation loss and recovery on the control plane.
- Forward/backward service-clock steps while leases and requests are active.
- Device clocks ahead/behind by the exact allowed skew and one unit beyond it.
- Stale, future-dated, extreme and replayed telemetry.
- Service/database clock disagreement and transaction retry behaviour.
- Lease expiry and renewal under clock steps, restart and failover.
- Audit ordering without assuming wall-clock timestamps are monotonic.
- Cross-platform worker monotonic timeout, sleep/resume and cancellation tests.

Remote worker dispatch remains disabled until the trusted-time source, durable lease authority, worker-side enforcement and recovery tests are implemented and independently reviewed.
