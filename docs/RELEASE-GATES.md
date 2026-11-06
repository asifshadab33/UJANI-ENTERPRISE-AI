# UJANI Enterprise AI — release gates and risk register

This file defines minimum gates before enabling remote work on enrolled devices. Passing a code test alone does not satisfy a security gate.

## Risk register

| Risk | Required control | Evidence before pilot |
|---|---|---|
| Unauthorised device joins | Admin invitation, device-bound identity, approval and revocation | Negative enrolment tests, credential lifecycle tests |
| Impersonated/replayed job | Signed short-lived assignment, nonce, expiry and policy version | Signature, replay, expiry and stale-policy tests |
| Compromised control plane | Worker-side validation and signed policy/job envelope | Invalid signature and downgrade rejection tests |
| Workload escape | OS-enforced isolation matched to threat level | Platform-specific sandbox escape review and independent test |
| Data exfiltration | Scoped mounts, egress allow-list, data classification | Network-denial tests and data-flow review |
| Employee disruption | Interactive activity detection, priority, pause and opt-out | Foreground-app simulation and interruption tests |
| Resource exhaustion | CPU/RAM/GPU/disk/network/time quotas | Stress and quota enforcement tests |
| False worker results | Output verification, provenance and, where appropriate, redundant checks | Corrupt/forged output tests |
| Device loss or compromise | Revocation, credential rotation and remote disable | Lost-device and revocation drill |
| Supply-chain compromise | Signed updates, SBOM, dependency review and rollback | Signature failure, rollback and vulnerability-response exercise |
| Misleading green claims | Workload-normalised energy measurement and transparent assumptions | Reproducible baseline comparison |
| Unreliable availability | Heartbeats, leases, checkpoints and bounded retries | Worker disconnect and recovery tests |

## Mandatory policy invariants

- No workload runs on an un-enrolled, revoked or unauthenticated device.
- No job starts if its signature, expiry, nonce or policy version is invalid.
- No job gets broader filesystem or network access than its declared policy.
- No workload runs outside its permitted window or resource budget.
- Employee activity and device-owner pause take precedence over batch jobs, subject to documented organisation policy.
- Cancellation stops new work, terminates the workload and cleans temporary resources.
- Sensitive workload data is never placed in general-purpose logs.
- Failure to verify a security property means deny by default.

## Pilot acceptance checklist

- [ ] Threat model reviewed by someone other than the implementer.
- [ ] Device identity enrolment, rotation and revocation tested.
- [ ] Worker-side signed assignment validation tested.
- [ ] OS sandbox and resource controls verified on every supported OS.
- [ ] Network egress blocked by default and tested.
- [ ] Interactive-user pause and emergency stop tested.
- [ ] Data retention and deletion verified.
- [ ] Audit events are attributable and protected from ordinary workload modification.
- [ ] Failure injection covers worker loss, controller loss, timeouts and partial output.
- [ ] Independent security review completed for the intended workload class.
- [ ] Energy and cost claims use reproducible workload-normalised measurements.

## Non-goals until later

- Public anonymous compute marketplace.
- General-purpose execution of arbitrary third-party code.
- Multi-tenant sharing of accelerators without a reviewed isolation model.
- Claims of guaranteed cost savings, carbon savings or compliance.


## Additional scheduler admission gate

The policy crate exposes `admit_with_context`, layering these mandatory conditions on top of device enrolment and resource quotas: fresh telemetry, explicit owner opt-in, administrator-approved schedule, no interactive user activity, AC power, safe thermal state, network/egress approval and workload data-classification approval.

This is side-effect-free policy logic. It does not read telemetry, authenticate devices, schedule or execute work. A production worker must independently revalidate the conditions immediately before launch using OS-enforced resource and isolation controls. Missing evidence fails closed.
