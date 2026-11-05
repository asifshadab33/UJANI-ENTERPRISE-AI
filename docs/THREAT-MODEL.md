# Initial threat model

This is a starting point for review, not a completed security assessment.

## Assets
- Organisation data and credentials.
- Device identities and enrolment tokens.
- Workload inputs, outputs and model artefacts.
- Control-plane policy and audit records.
- Endpoint availability and integrity.

## Trust boundaries
- User/admin to control plane.
- Control plane to worker agent.
- Worker agent to isolated workload.
- Workload to host OS and hardware.
- Workload to data stores and external networks.
- One organisation/team/workspace to another.

## Threats to address
- Unauthorised device enrolment or device impersonation.
- Compromised control plane issuing malicious jobs.
- Malicious or compromised worker reporting false capacity/results.
- Workload escape or privilege escalation.
- Data exfiltration through workload network access or logs.
- Credential theft, replay and stale assignments.
- Resource exhaustion or denial of service.
- Insider misuse or hidden use of employee devices.
- Supply-chain compromise of agents, models or dependencies.

## Minimum mitigations
- Short-lived, device-bound credentials and revocation.
- Signed assignments with expiry, nonce and policy version.
- Independent worker-side policy validation.
- OS-enforced sandboxing and strict resource limits.
- Egress allow-lists and scoped data mounts.
- Immutable/append-only audit design with access controls.
- Transparent participation indicators and admin/user controls.
- Signed releases, SBOM, reproducible builds where feasible and security review.

## Open questions
- Which operating systems and isolation mechanisms are in scope first?
- What identity provider and device-management systems must integrate?
- What data classifications may run on which device groups?
- What is the threat model for malicious administrators or compromised endpoints?
- What retention and regulatory obligations apply to target customers?
