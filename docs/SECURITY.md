# Security Policy

## Status

UJANI Enterprise AI is pre-alpha. Do not deploy it to production infrastructure or employee endpoints. The current code is illustrative policy logic, not an enforcement system.

## Reporting

Please do not publish exploitable details in a public issue. Use GitHub private vulnerability reporting if enabled, or a verified private maintainer contact.

Include affected commit, environment, impact, safe reproduction steps and suggested mitigation.

## Required controls before production

- Explicit device enrolment, strong identity, key rotation and revocation.
- Mutual authentication and signed workload assignments.
- OS-enforced workload isolation and least privilege.
- Strict network egress, filesystem and resource limits.
- Tenant/workspace isolation and data classification.
- No silent employee-device participation.
- Admin policy, user-visible status and audit trail.
- Signed agent updates, dependency provenance and rollback.
- Incident response and independent penetration testing.

A policy decision in application code is not a substitute for OS-enforced security. Do not describe the platform as secure or compliant until controls are implemented and independently assessed.
