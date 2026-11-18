# UJANI Enterprise AI — Project Handbook

> A navigable operations, development and troubleshooting index. This handbook links to the authoritative contracts and source; it does not imply that a prototype policy component is a deployed fleet service.

**Project state:** pre-alpha policy/control-plane prototype. No production endpoint agent, live fleet scheduler, general remote execution or production identity/network service is enabled. Read [Release Gates](RELEASE-GATES.md) and [Operator Control Plane](OPERATOR-CONTROL-PLANE.md) before any pilot.

## Contents

1. [Start here](#1-start-here)
2. [Build from zero](#2-build-from-zero)
3. [System architecture and trust boundaries](#3-system-architecture-and-trust-boundaries)
4. [Repository map](#4-repository-map)
5. [Policy, service and database operation index](#5-policy-service-and-database-operation-index)
6. [Model inventory and resource coordination](#6-model-inventory-and-resource-coordination)
7. [Operator console](#7-operator-console)
8. [Tests, checks and CI](#8-tests-checks-and-ci)
9. [Troubleshooting and incident handling](#9-troubleshooting-and-incident-handling)
10. [Security and deployment gates](#10-security-and-deployment-gates)
11. [Change and maintenance procedure](#11-change-and-maintenance-procedure)
12. [Glossary and further reading](#12-glossary-and-further-reading)

## 1. Start here

- Operators: [Operator workflows](OPERATOR-WORKFLOWS.md), [Operator console readiness](OPERATOR_PREVIEW_TESTER_READINESS.md), [Customer-hosted deployment](CUSTOMER-HOSTED-CONTROL-PLANE-DEPLOYMENT.md).
- Developers: [Architecture](ARCHITECTURE.md), [Contributing](../CONTRIBUTING.md), [Security](SECURITY.md), [Threat model](THREAT-MODEL.md).
- Device trust: [Device trust service integration](DEVICE-TRUST-SERVICE-INTEGRATION.md), [Durable device trust registry](DURABLE-DEVICE-TRUST-REGISTRY.md).
- Model and compute: [Model inventory ingestion](ENTERPRISE-MODEL-INVENTORY-INGESTION.md), [Operator model inventory](OPERATOR-MODEL-RUNTIME-INVENTORY.md), [Adaptive resource allocation](ADAPTIVE-RESOURCE-ALLOCATION.md).
- Security integrations: [Connector integration status](CONNECTOR-INTEGRATION-STATUS.md), [Security provider integration](ORG-SECURITY-PROVIDER-INTEGRATION.md).
- Reviewers: [Release gates](RELEASE-GATES.md), [Risk register](ADMIN_FEATURE_ENABLEMENT_AND_RISK_REGISTER.md).

## 2. Build from zero

### 2.1 Prerequisites

- Git.
- Rust stable toolchain and Cargo.
- For the operator console: Node.js 20 or newer (check the console package instructions/scripts).
- For database/migration validation: PostgreSQL tooling only when running the documented SQL integration checks.
- For lab validation: isolated, explicitly authorised test devices. Do not enrol employee or production devices during development.

### 2.2 Obtain source

```sh
git clone https://github.com/asifshadab33/UJANI-ENTERPRISE-AI.git
cd UJANI-ENTERPRISE-AI
```

### 2.3 Validate the Rust workspace

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
```

### 2.4 Validate the operator console

The static operator console lives under `apps/operator-console`. Read its [README](../apps/operator-console/README.md) and inspect its declared scripts before running commands:

```sh
cd apps/operator-console
npm ci
npm run
```

Run the documented validation/test script(s) for the checked-out revision. Do not assume a local preview is a live service: the console intentionally shows no live tenant/device data until a real authenticated API and repository are deployed.

### 2.5 Database/migration work

Migration files are in `migrations/`. Review the intended migration order, role privileges, RLS policies, transaction assumptions and rollback/recovery plan before applying anything. Use a disposable local database for development. Never point a test migration at a customer database.

Example inspection only:

```sh
ls migrations
```

Do not run production migrations without customer change approval, backup, tested restore and a reviewed maintenance plan.

## 3. System architecture and trust boundaries

Intended control path:

1. Organisation identity provider authenticates an operator.
2. A trusted hosting adapter maps identity, tenant and role to a short-lived session.
3. The service authenticates that session and derives tenant identity server-side.
4. A tenant-isolated repository supplies minimum necessary device, model, telemetry, lease and policy metadata.
5. Policy checks validate device enrolment, owner consent, administrator approval, freshness, resource budgets, workload scope and revocation.
6. A future worker independently verifies signed assignments and re-evaluates current policy before any execution.
7. Signed receipts and tamper-evident audit events record outcomes.

The repository currently contains policy/service foundations and a read-only console, not the complete deployed chain. See [Operator Control Plane](OPERATOR-CONTROL-PLANE.md), [Device Trust Integration](DEVICE-TRUST-SERVICE-INTEGRATION.md) and [Threat Model](THREAT-MODEL.md).

**Non-negotiable:** no device is used without explicit authorisation; no sleeping device is awakened; no remote execution, arbitrary shell, hidden employee monitoring or automatic containment is enabled.

## 4. Repository map

| Path | Purpose |
|---|---|
| `crates/ujani-enterprise-policy/` | Rust policy, contracts, service-core and persistence abstractions |
| `crates/ujani-enterprise-policy/src/` | Policy modules, validators, inventory, trust, leases and service logic |
| `crates/ujani-enterprise-policy/tests/` | Rust integration and regression tests |
| `apps/operator-console/` | Read-only operator web console |
| `apps/operator-console/tests/` | Console regression tests |
| `catalogs/` | Curated model catalogue |
| `schemas/` | Versioned API, inventory, security and workload schemas/test vectors |
| `migrations/` | PostgreSQL schema and transaction-function migrations |
| `scripts/` | Read-only connectors, ingestion prototypes, validators and SQL test runners |
| `tests/` | Python/script-level integration tests |
| `docs/` | Architecture, trust, operations, security and deployment contracts |
| `.github/workflows/` | CI, CodeQL, dependency and security workflows |

Inspect the exact checkout rather than relying on a static map:

```sh
git ls-files
find crates apps schemas migrations scripts tests docs .github/workflows -maxdepth 3 -type f | sort
```

## 5. Policy, service and database operation index

This project is not a traditional CLI application with a stable end-user command suite. Its primary operations are typed Rust policy/service APIs, static-console actions, scripts and database migrations. The authoritative entry points are:

- Rust workspace and crate modules: `Cargo.toml`, `crates/ujani-enterprise-policy/Cargo.toml`, `crates/ujani-enterprise-policy/src/`.
- Operator service contract: [OPERATOR-CONTROL-PLANE.md](OPERATOR-CONTROL-PLANE.md).
- Device trust: [DEVICE-TRUST-SERVICE-INTEGRATION.md](DEVICE-TRUST-SERVICE-INTEGRATION.md).
- Model inventory: [ENTERPRISE-MODEL-INVENTORY-INGESTION.md](ENTERPRISE-MODEL-INVENTORY-INGESTION.md).
- Reservation/lease semantics: [DURABLE_RESERVATION_LEDGER.md](DURABLE_RESERVATION_LEDGER.md), [ATOMIC-ADMISSION-TRANSACTION-CONTRACT.md](ATOMIC-ADMISSION-TRANSACTION-CONTRACT.md).
- Database schema and functions: `migrations/*.sql`; each migration's comments and matching scripts define the current contract.

To list public Rust functions/types and tests, inspect the source and generated Rust documentation:

```sh
cargo doc --workspace --no-deps
```

To inspect available crate features and targets:

```sh
cargo metadata --no-deps --format-version 1
```

Do not expose internal policy methods as HTTP endpoints simply because they are public Rust functions. A network adapter must add authentication, tenant binding, authorization, request limits, audit and replay protection.

### Change checklist for a new operation

1. Define a versioned input/output contract and bounded payload sizes.
2. Identify tenant, device, user and administrator authorities.
3. Require owner consent and administrator approval where applicable.
4. Validate signatures, digest, freshness, nonce, revocation and policy version.
5. Enforce tenant scoping in the repository query/database itself.
6. Define idempotency, replay, timeout, cancellation and recovery semantics.
7. Add negative tests for cross-tenant, stale, revoked, malformed and unauthorised inputs.
8. Add audit evidence without prompts, credentials, file paths or sensitive raw telemetry.
9. Update schema/docs/migrations and test upgrade/rollback on a disposable database.
10. Do not dispatch or execute work until worker-side validation and OS isolation are implemented and independently reviewed.

## 6. Model inventory and resource coordination

- [Model runtime inventory v2](MODEL-RUNTIME-INVENTORY-V2.md)
- [Enterprise model inventory ingestion](ENTERPRISE-MODEL-INVENTORY-INGESTION.md)
- [Operator model inventory](OPERATOR-MODEL-RUNTIME-INVENTORY.md)
- [Adaptive resource allocation](ADAPTIVE-RESOURCE-ALLOCATION.md)
- [Durable reservation ledger](DURABLE_RESERVATION_LEDGER.md)
- [CPU-only inference adapter](CPU-ONLY-INFERENCE-ADAPTER.md)

Keep these states separate:
- Registered device is not necessarily trusted.
- Trusted device is not necessarily online.
- Online device with stale telemetry is not schedulable.
- Signed inventory is an authenticated assertion, not proof that hardware measurements are physically truthful.
- Model task labels are not verified model capabilities.
- Estimated RAM/performance is not a guarantee.
- Fleet-wide RAM is not one pooled memory allocation.

No silent model installation, runtime start, workload dispatch or remote execution.

## 7. Operator console

The static console is under `apps/operator-console/`. Its catalogue and task filters are advisory metadata; they do not select/install a model or prove capability. The console does not become live merely because it renders sample data.

Production connectivity still requires, at minimum:
- OIDC/SAML identity integration and role mapping.
- Authenticated HTTPS service and secure session cookie handling.
- Durable tenant-isolated repository and row-level security.
- Durable append-only audit sink.
- Protected key custody, rotation and revocation.
- Fresh authenticated device inventory and telemetry.
- Browser security headers, CSRF/origin protections and rate limits.

See [Operator Control Plane](OPERATOR-CONTROL-PLANE.md) and [Operator Workflows](OPERATOR-WORKFLOWS.md).

## 8. Tests, checks and CI

Common Rust checks:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Inspect scripts before running them:

```sh
find scripts -maxdepth 1 -type f -print | sort
find apps/operator-console/tests -maxdepth 2 -type f -print | sort
```

Important test families include:
- Rust policy and integration tests.
- Operator-console JavaScript tests and static validation.
- Python tests for bounded read-only connectors and event handling.
- PostgreSQL migration, RLS, concurrency, replay and atomic admission tests.
- CI, CodeQL, dependency audit and security change watch.

Only claim a SQL test passed if it ran against the intended PostgreSQL version and exact migration set. A pure policy unit test does not prove database isolation or production transport security.

Always tie workflow results to the exact commit SHA under review. Inspect failed logs; never disable a test, advisory or security gate to obtain green CI.

## 9. Troubleshooting and incident handling

| Symptom | Checks and safe response |
|---|---|
| Operator console shows no live devices | Expected until an authenticated service, tenant repository and connector are deployed. Do not insert fake device data to make the dashboard look live. |
| Operator session rejected | Check trusted identity adapter, issuer/audience, role/tenant mapping, expiry, revocation and signing-key configuration. Never accept tenant/role values from browser input. |
| Cross-tenant or stale inventory rejected | Treat as a security boundary working as designed. Inspect tenant binding, device identity, observation timestamp and revocation state. Do not weaken freshness checks. |
| Model inventory is absent | Verify device enrollment, explicit owner consent, device signature, supported schema/provider, freshness and authenticated ingestion. Never treat anonymous inventory as trusted. |
| Task/model match is unknown | Missing or stale metadata is not compatibility. Refresh evidence through the authenticated device path; do not hand-edit a positive match. |
| Lease/admission denied | Check current owner consent, administrator approval, device trust/revocation, telemetry freshness, interactive use, AC/thermal state, memory/CPU headroom, quota and active leases. Do not override policy to force a job. |
| Lease appears stuck | Inspect durable ledger state, lease expiry/revision, audit events and recovery procedure. Do not manually delete ledger rows or replay an old signed request. |
| Migration fails | Stop. Preserve logs, check database version, migration order, role grants, RLS and transaction state. Restore from a tested backup in a disposable environment before retrying. |
| Audit sink unavailable | Fail closed. Restore the durable audit service; do not bypass audit acknowledgement. |
| Connector/importer rejects a file | Check documented JSON-lines/schema/size limits and sanitised parser errors. Never feed untrusted logs into a privileged command or execute content from them. |
| CI fails on one OS | Read the exact failing job, inspect platform-specific code and add a target-specific regression test. Do not claim all-platform support from Linux-only tests. |
| Security incident suspected | Stop new workload admission, preserve protected audit evidence, revoke affected device/session credentials through the approved authority, follow the organisation's incident-response plan and investigate offline. No automated endpoint containment is implied by this prototype. |

### Incident report minimum

Record repository commit, service/build version, OS, tenant reference using an approved non-secret identifier, event time, affected device pseudonymous ID, workflow/job ID, expected/actual outcome and non-sensitive logs. Never include credentials, private keys, prompts, employee documents or raw sensitive telemetry in a public issue.

## 10. Security and deployment gates

Before a controlled pilot, complete [Release Gates](RELEASE-GATES.md) and [Controlled Lab Validation](CONTROLLED-LAB-VALIDATION-PLAN.md).

Mandatory invariants:
- Explicit organisation approval and individual owner consent.
- Trusted-device identity, revocation and replay resistance.
- Worker-side signature and policy validation before execution.
- Tenant isolation in every query and mutation.
- OS-enforced workload isolation and resource quotas.
- Default-deny network egress and scoped filesystem access.
- Visible pause/opt-out and interactive-user priority.
- Durable audit and signed result provenance.
- No wake-on-LAN, hidden monitoring, unrestricted shell or silent compute.
- No remote execution until the end-to-end security and isolation gates pass.

Collective Defence additionally requires both organisation and individual opt-in. See [Collective Defence Consent](COLLECTIVE-DEFENCE-CONSENT.md).

## 11. Change and maintenance procedure

1. Inspect both repositories' current branches, PRs, exact SHAs and workflow states.
2. Find existing issue/PR before opening new tracking.
3. Create a focused branch from the current default-branch SHA.
4. Read source, schema, tests and relevant migration before editing.
5. Add small changes with negative tests and recovery semantics.
6. Run formatting, Rust tests, console tests, script tests and relevant database checks.
7. Verify exact changed files/commit SHA on GitHub.
8. Inspect exact-head CI and failed logs.
9. Keep draft PRs open until checks/review/security gates are satisfied.
10. Never merge a change that enables execution, deployment or endpoint security action without explicit approval and completed gates.

## 12. Glossary and further reading

- **Tenant:** an organisation security and data-isolation boundary.
- **Enrolled:** device identity has been registered; this alone does not make the device trusted or schedulable.
- **Owner consent:** explicit permission from the device's individual owner.
- **Administrator approval:** organisation-level authorisation under policy.
- **Lease:** bounded, revocable reservation of a device/resource for a workload.
- **Telemetry freshness:** age and provenance of an authenticated device observation.
- **Fail closed:** deny when required evidence or authority is unavailable.
- **OS-enforced isolation:** protection implemented by the host operating system, not merely a policy flag.

Further reading: [Architecture](ARCHITECTURE.md), [Threat Model](THREAT-MODEL.md), [Security](SECURITY.md), [Time and Clock Reliability](TIME-AND-CLOCK-RELIABILITY.md), [Key Custody](KEY-CUSTODY-AND-ENCRYPTED-LEDGER.md), [Connector Status](CONNECTOR-INTEGRATION-STATUS.md) and [Release Gates](RELEASE-GATES.md).
