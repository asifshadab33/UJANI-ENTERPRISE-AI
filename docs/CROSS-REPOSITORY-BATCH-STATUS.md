# Cross-repository batch status — Enterprise AI

**Evidence snapshot: 20 November 2026.** This register coordinates Enterprise feature development with UJANI Public AI without making Enterprise depend on Public. It is not a security certification.

## Current main and integration boundary

- Enterprise main: `6f37092b4e184eab1405b6cc19fce44ba4247fb4`.
- Public main at the coordinated snapshot: `2081a36cd6f21e28777fa9733cd9808f6bf45519`.
- Enterprise Model Intelligence v2 boundary clarification (#310) is merged; validator and schema/consent vector parity should be rechecked against Public at each pass.
- Enterprise inventory and capability matching are informational; inventory is not proof of device trust, owner consent, administrator approval or workload authorization.
- No live authenticated fleet inventory API/console feed, production identity integration, production key custody, or remote execution is enabled.

## Parallel batches

1. **Trust foundations (P0):** enrollment identity lifecycle, owner consent, admin authorization, key custody/rotation/revocation, tenant RBAC and durable replay. Close gaps in protected external anchoring and recovery.
2. **Read-only inventory (P1):** authenticated enrolled-device inventory and privacy-minimised telemetry; show source/confidence/freshness and unknown/stale state. No prompts, file contents, credentials, conversation history, employee activity or personal paths.
3. **Model Intelligence v2 (P1):** test empty inventory, unknown fields/capabilities, unsupported providers, stale evidence, resource mismatch, owner/admin policy conflict and revocation. Future provider descriptors may be metadata only; selectability requires a verified adapter and policy.
4. **Operator UX (P1):** continue useful read-only tenant-isolated fleet/model planning, visible evidence and demo-data labels, health/availability and audit views. Avoid duplicating the existing console.
5. **Scheduling and leases (P1):** transactional admission combining authenticated device trust, task digest, dual consent, classification, resource bounds, expiry and replay; lease renewal/release/cancel and crash/partition recovery tests. These are still service integration gaps.
6. **Isolation and receipts (P0 before remote work):** OS-enforced isolation/egress, signed verifiable execution receipts, exact output binding and ledger ingestion, rollback/recovery and independent threat review. Keep dispatch/execution disabled.
7. **Energy/resource planning (P2):** adaptive CPU/GPU/NPU, RAM, thermal, power, interactive and availability-aware planning; benchmarks against local/central/distributed baselines. Never wake sleeping devices and do not claim energy savings without equivalent-workload measurement.
8. **Release/operations (P0):** exact main SHA CI, CodeQL/dependency audits, platform tests, DB/RLS integration, backup/DR, rollback, KMS/HSM/TPM and deployment tests. Separate automated evidence from manual/physical/external validation.

## Public AI coordination

Public AI remains the independent personal-device runtime. Cross-product adapters must use the versioned contract and explicit user approval; Enterprise policy must not silently change a user's selected model or disclose prompts/private content. No cross-repo dependency should be introduced for standalone features.

## Release posture

Enterprise remains pre-alpha policy/control-plane prototype. Remote worker execution is not production-ready and remains disabled. Do not enable deployment actions, publish releases, sign artifacts or delete branches absent the required explicit authorization and verified evidence.
