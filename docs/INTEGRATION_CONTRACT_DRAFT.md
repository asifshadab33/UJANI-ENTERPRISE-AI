# Personal-to-Enterprise task contract RFC (draft v1)

## Goal and product boundary

Define a narrow, optional bridge from UJANI Public AI to an organisation-controlled UJANI Enterprise service. Public AI remains independently useful on a personal device; Enterprise AI remains independently useful for organisation policy, fleet planning and approved internal workloads. Neither product requires the other to start or operate.

This RFC describes a future protocol boundary. It does not enable transport, remote dispatch, worker execution or data sharing. Remote execution remains disabled until the Enterprise safety gates pass.

## Verified current formats — not wire-compatible

| Concern | Public AI today | Enterprise AI today | Demonstrated gap |
|---|---|---|---|
| Envelope and version | `peer_protocol::TaskEnvelope`, protocol version **2** | `WorkloadManifest` schema version **1**, plus a separate signed admin-approval claim | Different messages, versions and signing domains; neither can be deserialised as the other |
| Task and sender identity | Task ID and recipient device fingerprint; no sender principal, organisation audience or signed key ID in the envelope | Workload ID and target device in approval claims; approver key ID | No common sender, tenant/audience or worker identity envelope |
| Consent | Boolean user-consent claim, signed with the envelope; narrow allow-listed scopes | Signed administrator approval; scheduler policy separately checks device-owner opt-in | No single dual-consent state machine or consent records bound to one shared task digest |
| Capabilities | Peer scopes such as `prompt.read`, `document.read`, `result.write` | Workload class/model and Enterprise capability policy; model inventory has its own capability vocabulary | Access scopes and model/task capabilities are different concepts and must remain separate fields |
| Data and privacy | Peer envelope has no data/privacy classification | Workload manifest has public/internal/confidential/restricted data classification | No shared privacy classification or mapping rule |
| Resources | Peer envelope has no CPU, memory, output or runtime budget | Workload manifest has CPU millis, memory MiB and max runtime | No common bounded resource request |
| Expiry and replay | Unix seconds; maximum task lifetime 300 seconds; 16-byte hex nonce; bounded **in-memory** replay guard | Admin approval has its own expiry; device trust and durable ledger have separate replay/sequence primitives | No common nonce/expiry semantics or single transactional replay claim for a delegated task |
| Task state | Public task engine tracks local work; peer envelope has no cross-product status stream | Enterprise ledger tracks reservations/leases; no shared task-status message | No common lifecycle, monotonic status sequence or cancellation acknowledgement |
| Receipt | Public execution receipt v3 is a local hash-chained SQLite metadata record; it is not digitally signed or externally anchored | No interoperable worker execution receipt | No signed worker/organisation-bound receipt or common output-byte verification |

### Important implementation details

- Public peer protocol v2 signs a domain-separated, length-prefixed `serde_json` representation and verifies against a trusted public key supplied out of band. The envelope contains no `key_id` or organisation audience. Its replay guard is in memory; the module comments describe persistence as a future production-adapter responsibility.
- Public receipt v3 records input/output digests, adapter/model provenance, timestamps, network evidence and outcome for supported local operations. It is not the signed receipt required for a remote task.
- Enterprise's workload manifest is a bounded scheduler input, not an authorisation grant. Its signed administrator approval binds the workload/device/class/resource limits, approver key ID, manifest digest and expiry. The durable device-trust registry is a persistence primitive that accepts externally supplied integrity material and can use an external monotonic anchor; this is not a deployed authenticated ingestion service or proof of production KMS custody.
- The shared `model-runtime-inventory-v1` schema is already byte-for-byte identical in both repositories. It is a separate, privacy-minimised capability/resource report; it must never carry prompts, files, credentials or conversation history and it does not authorise a task.

## Proposed language-neutral v1 message set

The shared draft schema is `schemas/personal-enterprise-task-contract-v1.schema.json`. It defines three strict JSON message shapes in one versioned contract:

1. **task_envelope** — task ID and schema version; sender principal/device; organisation/service audience; issue/expiry timestamps; 32-byte random base64url nonce; registered operation and version; exact payload SHA-256, byte length and media type; data and privacy classifications; named access scopes; required model/task capabilities and minimum context; CPU/memory/runtime/output limits; network-access class and explicit bounded destination allowlist; explicit user-consent record; required organisation-admin and worker-owner approvals; target-device constraint and active-enrollment requirement; Ed25519 signature and key ID.
2. **task_status** — task ID, monotonically increasing sequence, lifecycle state, policy version, user/admin/worker-owner consent state (including revocation), bounded reason code and service signature. Receivers reject stale or repeated sequence values.
3. **execution_receipt** — task/input/output digests; organisation and worker device identity; execution location; start/completion times; outcome; optional measured resource usage; references to user, administrator and device-owner consent; policy version; worker-authorised signature. A missing output digest is permitted only when no output bytes were produced.

The schema rejects unknown fields and bounds identifiers, payload size (16 MiB), collection sizes, CPU, memory, runtime (at most seven days), output size (64 MiB), nonce and signature encodings. Runtime policy should normally set a much shorter expiry: **300 seconds from issue to expiry**, matching Public's existing peer-task lifetime. The schema expresses field shape; it cannot prove relative timestamp ordering, cryptographic validity, consent authority, policy approval or resource enforcement.

## Normative security and compatibility rules

- Hash the exact payload bytes before parsing them. Reject a byte-length or SHA-256 mismatch. Never hash a re-serialized payload in place of the received bytes.
- Sign RFC 8785 JSON Canonicalization Scheme (JCS) bytes with UTF-8 and a message-type-specific domain separator. Exclude only the `signature` member from the signed object. Use Ed25519. Key ID, sender, audience, task ID, expiry, nonce, consent, classifications, scopes, capabilities and limits are all signed. Existing Public peer protocol v2 signing bytes are **not** interchangeable with this proposed profile.
- Enrol sender and worker keys out of band. Bind each key to its principal, device, organisation, allowed audience, validity interval and status. Key IDs and self-asserted device IDs are not proof of trust. Rotation and revocation must be checked at acceptance and immediately before execution.
- Require TLS with authenticated peers on every hop, or equivalent independently authenticated end-to-end encryption. Signatures and digests provide integrity, not confidentiality.
- Atomically claim task ID and nonce in durable replay storage before accepting a task. Reject duplicates across concurrent requests, restarts and recovery. Status sequence numbers must be strictly monotonic per task.
- Require the user's explicit grant for the exact task, payload digest, audience, scopes, classifications and resource limits. Enterprise must independently obtain administrator approval and device-owner opt-in. A task cannot become queued/running until all required authorities approve; denial, revocation, expiry or unavailable policy evidence fails closed.
- Re-evaluate current policy, device trust, owner opt-in, workload class, capability, quotas, resource headroom, network scope and expiry immediately before dispatch. Enforce CPU, memory, wall-clock, output and isolation limits at the OS boundary. Never execute shell commands or model-generated code.
- Sign receipts with a worker-authorised key. The client verifies key/organisation/device identity, task ID, input digest and policy/consent references, then hashes the exact returned output bytes and compares them with the signed output digest before consuming output.
- Keep inventory separate from task content. Enterprise inventory is accepted only from enrolled/authorised devices after required consent; share only pseudonymous model/runtime/resource metadata. Never share prompts or private content as inventory.
- Preserve standalone operation. A Public-only installation never contacts Enterprise. An Enterprise-only installation continues its own policy/fleet functions. A bridge is used only after explicit user action and organisation acceptance; there is no silent cloud fallback or background compute.

## Rollout and current status

The schema is a draft compatibility boundary, not an active protocol. Existing v2 peer envelopes, Enterprise manifests/approvals and Public local receipts must not be relabelled as interoperable v1 messages. A future adapter must explicitly translate a user-approved task into the new envelope and independently verify the Enterprise status/receipt.

Still required before any remote worker execution: cross-language canonicalisation/signature test vectors; strict duplicate-key parser tests; schema/Rust parity tests; sender/organisation/worker key enrollment and revocation; durable transactional replay; authenticated transport; atomic consent/policy/lease admission; OS-enforced isolation and egress; signed receipts and exact output verification; crash, timeout, cancellation and rollback recovery. No transport or remote execution is enabled by this RFC.
