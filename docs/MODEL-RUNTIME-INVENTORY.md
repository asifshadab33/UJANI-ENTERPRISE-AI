# Model and Runtime Inventory for Enterprise AI (v1)

Enterprise AI uses model/runtime inventory to understand which already-authorised organisational devices can support approved internal workloads. It extends the same metadata contract used by UJANI Public AI; it does not turn Enterprise into a model host or remote-execution agent.

## Intended operator value

- See which enrolled devices report supported runtimes and installed models.
- Match approved workload capability requirements (for example chat, coding, vision or embeddings) to observed device resources.
- Distinguish installed models from downloadable catalogue entries and unknown availability.
- Plan around CPU, RAM, accelerator memory and runtime compatibility without waking sleeping devices or displacing interactive users.
- Prefer existing internal compute where policy, locality, consent, resource headroom and energy considerations support it.

## Trust and privacy boundary

- Accept inventory only from an authenticated, enrolled device through a future trusted ingestion service. The JSON schema validates shape; it does not authenticate a sender or prove measurements are true.
- Require both administrator approval and device-owner opt-in before collecting or using device inventory for resource participation. Revocation must stop future collection/use.
- Share only the minimum metadata needed for capability and resource planning. Never collect prompts, conversation history, user files, credentials, arbitrary local paths or personal activity.
- Treat device-reported hardware/runtime/model metadata as assertions from an enrolled agent, not independently verified physical facts. Preserve provenance, confidence and freshness.
- Do not infer GPU/NPU availability from a device name or model catalogue. Unknown remains unknown.
- Inventory is not an admission decision, lease, workload approval or execution receipt.
- No model downloads, remote runtime starts, job dispatch, remote execution or network exposure are enabled by this contract.

## Contract and integration

schemas/model-runtime-inventory-v1.schema.json is intentionally identical to the Public AI v1 schema. A fleet device may reference one inventory snapshot using its pseudonymous device_ref. The current fleet-inventory schema remains unchanged until an authenticated ingestion path and retention policy are implemented and reviewed.

The schema rejects unknown fields and bounds collection sizes. Evolving the meaning or adding incompatible fields requires a new schema version and compatibility tests.

## Implementation status

The shared v1 JSON Schema remains byte-for-byte identical to the Public AI v1 schema. Enterprise now also has a typed, side-effect-free policy module in `crates/ujani-enterprise-policy/src/model_inventory.rs`. It adds bounded metadata validation, duplicate/reference checks, freshness and evidence checks, privacy assertions, and advisory per-model task-capability matching.

The matcher returns **Compatible**, **Incompatible** or **Unknown**. It requires an already-installed model and an available runtime; it never treats stale/unknown evidence as a positive match. Estimated memory is considered only when a task asks for a memory fit; an estimate that appears to fit is explicitly reported as **Unknown**, not as a verified fit. The result is not an admission decision and must still be combined with authenticated device trust, both consent authorities, fresh telemetry, power/thermal/interactive-use policy, quotas and durable reservations.

The module is not an ingestion endpoint and does not authenticate a sender. A future receiver must authenticate the enrolled device and tenant before parsing/accepting the snapshot, enforce monotonic generation/sequence and replay protection transactionally, then validate this contract. It does not implement a live agent, persistent model inventory, operator GUI integration, runtime discovery, model downloads, scheduler dispatch or execution.
