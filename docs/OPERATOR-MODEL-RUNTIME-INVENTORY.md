# Enterprise operator model/runtime inventory contract

The operator overview v1 response may include an additive `model_inventory` array.
Each entry is scoped to one device already present in the authenticated tenant
overview and carries a bounded observation timestamp, available-memory reading,
runtime metadata and installed-model metadata.

## Admission and freshness

- The control-plane service must obtain inventory only from an authenticated
  device/telemetry adapter. The DTO does not authenticate devices or signatures.
- Inventory must refer to a device in the same tenant overview; duplicate or
  foreign device identifiers are rejected.
- Overview, inventory and evidence timestamps are bounded to the same freshness
  window. Missing timestamps or unknown evidence remain unknown, never inferred.
- Per-device arrays are bounded (16 runtimes and 512 models); one overview
  accepts at most 100,000 model rows across the fleet.
- Model capabilities are allowlisted. Unknown capability metadata stays unknown.
- The serialized overview is capped at 8 MiB. It includes only complete
  per-device snapshots that fit the budget and reports total/returned device and
  model counts plus model_inventory_status. The console displays the first
  5,120 returned rows and labels a partial_response_budget result explicitly;
  no individual device snapshot is silently truncated.
- An absent or empty inventory means "not reported"; it does not prove that a
  device has no installed models or no AI capability.

## Privacy and authority

The contract intentionally has no fields for prompts, model contents,
process lists, personal files or credentials. A device/telemetry adapter must
remove local paths from both model_ref and display_name before publishing
inventory; the operator API and console reject path-like labels as a second
boundary. It is read-only operator visibility; it does not select or replace a
user's local model, authorize a workload, reserve resources, download models or
enable remote execution.

## Current implementation boundary

Enterprise main now contains the typed operator API DTO, tenant/device scoping,
validation, bounded overview serialization and read-only console rendering for
runtime/model availability, capabilities, estimated RAM fit and evidence
freshness. The RAM comparison is an estimate, not verified task compatibility.
The task-capability matcher is not yet surfaced as a task-specific operator result
or wired to admission, reservations or leases.

The production repository/telemetry adapter that populates these values from
authenticated device samples is not yet implemented; neither is device-side
runtime/model discovery or durable inventory persistence. Until that adapter
exists, the normal repository may return an empty array. Do not populate it from
UI-supplied or unauthenticated client data.


## Operator hardware and evidence presentation

The read-only console presents reported CPU, RAM, free storage and GPU/NPU accelerator summaries alongside runtime/model rows. It shows model, runtime and accelerator evidence freshness separately. A device snapshot with hardware/runtime metadata but no model rows remains visible as a hardware-only entry; an empty accelerator list is labelled "not reported", not interpreted as proof that the device has no accelerator. RAM comparison remains an estimate and is not a verified workload-fit or admission decision.


## Read-only task-match request/response contract

The Rust operator service now has a tenant-session-derived, read-only model-task-match operation and a bounded response DTO. The v1 request and response wire shapes are defined by `schemas/operator-model-task-match-request-v1.schema.json` and `schemas/operator-model-task-match-response-v1.schema.json`; CI validates both schemas and adversarial examples. The request deliberately excludes tenant and role fields, which must come from the authenticated server-side session. The response distinguishes `compatible`, `incompatible` and `unknown`; estimated or unknown evidence cannot be represented as compatible.

This is a versioned contract and policy-service capability, **not an HTTP route or live console integration**. The route remains blocked on the authenticated self-hosted HTTP control plane, bounded request decoding, durable tenant-isolated inventory/telemetry repository and audit sink described in issue #90. No client-supplied inventory, silent model selection, model installation, lease, admission or dispatch is enabled by this contract.
