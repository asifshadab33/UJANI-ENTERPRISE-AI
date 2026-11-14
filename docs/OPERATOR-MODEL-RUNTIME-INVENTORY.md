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
