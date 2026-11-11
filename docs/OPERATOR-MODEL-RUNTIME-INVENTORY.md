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
- Runtime/model arrays are bounded (16 runtimes and 512 models per device).
- Model capabilities are allowlisted. Unknown capability metadata stays unknown.
- An absent or empty inventory means "not reported"; it does not prove that a
  device has no installed models or no AI capability.

## Privacy and authority

The contract intentionally has no fields for prompts, model contents, local
paths, process lists, personal files or credentials. It is read-only operator
visibility; it does not select or replace a user's local model, authorize a
workload, reserve resources, download models or enable remote execution.

## Current implementation boundary

This PR adds the typed operator API DTO, validation, serialization and console
rendering contract. The production repository/telemetry adapter that populates
these values from authenticated device samples is not yet implemented. Until
that adapter exists, the normal repository may return an empty array. Do not
populate it from UI-supplied or unauthenticated client data.
