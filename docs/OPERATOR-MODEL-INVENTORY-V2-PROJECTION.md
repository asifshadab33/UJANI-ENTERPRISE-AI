# Operator Model/Runtime Inventory v2 Projection (Draft Contract)

**Status:** design-only draft. This document does not authorize runtime execution, workload dispatch, device scheduling, model installation, or changes to consent.

## Purpose

Expose bounded, privacy-minimised evidence from the existing Model/Runtime Inventory v2 descriptor in the Enterprise operator console. The projection must preserve evidence quality and uncertainty. It must not silently flatten the v2 descriptor into v1 or infer capability from missing/unknown facts.

## Separation of authority

- The projection is read-only, informational, tenant-scoped, and generated only for enrolled devices whose inventory is currently authorised for organisation collection.
- Inventory evidence is not device trust, consent, administrator approval, workload admission, lease, or execution authority.
- Model/task match remains advisory. The console must not offer reserve, dispatch, download, install, or execute actions from this projection.
- Public AI remains independent. Enterprise may consume shared descriptor formats but must not grant Public AI permissions or control.

## Proposed versioned response member

The overview API v1 may gain an optional, independently versioned member. Its absence means the API does not provide v2 projection; clients must not synthesize v2 facts from the v1 inventory.

```json
{
  "model_runtime_inventory_v2": {
    "projection_version": 1,
    "status": "complete",
    "generated_at_unix_ms": 0,
    "total_devices": 0,
    "returned_devices": 0,
    "total_models": 0,
    "returned_models": 0,
    "records": []
  }
}
```

The projection envelope is a proposal, not a committed API promise. Use explicit statuses: `complete`, `partial_response_budget`, `disabled_by_policy`, `unavailable`, `not_supported`. Unknown, absent, stale, or unverified evidence must remain unknown and be shown as such.

## Record contents and evidence

A device record may contain an opaque enrolled-device reference, a display-safe platform summary, bounded hardware resource estimates, runtime summaries and model summaries. Each relevant field must preserve evidence source, confidence, and observation time from the v2 descriptor. The projection must not include prompts, model weights/content, local filesystem paths, user names, process lists, API keys, raw telemetry, or employee activity.

Model and runtime records should be capped using existing schema bounds and a response budget. Truncation must be explicitly reported, counts must distinguish total from returned, and pagination/filtering must be tenant-scoped and authorized. Never silently claim completeness after truncation.

## Freshness and fit

- Freshness must be calculated against trusted control-plane time and the tenant's versioned freshness policy; do not trust the operator browser wall clock.
- Show evidence freshness independently for platform, hardware, runtime and model observations where they differ.
- Unknown/stale evidence cannot be treated as verified, compatible, or schedulable.
- Any resource-fit display is an estimate and must state assumptions and evidence sources. Do not aggregate fleet RAM as a shared pool.
- No model candidate may be automatically installed or distributed by this view.

## Console acceptance criteria

1. A v2 projection appears only when a validated, authenticated API response includes it.
2. The view labels v2 explicitly and indicates projection version.
3. Unknown, stale, estimated, reported and verified states are visually distinct and described accessibly.
4. No local paths, prompt/content, credential or user activity data are rendered.
5. Response size, record count and field length limits are enforced before rendering.
6. Demo fixtures are visibly synthetic and never appear as live data; refreshing live clears demo content first.
7. Partial responses show returned/total counts and a warning; no unsupported inference is made.
8. UI uses text-only DOM assignment (e.g. `textContent`) for untrusted values, not HTML interpolation.
9. All actions remain read-only; this projection cannot authorise model install, task matching, lease creation or dispatch.
10. Unit and integration tests cover missing, malformed, oversized, stale, unknown, partial, cross-tenant and privacy-violating projections.

## Delivery order

1. Confirm an authenticated server-side projection source and tenant policy. Do not build the browser around demo or fabricated live data.
2. Implement a bounded projection DTO and validator with schema-parity tests.
3. Add API contract tests for tenant filtering, policy-disabled/unavailable states, freshness, response-budget truncation and no sensitive fields.
4. Add console rendering and safe DOM tests against contract fixtures.
5. Independently review privacy, authorization and release gates before enabling the endpoint.

## Compatibility

The current `/api/v1/operator/overview` v1 `model_inventory` member remains unchanged. The proposed optional v2 member is additive. A missing member is not an error and must not be treated as evidence of no models.
