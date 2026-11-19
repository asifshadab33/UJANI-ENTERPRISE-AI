# Authenticated device capacity telemetry v2

Status: implemented policy/service-core contract plus PostgreSQL admission function and CI tests. This is not yet a hosted HTTP service or a production device agent.

## Why v2 is separate

The legacy device telemetry body (schema v1) carries generation and sequence but does not bind a sample to the reservation watermark measured by the device or to the exact server-side owner-consent generation. It remains parseable for compatibility, but it must not be admitted through the new transactional service.

Schema v2 is additive on the existing POST /v1/devices/{device_id}/telemetry route. It requires:

- schema_version: 2
- reservation_revision: the device reservation watermark observed when the resource sample was measured
- consent_generation: the server-issued database owner-consent generation acknowledged after the latest owner-consent write
- the existing device ID, telemetry generation/sequence, observation time, bounded CPU/memory and thermal/power/participation fields

The body remains exact-byte signed through the existing device request envelope and v2 domain-separated manifest digest. Unknown JSON fields remain rejected. Generation, sequence, reservation revision and consent generation are bounded to JavaScript's safe-integer range. The request body remains capped at 1 MiB.

The SQL consent_generation is deliberately distinct from the durable local registry's key-bound owner-consent generation/revision. The local registry proves that owner opt-in is current for the active device key. The SQL generation is returned by the hosted owner-consent transaction and proves that the telemetry sample was created against that exact server-side consent state. Do not substitute one counter for the other.

## Admission sequence

1. The host applies TLS, bounded request-body handling, rate limits and bounded concurrency before calling the service core.
2. authenticate_device_telemetry_v2_request resolves the server-selected route, checks the exact method/resource/workload/manifest binding, hashes the unmodified body and verifies the device signature.
3. The durable device registry rechecks enrollment, active key ID/generation and explicit local owner opt-in. A v2 sample must carry both database consent generation and reservation revision.
4. DeviceTelemetryAdmissionService makes one DeviceTelemetryAdmissionRepository call while holding the durable registry lock, so local owner opt-out or key rotation cannot interleave between the final local check and database commit. The repository must use a single tenant-scoped PostgreSQL transaction and invoke ujani_control.accept_authenticated_device_telemetry_v2.
5. The database rechecks the current enrolled/trusted device, active key ID and generation, organisation approval, active owner binding, enabled owner subject, exact granted owner-consent generation, request expiry, sample freshness, monotonic telemetry generation/sequence and reservation watermark. It claims the request ID, advances the device telemetry watermark, inserts the bounded sample and appends an audit receipt in the same transaction.
6. A replay, stale/future sample, changed key/consent/approval, invalid watermark or capacity-state mismatch returns a generic admission rejection. Any failure after the replay claim aborts the statement transaction, rolling back the replay row, watermark, sample and audit receipt together.

The repository must derive tenant/device/key identity from the authenticated principal, not JSON. It sets the transaction-local ujani.tenant_id from the authenticated tenant, uses parameterized SQL, and applies bounded connection, lock and statement timeouts. It must not call back into the durable registry while the registry lock is held. The signed request expiry is passed in milliseconds and rechecked against the database clock after lock acquisition and after audit append. A false database result maps to a generic conflict (409); connection, transaction or audit errors map to unavailable (503). Internal policy details must not be exposed to the device.

device_telemetry_samples.consent_generation is nullable for historical/legacy rows. New v2 rows store the exact generation. A NULL value means that the sample predates consent-generation binding; it must be displayed as unknown rather than retroactively trusted.

## Privacy and resource-use boundary

The sample contains only bounded resource availability and coarse thermal, power and participation state. It does not contain prompts, model contents, personal files, file paths, process lists, browsing history or arbitrary activity. Do not add those fields to this endpoint. The report is evidence supplied by an enrolled key, not proof that the device's sensors or agent are physically trustworthy.

The reservation watermark is a capacity-accounting boundary. It is not a command to execute work. This migration does not create reservations or leases, download models, dispatch workers or enable remote execution.

## Deployment and verification

Apply migrations/0016_authenticated_device_telemetry_v2.sql after the trust, telemetry, reservation and owner-consent migrations (0008 and 0013 are required; 0016 is independent of the optional lease-lifecycle migration 0015). The customer must provision ujani_runtime as a non-superuser, non-BYPASSRLS role that does not own the control schema/tables. The migration grants only the table/column permissions required for row locks, telemetry insertion, replay claims and audit append.

PostgreSQL CI runs scripts/test_authenticated_device_telemetry_v2.sql for dual consent, exact generations, replay, ordering, freshness, watermark rejection and audit rollback. scripts/test_authenticated_device_telemetry_v2_concurrency.sh holds one transaction while a second request races on the same generation/sequence and verifies that exactly one sample, replay claim and receipt commit.

The real Axum/Tokio listener, OIDC tenant/RBAC adapter, SQLx connection-pool repository, owner-consent acknowledgement endpoint, device agent and production deployment remain unfinished. The host must return the server-issued SQL consent generation in the owner-consent acknowledgement before a device can produce v2 telemetry. Until those pieces are implemented and independently reviewed, this contract is not a production service and must not be used to enable worker dispatch.
