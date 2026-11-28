# Enterprise tenant-context transaction contract

Status: implementation contract for issue #353. This is not an implemented HTTP/OIDC service and does not authorize production fleet execution.

## Security invariant

A tenant ID supplied by a browser, device payload, URL, request header, SQL session setting or cache key is untrusted. The service must derive the effective tenant only from a successfully authenticated and authorized server-side principal. PostgreSQL RLS using `current_setting('ujani.tenant_id', true)` is a data-isolation control only after the service has established that trust boundary. A custom PostgreSQL GUC is session-settable and is not an independent authentication credential.

## Required request sequence

1. Accept a bounded request over the customer-approved TLS/private ingress. Reject oversized headers/body before expensive parsing.
2. Validate OIDC/device authentication: issuer, audience, signature, nonce/state, expiry, account/device status, key generation, revocation, tenant membership and required MFA/role claims. Never trust tenant or role values from the request body.
3. Construct an immutable server-side principal containing authenticated subject, tenant, roles/scopes, device identity/generation where applicable, authentication time and policy version.
4. Authorize the requested resource/action against that principal before opening a business transaction. Resolve tenant-owned resource IDs through tenant-scoped queries; do not infer ownership from caller-provided IDs.
5. Acquire a pooled connection and begin a transaction. Set transaction-local role and tenant context only from the verified principal. The intended sequence is conceptually:

   ```sql
   BEGIN;
   SET LOCAL ROLE ujani_runtime;
   SELECT set_config('ujani.tenant_id', $1, true); -- $1 from verified principal only
   -- perform tenant-scoped statements and SECURITY DEFINER calls
   COMMIT;
   ```

   Use parameter binding for the tenant value. Never interpolate SQL. Do not use session-persistent `SET` for tenant context.
6. Verify that the runtime role is least-privileged and cannot log in directly. Only the trusted service identity may assume it. End-user/device credentials must never receive database access.
7. Commit on success; rollback on every error, cancellation or panic path. The pool must not return a connection with an open transaction or tenant/role state. Transaction-local state must disappear at transaction end.
8. Emit a minimal audit event bound to the authenticated tenant and principal. Do not log bearer tokens, device secrets, prompts, document content or raw request bodies.

## Database adversarial tests

- A direct connection using the runtime role is rejected (NOLOGIN).
- An untrusted database login cannot assume `ujani_runtime`.
- A service request with tenant A credentials cannot read, mutate, or invoke consent/lease routines for tenant B even when the body, URL, header and resource identifier claim tenant B.
- A request that tampers with the tenant GUC cannot change the immutable authenticated principal; the service must overwrite the transaction-local value from verified identity before any tenant query.
- Missing identity, invalid signature, expired token, revoked key generation, missing tenant membership, role mismatch and stale policy all fail closed before the business transaction.
- A failed transaction, cancellation and pooled-connection reuse cannot leak tenant or role context into the next request.
- SECURITY DEFINER functions must have fixed safe search paths, narrow EXECUTE grants and explicit tenant binding; test direct invocation and parameter substitution.
- Test with two real concurrent pooled connections and separate tenants, not only a single-connection unit fixture.

## Operational requirements

- OIDC issuer/audience/key rotation and device trust/revocation are server-side responsibilities.
- The database service role is held only by the customer-hosted control-plane service and stored in a customer-managed secret provider.
- The customer must protect TLS termination, database network access, backups, logs, monitoring and service deployment.
- Health/readiness endpoints must not disclose tenant data or key material.
- Any unavailable identity provider, revocation source, key provider or tenant policy must fail closed for state-changing actions.
- The service must expose provenance and freshness for telemetry; stale, missing or simulated data must never appear as healthy/live.

## Release gate

Issue #353 remains open until a real authenticated service adapter is implemented, transaction setup is reviewed, the adversarial PostgreSQL tests pass, pool cleanup is verified under failure, and a customer-hosted deployment test is recorded. Until then, the migrations are database primitives, not a production tenant-authentication boundary. Keep lease dispatch, remote execution and Collective Defence actions disabled.
