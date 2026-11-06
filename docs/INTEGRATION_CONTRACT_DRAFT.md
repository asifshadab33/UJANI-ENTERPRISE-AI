# Personal-to-Enterprise integration RFC (draft)

## Goal

Define a narrow bridge where UJANI Public AI can submit a user-approved task to
an organisation-controlled UJANI Enterprise service. The user keeps control of
their personal client; the organisation keeps control of enrolled devices,
data policy, approvals, quotas and audit records.

## Required protocol properties

1. Versioned envelope with strict unknown-field rejection.
2. Globally unique task ID, sender identity, target organisation/audience,
   issued-at and short expiry timestamps, and a cryptographically random nonce.
3. Registered operation ID only; never a shell command or arbitrary executable.
4. Digest of the exact payload bytes and a maximum payload size.
5. Explicit data classification and minimal named access scopes.
6. User consent bound to the exact task, payload digest, destination audience
   and requested scopes.
7. Ed25519 signature over a domain-separated, canonical, length-prefixed
   encoding; key ID and audience must be signed.
8. Receiver-side key enrollment/revocation, strict signature verification,
   replay protection that survives process restarts, and worker-side policy
   re-evaluation before execution.
9. Signed result receipt containing task ID, payload digest, worker identity,
   execution location, timestamps, status and output digest.

## Compatibility and status

UJANI Public AI currently has a version-1 signed task-envelope foundation with
short expiry, nonce, payload digest, registered operation, consent and narrow
scopes. Its verification currently depends on an already trusted public key
provided out of band and an in-memory replay guard. UJANI Enterprise has a
separate signed administrator-approval contract; that is not the same protocol.

This RFC proposes the additional audience, sender/key identity, durable replay,
worker revalidation and receipt requirements for a future interoperable
version. No Public-to-Enterprise transport or identity federation is implemented
by this document. Do not treat the two existing cryptographic structures as
wire-compatible.
