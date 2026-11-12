# UJANI Enterprise AI — code and release-readiness audit (12 November 2026)

## Confirmed architectural boundaries

- Enterprise model catalogue and customer-facing model profiles are descriptive/read-only; catalogue visibility does not install or distribute models.
- Administrator model approval and individual device-owner consent are separate requirements.
- The merged HTTP route contract is transport-neutral and contains no workload execution or arbitrary command route.
- Existing trusted-device, authenticated lease and reservation policy primitives remain separate from model selection.
- Remote execution and dispatch are not enabled by the model catalogue or route contract.

## Release blockers / work still required

1. **Production control plane:** merged PR #147 defines a fail-closed route contract only. It is not a running TLS HTTP service, OIDC adapter, production device-signature verifier, durable SQL-backed repository or production audit pipeline.
2. **Lease and telemetry hardening:** PR #148 merged at `b17648503875b6e3b677dcd335b2783b0aac1bc9`. Its exact PR-head CI (`43227088557`), CodeQL (`43227088389`), RustSec (`43227088372`) and security-sensitive change watch (`43227088777`) all passed on `5ed25ee0df23b703a5fbc5f79661c79b4a8e7ca4`; post-merge main CI (`43227645555`), CodeQL (`43227645341`) and RustSec (`43227645488`) also passed on `b17648503875b6e3b677dcd335b2783b0aac1bc9`. Four historical hard-coded-nonce CodeQL review threads and both route review threads are resolved; the nonce threads are outdated. Remaining limits are explicit: registry-path serialization is single-host, the trust-registry replay nonce and ledger reservation are not one cross-store transaction, and immediate cancellation of an active lease after owner opt-out still needs a unified registry/lease/audit transaction. A production host adapter, external-anchor provider and customer multi-host validation remain outstanding.
3. **Tenant model policy:** PR #150 merged at `ad31df7bed3e3da3eace67b802424312a7e52bec` and adds advisory fleet recommendations only. It does not implement authenticated tenant allowlist persistence, exact artifact pinning, admin approval controls or managed distribution. Keep the UI read-only until those services exist.
4. **Artifact provenance:** enterprise model distribution must pin publisher, exact version, quantisation, digest, licence and download bytes; customer-controlled mirrors must be verified. Do not infer integrity from a model name or runtime inventory.
5. **Hardware admission:** fleet tiers are advisory. Every device needs fresh RAM, free-storage and runtime observations; unknown/stale evidence must fail closed for distribution/admission. Inventory is not hardware attestation.
6. **Consent and trust:** administrator approval never substitutes for device-owner consent. Model approval/presence does not grant workload permission, lease admission or remote execution.
7. **Customer validation:** complete customer-hosted tenant-isolation tests, multi-device concurrency, consent/opt-out races, lease expiry/release, rollback/revocation, audit retention and operational recovery in a controlled customer lab.
8. **Security boundary:** do not add arbitrary shell, model-triggered execution, unapproved device-to-device transfer or remote execution to complete the model-management workstream.

## Required acceptance evidence before manual testing/release

- Exact-head Enterprise CI, CodeQL and RustSec pass on the latest commit.
- Tenant-isolation and authenticated control-plane integration tests pass.
- Fresh owner-consent and lease race tests pass.
- Model allowlist, digest pinning, licence acceptance, internal distribution, cancellation, rollback and metadata-only audit tests pass.
- Customer lab validates stale telemetry, denied devices, opt-out, key rotation and failed artifact verification.
- Deployment evidence covers TLS, OIDC, protected key storage, durable repositories, backups and audit persistence.
- Remote execution remains disabled until a separate security design and customer acceptance gate is completed.

## Audit conclusion

Enterprise has a sound separation between model catalogue, device trust and workload admission, but the customer model-policy/distribution services and production control plane are not complete. The current model UI is informational only. Do not call Enterprise production-ready or enable remote execution until the listed service and customer-lab evidence exists.
