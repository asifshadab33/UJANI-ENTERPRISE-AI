# Core protection and release integrity

**Status: implementation policy and maintainer checklist. This document does not mean repository rules or signing infrastructure have already been configured.**

## Protected source

- Keep `main` as the release integration branch.
- Require pull requests, passing CI and resolved review conversations before merge.
- Prohibit force pushes and branch deletion on `main`.
- Protect policy, device trust, cryptography, consent, lease/reservation, workload manifest, operator authentication, tenant isolation, audit and workflow files.
- Require independent review for changes to trust boundaries when an eligible reviewer is available. Contributors must not approve their own pull requests.
- Keep workflow permissions minimal and pin third-party actions to reviewed commit SHAs.

## Change alerts

The `security-change-watch.yml` workflow flags security-sensitive paths in pull requests. It is a review alarm, not an enforcement mechanism, security verdict or substitute for branch protection.

## Release integrity

Before any pilot distribution:

1. Sign worker/agent and control-plane release artifacts using keys held outside source control.
2. Publish SHA-256 checksums, SBOM and build provenance.
3. Verify signatures and version policy before installation or update.
4. Test rejection of unsigned, modified, expired and wrong-key artifacts.
5. Document key custody, rotation, revocation, recovery and incident response.
6. Keep preview artifacts clearly labelled and never represent them as production-ready.

## Installed agent integrity

A future worker agent must verify its signed release manifest and security-critical components. On mismatch, it must stop accepting new work, alert the operator and device owner, preserve safe diagnostics and recover only from a verified artifact. Do not allow a workload or remote controller to overwrite the agent, policy, trust store or update verifier.

## Repository settings that must be configured by an administrator

The GitHub integration used for this change can edit repository files and create pull requests, but does not expose branch-protection/ruleset administration. An administrator must configure the `main` ruleset:

- Require pull requests and passing CI.
- Block force pushes and branch deletion.
- Restrict direct pushes to `main`.
- Require independent Code Owner review when a second eligible reviewer exists.
- Restrict changes to repository rules, Actions secrets, deployment environments and release permissions.

Do not claim these settings are active until their GitHub configuration has been inspected.

## Enterprise safety boundary

No remote workload execution, device containment or employee-device participation may be enabled solely because these repository controls exist. The independent release gates remain mandatory: authenticated enrollment, revocation, worker-side assignment verification, OS-enforced isolation, egress controls, owner opt-in, administrator policy, resource quotas, durable audit, failure recovery and independent security assessment.
