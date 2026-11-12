# Enterprise fleet model recommendation policy

Enterprise AI shares the Public AI model catalogue but not its user-facing policy. There is no universal fleet model and no automatic installation.

## Recommended administrator starting profiles

| Device hardware | Suggested candidate | Minimum currently available RAM |
|---|---|---:|
| 4 GiB total or less | No model | — |
| 6 GiB total | Qwen3 0.6B | 2.5 GiB |
| 8 GiB total | Qwen3 1.7B | 3.5 GiB |
| 16 GiB total | Qwen3 4B | 6 GiB |
| 24 GiB+ total | Qwen3 8B | 10 GiB |

These are conservative planning thresholds, not guarantees. The administrator must select an approved tenant profile and exact model artifact. A device is eligible only if fresh OS memory and storage observations, runtime compatibility, digest, licence, tenant allowlist, policy and device-owner consent all pass. Unknown or stale evidence yields no recommendation. A device can always remain model-free.

Ollama is the recommended optional runtime for supported desktop systems where the customer elects to use it. It is not a model, is not bundled with UJANI, and is not assumed on mobile. Customers may select a different validated runtime through a future typed adapter.

## Governance requirements

- Tenant allowlist pins model ID, publisher, exact version/digest, quantisation, licence and runtime.
- Per-device recommendations are restricted to the tenant allowlist.
- Administrator approval does not replace device-owner consent.
- Catalogue visibility does not trigger installation or distribution.
- Managed distribution requires authenticated policy services, verified artifact source/digest, bounded storage/network scheduling, cancellation and rollback.
- Model approval or presence does not authorize remote execution or workload dispatch.
- Audit records are metadata-only; never store prompts or document contents.
