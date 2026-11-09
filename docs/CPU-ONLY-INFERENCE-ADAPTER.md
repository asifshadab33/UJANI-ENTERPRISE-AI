# CPU-only inference and worker integration profile

**Status:** deployment design and admission-policy integration. This document does not claim a LocalAI adapter, worker agent, inference gateway, task queue or production scheduler is implemented.

## Purpose

Add CPU-only inference as an optional Enterprise worker capability. Keep the existing UJANI policy and lease system as the authority for placement. An inference engine is an interchangeable provider, not the scheduler and not a trust authority.

## Component decisions

| Component | Decision | Reason / boundary |
|---|---|---|
| Existing Ollama runtime | Retain where already deployed | Avoid forcing customers to migrate working local inference. |
| LocalAI | Optional additional inference provider | MIT-licensed core, OpenAI-compatible API, CPU-capable backends. Pin a reviewed release and backend image digest. |
| Nginx | Optional gateway for larger installations | Use only for stable ingress, TLS termination or conventional HTTP routing. It must not replace UJANI capacity-aware placement. |
| Qdrant | Optional semantic retrieval service | Apache-2.0; use only for vector search. Enforce tenant filters in the trusted host. |
| Redis | Do not adopt from this blueprint by default | Redis licensing is not uniformly MIT/Apache across current releases. |
| NATS JetStream | Candidate durable message transport, not yet a dependency | Apache-2.0 server and durable streams/consumers; evaluate only if a real multi-process queue is required. |
| Existing DurableLedger | Retain for reservations and lease capabilities | It is a single-host file-backed persistence primitive, not a distributed queue or HA database. |

No new third-party runtime dependency is added by this milestone.

## CPU capacity and safe placement

The Rust policy crate exposes cpu_capacity::evaluate_cpu_placement. It accepts a trusted, authenticated and timestamped worker snapshot and a CPU/memory request. It fails closed for stale/future telemetry, powered-off devices, missing owner opt-in, interactive use, user pause, battery operation, unsafe thermal state, unauthenticated telemetry, unavailable OS isolation, invalid measurements or insufficient headroom.

CPU capacity is expressed in milli-cores (1,000 = one logical CPU's worth of quota). The worker reports the effective quota visible to its process/container/job object, not just host core count. A configurable CPU reserve protects OS/network services; the policy deliberately does not hard-code "leave two cores unused". Memory reserve is likewise configurable. The caller supplies the maximum telemetry age.

This helper only evaluates admission. It does not reserve resources, read sensors, authenticate transport, create a sandbox or enforce CPU/RAM limits. Production flow must:

1. Authenticate the enrolled device and verify telemetry freshness/signature.
2. Validate the signed workload manifest and tenant/data classification.
3. Evaluate capacity and existing policy gates.
4. Acquire the durable reservation/lease using the existing ledger.
5. Issue a short-lived signed assignment bound to device, tenant, workload, manifest digest, resource budget and policy version.
6. Revalidate on the worker immediately before launch; enforce CPU, memory, process, disk, network and wall-clock limits using OS controls.
7. Pause/terminate on interactive activity, owner pause, revocation, thermal risk, quota breach or cancellation.
8. Record bounded, tenant-scoped status and provenance; never log prompts or secrets.

A lost worker or ambiguous durable-anchor outcome must not trigger blind duplicate dispatch. Reconcile the existing lease/ledger state before retrying.

## CPU inference deployment defaults

- Use a private, authenticated network. Never expose an unauthenticated inference endpoint to the LAN or internet.
- Require TLS/mTLS or an authenticated local reverse proxy; disable redirects where credentials or request bodies could be forwarded to another host.
- Pin container tags and image digests; do not use an unpinned latest tag in a commercial deployment.
- Keep model files in a separately permissioned, read-only model directory where practical.
- Set a per-model context limit and max output-token limit based on tested RAM/latency. 4,096 tokens is a conservative starting profile, not a universal rule.
- Set a workload-specific deadline and cancellation path. Do not kill every request at one fixed 60–90 second boundary; distinguish interactive requests from batch tasks and checkpoint where supported.
- Bound request body size, queue depth, concurrency, response size and retry count.
- Use measured CPU quota and available memory, not a fixed thread count derived only from physical cores. Leave configurable system headroom and avoid CPU oversubscription.
- Use health/readiness checks and graceful shutdown; remove an unhealthy worker from placement before draining active leases.
- Do not download or pull models automatically without administrator policy, explicit storage budget and model-license review.

## Routing and queue evolution

First release: UJANI scheduler selects one authenticated worker and calls its registered inference adapter. Avoid adding Nginx in front of every two-node deployment; naive IP hashing can send unequal work to unequal CPUs and can conflict with worker-specific model availability.

Later scale-out: Nginx may provide stable ingress, TLS and health-aware upstreams, but UJANI must select the worker using measured capacity, locality, model availability and policy. A reverse proxy must not become an alternate path around tenant authorization or lease checks.

If asynchronous multi-worker recovery becomes necessary, benchmark NATS JetStream against a small durable database-backed job table. Define at-least-once delivery, idempotency keys, lease expiry, cancellation, dead-letter handling and tenant-scoped retention before selecting a queue. Do not claim exactly-once execution. The current file-backed ledger is not a distributed queue.

## Retrieval and tenant isolation

Qdrant is optional for semantic retrieval only. Ordinary file search and deterministic document indexing should not require it. Before a shared multi-tenant deployment, enforce tenant/collection boundaries, server-side payload filters, per-tenant authorization, encryption/backup/retention and adversarial cross-tenant tests. Embeddings may reveal information about source content and must inherit the source data classification.

## Model and third-party licensing

LocalAI's core MIT licence does not grant rights to every model, backend, container or downloaded asset. Track each model's publisher, exact revision, licence/terms, use restrictions, redistribution rights and checksum in the approved model registry. Do not label a model "commercial-safe" solely because it is quantized or uses GGUF.

Nginx, Qdrant and NATS must each retain their own licence notices and version/provenance records. Customer-selected providers remain separately installed unless redistribution rights are reviewed. This is engineering guidance, not legal advice.

## Acceptance tests before any worker pilot

- Stale, forged, replayed or cross-tenant telemetry is rejected.
- Owner opt-out, interactive activity, battery, thermal risk and powered-off states prevent placement.
- CPU reserve and memory reserve cannot be consumed by UJANI work.
- CPU quota reflects the actual container/job-object quota.
- Two concurrent requests cannot overbook the same capacity after lease acquisition.
- Worker disconnect, lease expiry, controller restart and cancellation recover without blind duplicate dispatch.
- A tenant cannot retrieve another tenant's model metadata, prompts, embeddings, task status or logs.
- The inference endpoint cannot be reached without authenticated transport and policy admission.
- Model pull, update and deletion require administrator policy and are auditable.
- Performance and energy comparisons use equivalent completed work and report measured versus estimated values separately.
