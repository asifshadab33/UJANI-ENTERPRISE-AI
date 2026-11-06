# Workload manifest contract (draft v1)

This contract adds a typed, versioned input shape for future control-plane and
worker-agent integrations. It is not a job queue, scheduler, transport protocol,
or authorization grant.

## Fields

| Field | Type | Validation |
|---|---|---|
| schema_version | u16 | Must equal 1 |
| workload_id | string | 1–128 ASCII identifier characters: letters, digits, dot, underscore, colon, hyphen |
| class | string | 1–64 characters using the same identifier alphabet |
| model | string | Non-empty, at most 128 bytes, no control characters |
| requested_cpu_millis | u32 | 1–1,000,000 |
| requested_memory_mb | u64 | 1–4,194,304 MiB |
| max_runtime_ms | u64 | 1–604,800,000 ms (7 days) |
| data_classification | enum | public, internal, confidential, restricted |
| network_access | bool | Explicitly declares whether network access is requested |

Unknown fields are rejected by Serde deserialization (`deny_unknown_fields`).
The Rust validation function rejects unsupported schema versions, malformed
identifiers/model names and out-of-range resource/time limits.

## Example

    {
      "schema_version": 1,
      "workload_id": "job-001",
      "class": "inference",
      "model": "qwen2.5:7b",
      "requested_cpu_millis": 2000,
      "requested_memory_mb": 4096,
      "max_runtime_ms": 60000,
      "data_classification": "internal",
      "network_access": false
    }

## Security boundary

A valid manifest is only well-formed input. It does not establish device trust,
admin approval, user consent, class authorization, data residency, resource
availability, sandboxing, or permission to execute. Admission must still combine
the manifest with enrolled device identity, current policy, signed approvals
where required, fresh telemetry and a durable reservation transaction.

The current repository has no control-plane HTTP/API deserializer or worker
agent. The manifest contract is therefore a library-level foundation, not an
active network admission endpoint.
