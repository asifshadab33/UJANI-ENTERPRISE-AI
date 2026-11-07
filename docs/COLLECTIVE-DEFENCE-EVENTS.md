# Collective cyber-defence event contract (v1)

## Purpose and scope

This is the first versioned boundary for privacy-minimised endpoint signals used by UJANI Enterprise AI to correlate suspicious activity across devices belonging to one authorised tenant. It is a data contract only: it does not implement an endpoint sensor, ingestion API, threat detector, antivirus engine or response agent.

The normative JSON Schema is [security-event-v1.schema.json](../schemas/security-event-v1.schema.json). Consumers must enable JSON Schema format assertion for `uuid` and RFC 3339 `date-time`; repository CI explicitly asserts both formats. The schema restricts sensor identifiers and sensor versions to bounded formats, and signals to a fixed categorical allowlist.

## Trust and transport requirements

A schema-valid JSON document is **not trusted** merely because it parses. Before accepting an event, a future ingestion service must:

- authenticate the enrolled device using a currently valid device identity and tenant binding;
- verify the request signature over the canonical method, resource, tenant/device identity, sequence, timestamp, body digest and replay nonce;
- reject replayed or out-of-order sequence values, expired credentials, revoked keys, tenant substitution and stale/future timestamps;
- enforce receiver-side authorization, payload-size limits, rate limits and bounded parsing;
- persist an audit receipt and apply tenant retention policy.

Use the existing device-trust and authenticated-request primitives; do not create a parallel weaker identity system. A client-supplied tenant or device ID is a claim to verify, not an authority.

## Privacy constraints

- Never send file contents, document contents, credentials, tokens, raw command lines, memory dumps or unrestricted process arguments in this event format.
- Do not send raw usernames, home-directory paths, full file paths, email addresses or personal identifiers by default.
- Prefer bounded categorical signals, hashes/fingerprints and pseudonymous identifiers. Sensor IDs, sensor versions, and signal names are allowlisted or pattern-constrained; free-form command text is not accepted in source metadata. Hashes can still be sensitive or linkable; protect them as security data.
- Treat `evidence.indicator_domain` as sensitive and potentially linkable: it can reveal visited sites, and arbitrary subdomain labels can carry covert data. Include it only when strictly necessary for an approved security indicator. Receivers must normalize/allowlist domains, restrict access and retention, and avoid exposing values in general telemetry or broad logs. Prefer registered-domain or hash-based indicators in a future schema version.
- Tenant-private storage is the default. Cross-tenant exchange requires separate explicit policy, governance, provenance and opt-in.
- Apply purpose limitation, access logging, encryption, retention limits and deletion workflows.

## Detection and poisoning resistance

Events are observations, not verdicts. A single endpoint cannot declare another endpoint compromised or issue a response command. Correlation must combine independent signals, freshness, provenance, device trust and confidence; detect duplicate/replayed/contradictory reports; and retain explainable evidence. Treat a compromised sensor as an expected threat-model case.

## Response boundary

Version 1 is read-only telemetry. It contains no command, executable payload, arbitrary URL action, remediation instruction or remote-execution field. Alerts may be presented to an analyst. Network isolation, session revocation or blocking must be a separate, receiver-authorized workflow with RBAC, scoped approval, idempotency, expiry/rollback and durable audit. Fleet-wide or destructive autonomous action is out of scope.

## Versioning

Additive optional fields may be introduced only when old consumers safely ignore them; this schema currently rejects unknown fields, so introduce a new compatible schema version or coordinated migration rather than silently widening the contract. Breaking changes require a new major schema version and explicit compatibility tests.
