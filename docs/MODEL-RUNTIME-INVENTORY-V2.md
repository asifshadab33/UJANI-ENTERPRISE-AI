# Model/runtime capability inventory v2

## Purpose and separation

model-runtime-inventory-v2 is a language-neutral, read-only descriptor for local model discovery and organisation fleet planning. It is not a task envelope, consent grant, execution instruction, installation request, or proof that a device is physically safe to use.

- **Public AI:** discovers models already installed on the personal device, presents only evidence-backed capabilities and resource estimates, and uses the user's explicit model selection. The default remains local; inventory is not sent to Enterprise.
- **Enterprise AI:** may accept inventory only from a currently enrolled and organisation-authorised device whose owner consent is currently granted. It exposes pseudonymous capability/resource metadata for operator planning only. It does not expose prompts, user files, credentials, conversation history or local filesystem paths.
- Both applications remain independently installable and useful. A shared schema does not create a runtime dependency between them.

## Descriptor semantics

schema_version is exactly 2. Runtime IDs and provider names are open strings within strict bounds; this permits future runtimes without vendor-specific assumptions. Unknown providers and unknown capabilities may be represented, but they are never treated as supported or usable.

Platform and aggregate host-hardware measurements, every capability and metadata group, and each accelerator carry an evidence record with source, confidence and observation time. Host platform and resource facts are accepted only with fresh OS evidence; model resource estimates remain separately identified as estimates. Preserve the distinction between OS-observed facts, runtime-reported facts, signed/published catalogue claims, estimates and unknown values. Estimates must not be promoted to verified facts. Consumers apply a local freshness window to generated_at_unix_ms and each evidence timestamp; stale or future-dated evidence is not usable for placement or model selection.

Model metadata explicitly separates context length, tool use, vision and embeddings. Platform/accelerator compatibility is an evidence-qualified per-model claim. Missing compatibility remains unknown; hardware presence or model naming must not be used to infer support.

Resource estimates are advisory. Consumers compare them with current available resources and reject a model as a fit when the known requirement exceeds measured capacity. Unknown capacity does not become unlimited capacity. An inventory may validly contain no runtimes or no models; that means no model was reported, not that a model is installed or available.

## Collection and consent boundary

collection_context.scope is personal_local_only for Public AI's local inventory and organisation_enrolled for Enterprise inventory. The schema requires not_required_local_only plus not_applicable for the personal local-only case. Enterprise records must explicitly carry owner-consent and organisation-authorisation states. Only granted + authorised permits an Enterprise inventory to be exposed to operator planning. revoked, unknown, missing evidence, or conflicting states fail closed. The descriptor reports these states; it does not authenticate them. The service must bind them to enrolled device identity and current server-side consent/policy generations.

## Selection and future runtime support

A selected model_ref must resolve to exactly one currently installed model whose runtime is available, required capability is explicitly supported, compatibility is compatible, relevant evidence is fresh, and measured resource headroom satisfies the estimate. There is no silent fallback to another model. The UI must retain the user's explicit selection and explain why a model is unavailable or unsuitable.

New runtimes add a bounded runtime record and model records; they do not require changes to the shared capability vocabulary for vendor-specific metadata. A new capability or structural field requires a schema-version change, not silent addition to v2. Unknown fields are rejected so that incompatible producers cannot be mistaken for compatible consumers.

## Verification vector

schemas/test-vectors/model-runtime-inventory-v2.json is the shared reference vector. The repository validators must test: byte-identical schema/vector manifests; unknown-field rejection; unknown/future runtime providers; unknown capabilities; empty inventories; stale reports; runtime/model reference integrity; resource mismatch; owner/admin conflicts and revocation; and exact explicit model selection without fallback.

The v2 descriptor is a contract foundation. Public's current live discovery remains Ollama-specific; Enterprise's current typed matcher consumes metadata but is not a live enrolled-device inventory service or operator-console inventory view. Producer/consumer migration, live authenticated ingestion, revocation race handling and operator presentation remain separate implementation tasks. The v1 schema remains unchanged for existing consumers.

## Evidence and accelerator matching rules

Freshness is strict: an observation timestamp later than the consumer's current time is not usable, even by one millisecond. Resource-estimate evidence must have a recognised source and confidence; an `estimate` source must use `estimated` confidence. Unknown or stale estimates never establish a resource fit. The detailed `tool_use`, `vision`, and `embeddings` metadata groups must agree with the corresponding capability-list entry and carry their own fresh evidence; vision additionally requires a positive image-byte limit and at least one supported MIME type, while embeddings requires a positive dimension count.

The non-empty `required_accelerator_kinds` and `required_accelerator_apis` arrays each express alternatives. At least one evidence-qualified accelerator must match one listed kind and one listed API, when both constraints are present; the same physical accelerator must satisfy both. Accelerator memory is evaluated only on that eligible set, preventing a low-memory CUDA device from borrowing the memory of a different Vulkan device. An empty list means no constraint for that dimension.
