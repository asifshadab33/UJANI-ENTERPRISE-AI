# Organisation security-provider inventory and coordination

## Product boundary

UJANI Enterprise coordinates existing organisation-approved endpoint security products; it is not an antivirus, EDR, SIEM, firewall, quarantine service, or network-isolation product. Customers retain their existing products and operating-system controls. UJANI must not deploy agents, install products, change endpoint settings, quarantine files, or isolate networks by default.

A tenant administrator may configure an existing vendor/OS integration. The connector authenticates to that vendor using customer-controlled credentials and least-privilege scopes. Credentials remain in the customer's secret store and never enter posture records or model prompts.

## Inventory contract

The inventory domain layer accepts normalized provider observations already bound by a trusted connector to a tenant and device. It rejects cross-tenant/device records, bounds record count and identifiers, evaluates freshness, and reports provider capabilities separately from overall health.

Supported categories are malware protection, firewall, EDR, quarantine, device isolation, and security updates. Capabilities are not inferred from the product name or from an aggregate healthy state.

## Existing connector-framework integration

This inventory is a domain assessment layer, not a second connector framework. Production adapters must implement the existing `ReadOnlyConnector` contract in `crates/ujani-enterprise-policy/src/connector_contract.rs`, advertise their read-only capabilities through the existing `CapabilityRegistry`, and pass every returned `EvidencePage` through `validate_evidence_page` before normalization or display. The host remains responsible for authenticating the tenant, selecting the tenant boundary, applying least-privilege permissions and resource budgets, and recording audit events.

Map the already validated connector evidence into the inventory observation as follows:

| Existing connector evidence | Inventory meaning |
| --- | --- |
| `EvidenceRecord.tenant_id` | Must equal the authenticated tenant; never trust a tenant ID supplied by a device payload |
| `EvidenceRecord.provider_id` | Stable, configured provider identifier |
| `EvidenceRecord.observed_at_unix_ms` | Provider-health observation time |
| `EvidenceRecord.fields.category` | Explicit supported security category |
| `EvidenceRecord.fields.status` | Provider-reported health only |
| `EvidenceRecord.fields.product_identity_known` | Explicit identity evidence; do not infer from a display label |
| `EvidenceRecord.fields.capabilities` | Explicit provider-declared capability list |
| `EvidenceRecord.fields.update_status` | Separate `current`, `out_of_date`, or `unknown` update finding |
| `EvidenceRecord.fields.update_checked_at_unix_ms` | Timestamp of the update check, distinct from the health observation |
| `EvidenceRecord.fields.update_channel` | Component checked, such as antivirus intelligence, engine/platform, or firewall rules/signatures |

The connector must provide update fields only when its authenticated source actually reports them. Missing, malformed, stale, or unsupported update evidence maps to **cannot verify**, not current. An explicit out-of-date report remains a warning even when overall provider health is reported healthy. Do not add a parallel transport, credential store, connector registry, or capability registry for this feature.

## Operator-console inventory contract

The read-only operator overview may include an optional `security_provider_inventory` object conforming to `schemas/security-provider-inventory-v1.schema.json`. The console validates tenant/device-bound provider IDs, categories, status, explicit fresh/stale/unknown evidence freshness, capabilities, evidence timestamps and update posture before rendering. Stale or unknown evidence is never presented as healthy, even if the provider's last reported health was healthy. It shows the source, last observation and update recommendation. Explicit `out_of_date` findings are visually distinguished from `unverified` and `not_reported`; none are silently converted to current.

The existing Rust `OperatorOverview` contract now has an optional `security_provider_inventory` field, with tenant/device membership, freshness, update-state, identifier and response-budget validation before serialization. The hosting repository must populate it only from the authenticated tenant's existing `ReadOnlyConnector` / `EvidencePage` / `EvidenceRecord` pipeline. The new Rust `map_security_provider_evidence_page` adapter first runs the existing page validator, binds device identity from enrolled host state (never a provider field), rejects non-internal/confidential evidence, and maps stale or incomplete update evidence to unverified. The hosting repository still owns connector credentials, capability authorization, tenant-filtered storage, paging, audit and calling this mapping seam; the field remains absent until that trusted pipeline is deployed.

The console is a display surface only. If the control plane omits this optional field, the console displays **No authenticated security-provider evidence is available**. It does not query endpoints directly, install agents, invoke provider actions, change settings, quarantine files or isolate devices. The new response contract does not itself create a live connector, collector, credentials store, or ingestion service.

## Operator experience

- Show which existing provider is connected, which devices have recent observations, the source and timestamp, and which capabilities are actually exposed by the connector.
- A healthy antivirus report is not proof of current signatures, successful file scans, ransomware protection, quarantine readiness, or network isolation.
- Treat update currency as a separate security finding for both malware protection and firewalls. A provider must explicitly report whether its security intelligence/virus definitions, engine/platform, and firewall software/signature/rule feeds are current or out of date; UJANI must not infer currency from product name, version strings alone, or an aggregate healthy state.
- If the provider reports an out-of-date component, raise a visible security warning identifying the affected product/category and evidence timestamp, and direct the user/administrator to update it through the existing vendor/OS workflow. If update evidence is absent, stale, or unsupported, say **cannot verify latest updates**—never label it current.
- Compare against current vendor release information only through an authenticated, supported provider connector or authoritative update feed. Do not hard-code a supposedly latest version that will become stale.
- Missing provider: warn the operator and let the tenant choose whether to install/configure an existing free or paid product through its normal vendor/OS workflow.
- Stale, unsupported, failed, or conflicting provider: mark posture unverified and show the integration problem.
- Preserve existing products; do not recommend replacement when a working approved product already covers the required capabilities.
- Keep tenant data isolated. Do not ingest file contents, secrets, raw command lines, or unrelated personal activity.

## Incident coordination boundary

UJANI may coordinate its own trusted-device and compute-lease participation according to separately approved policy. That is not endpoint isolation. Quarantine and isolation are capabilities of the customer's existing product/OS and require an explicit, separately authorised provider action with a verifiable receipt. No remote execution or autonomous remediation is introduced by this inventory layer.

## Delivery sequence

1. Normalized tenant/device-scoped posture assessment and tests.
2. Read-only connectors for the exact security products a customer already operates, beginning with documented vendor APIs and customer-managed credentials.
3. Provider-specific freshness, scan, alert and capability mapping with integration contract tests.
4. Explicit approval/receipt flow for any action delegated to a provider.
5. Recovery and audit verification before any action workflow is enabled.
