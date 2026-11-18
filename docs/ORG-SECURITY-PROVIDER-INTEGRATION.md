# Organisation security-provider inventory and coordination

## Product boundary

UJANI Enterprise coordinates existing organisation-approved endpoint security products; it is not an antivirus, EDR, SIEM, firewall, quarantine service, or network-isolation product. Customers retain their existing products and operating-system controls. UJANI must not deploy agents, install products, change endpoint settings, quarantine files, or isolate networks by default.

A tenant administrator may configure an existing vendor/OS integration. The connector authenticates to that vendor using customer-controlled credentials and least-privilege scopes. Credentials remain in the customer's secret store and never enter posture records or model prompts.

## Inventory contract

The inventory domain layer accepts normalized provider observations already bound by a trusted connector to a tenant and device. It rejects cross-tenant/device records, bounds record count and identifiers, evaluates freshness, and reports provider capabilities separately from overall health.

Supported categories are malware protection, firewall, EDR, quarantine, device isolation, and security updates. Capabilities are not inferred from the product name or from an aggregate healthy state.

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
