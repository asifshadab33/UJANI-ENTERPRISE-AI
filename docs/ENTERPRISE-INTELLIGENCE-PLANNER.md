# UJANI Enterprise Intelligence Planner

**Status:** design specification; no runtime integration is claimed by this document.  
**Tracking:** [Issue #53](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/issues/53). Related to the capability registry and read-only connector work in [PR #49](https://github.com/asifshadab33/UJANI-ENTERPRISE-AI/pull/49).

## 1. Product intent

UJANI Enterprise is an organisation-governed intelligent coordinator for existing calendars, collaboration products, task systems and workflow engines. It normalises approved work commitments and presents a user's daily/weekly plan. It does not replace Outlook, Zoom, project-management products, workflow automation or identity systems.

This is not an employee-surveillance product. The feature is optional, governed by organisation policy and separately authorised by each user for their own account scopes. Personal reminders must not become manager-visible merely because the user is an employee.

UJANI cannot read every installed application. It supports only documented APIs and explicitly configured connectors with known permission and data boundaries.

## 2. User experience and roles

- **Individual user:** connects permitted sources, selects scopes, reviews suggested commitments, manages personal reminders and controls briefing preferences.
- **Tenant administrator:** enables the feature, allowlists providers, configures permitted data classes, retention, regions, roles and audit policy. Cannot silently consent on behalf of an individual.
- **Manager/team view:** only explicitly shared work commitments and team-level project/calendar data allowed by policy; no personal reminders, private email content or hidden productivity score.
- **Auditor/security administrator:** sees consent, connector health, access and policy audit metadata, not unrestricted source content.

The UI should show connected providers, user/tenant permission state, last sync, provenance, freshness, data retained, errors and revocation/deletion controls.

## 3. Reuse existing Enterprise architecture

Use the existing tenant-scoped capability registry and versioned read-only connector/evidence contract from PR #49, after verifying its merged/current state. Reuse identity, tenant context, policy, durable consent, audit, secret-management and approval services as they become production-ready.

Do not create a parallel plugin registry, scheduler, consent database or event store. Do not treat an in-memory reference consent authority as production authority. Until durable consent, authenticated ingestion and tenant isolation are verified, keep the planner at specification/prototype stage.

```text
Tenant policy + authenticated user identity
  -> dual organisation/user consent and scope gate
  -> existing capability registry / read-only connector contract
  -> approved provider adapters
  -> bounded, tenant-scoped commitment evidence
  -> deterministic daily planner
  -> optional AI explanation / summarisation
  -> user-specific briefing and approved shared team views
  -> audit and retention controls
```

## 4. Candidate integrations

| Source | Initial use | Boundary |
|---|---|---|
| Microsoft 365 / Outlook | User calendar; selected mail query only if separately authorised | Microsoft Graph delegated scopes, tenant policy and per-user consent |
| Google Workspace | Calendar and approved task/mail scopes | Provider OAuth, tenant allowlist and per-user consent |
| Zoom | Meeting metadata and user-authorised preparation context | Documented OAuth/API; no transcript ingestion by default |
| CalDAV | Approved calendar event metadata | Read-only account scope |
| Task/project systems | Assigned tasks, due dates, project milestones | Provider-native least-privilege API |
| MCP / workflow platform | Explicitly allowlisted typed tools or read-only resources | Capability declaration, tenant policy, bounded schemas and audit |

Prefer native provider scheduling/workflow features where they are sufficient. UJANI coordinates and explains; it does not bundle a heavy automation engine or run a permanent agent loop.

### External software evaluation

- **[DailyOS](https://github.com/stadimeti19/DailyOS)** (MIT, early beta) is a useful local-first reference. Its repository currently marks Gmail and Google Calendar integrations as implemented but warns that live-account integration is not yet fully validated; weekday morning schedules require an explicit foreground worker, and native OS keychain support/additional providers remain planned. Evaluate it only as an optional bridge/reference; do not transplant its single-user assumptions into the Enterprise control plane. Its README describes a CLI/local SQLite application; no stable UJANI-facing connector API is established there, so do not couple to its internal database or claim a direct integration until an upstream-supported interface is verified.
- **[Open Assistant](https://open-assistant.org/)** is published under BSL 1.1; commercial reuse or distribution needs a separate licence agreement. It may be recommended as an independently installed product only after the customer's own licence and data-handling review.
- **[n8n](https://n8n.io/)** uses a Sustainable Use License. It may be suitable as an independently operated customer workflow system in some configurations, but customer-facing workflow building/configuration through an embedded UI, API, MCP or agent requires a commercial licence under its official FAQ. Do not bundle, host or expose workflow authoring from UJANI without written licence clearance.
- Prefer documented provider APIs, CalDAV and narrowly scoped MCP contracts. A connector must be independently disableable and must not bypass tenant policy.

Third-party availability, licensing and provider API support must be rechecked before a production integration. A product recommendation does not imply UJANI has installed, authenticated or enabled it.

## 5. Tenant security and consent

- Tenant administrator enables the capability and defines allowed providers/data classes; the individual user separately authorises their account and selected scopes.
- Enforce authenticated identity and tenant context server-side. Never trust a client-supplied tenant identifier.
- Both organisation policy and individual consent are required for personal source ingestion. Consent is versioned, purpose-bound, time-aware and revocable.
- Use delegated OAuth and least privilege; store credentials in the approved secret manager. TLS verification is mandatory; no credentials in URLs/logs.
- Every connector declares tenant, principal, provider, capability, schema version, scope, resource budgets, provenance and freshness.
- Bound query windows, page counts, response bytes, event counts, timeouts, retries and polling frequency.
- Persist minimal structured commitments and source references. No full mailbox, email bodies, attachments, meeting transcripts or recordings by default.
- Provider content is untrusted evidence. It cannot alter policies, expand scope, invoke tools or authorise actions.
- Revocation stops future access, invalidates credentials where supported and triggers deletion/expiry of derived cached records under documented retention rules.
- No cross-tenant sharing, no transfer to Public AI, no hidden personal data access and no manager access to private reminders.
- No remote execution, endpoint control, auto-send, calendar mutation or autonomous workflow action in MVP. Future writes require exact user approval and any required tenant approval, idempotency, audit and rollback.

## 6. Commitment evidence model

A planner item should be a typed record, not an arbitrary model-generated string:
- stable internal ID and tenant ID;
- source provider, source record reference and adapter version;
- principal/owner and visibility classification;
- kind: event, task, deadline, follow-up, reminder or proposal;
- bounded title/summary, original due-date wording where needed;
- start/due timestamps plus IANA timezone;
- confidence, confirmation state and freshness;
- created/observed/updated timestamps;
- consent/purpose reference and retention expiry.

Tenant ID must be derived from authenticated server context. Reject cross-tenant references, duplicate IDs, oversized fields, implausible future timestamps and unsupported schema versions. Unknown or stale evidence remains visibly unknown/stale and is never represented as confirmed.

## 7. Planning behavior

Use deterministic scheduling for timezones, recurrence, duplicate reconciliation, conflict detection and priority rules. AI may summarise or explain approved evidence but cannot authorise provider access or actions.

- Personal briefings remain private to the user.
- Shared team plans include only items explicitly marked shareable under tenant policy.
- Priority explanations cite source references and distinguish confirmed deadlines from inferred suggestions.
- User confirmation is required before an email-derived or document-derived candidate becomes a reminder.
- Fixed meetings are not moved automatically; proposed time blocks remain proposals.
- Provider outages produce partial results and explicit freshness warnings.

## 8. Delivery sequence

1. Validate commitment/evidence schema against existing connector contract; no duplicate persistence layer.
2. Add a read-only calendar adapter using tenant policy, authenticated per-user OAuth and dual consent.
3. Add approved task/project connectors and Zoom meeting metadata.
4. Add optional user-authorised email-derived follow-ups and renewal suggestions with confirmation.
5. Add reminder delivery alongside user-specific daily briefings and carefully scoped team views.
6. Add external planner/workflow bridges only after licence, security and operational review.

## 9. Test and release gates

Required tests include:
- tenant spoofing and cross-tenant reference rejection;
- organisation policy and individual consent independently enforced;
- consent revocation, stale consent, concurrent changes and audit integrity;
- token expiry, provider outage, partial results, pagination/rate limits and timeouts;
- duplicate events, timezone/DST, stale/future timestamps and schema compatibility;
- prompt injection from email, calendar, documents and connector output;
- private reminders excluded from manager/team views;
- no provider write operations in MVP;
- retention/deletion, secret redaction and bounded resource use;
- accessibility, role-based UI and audit review.

No production rollout until durable consent, authenticated connector ingestion, tenant isolation, secret management, audit retention and independent security review are complete.

## 10. Non-goals for MVP

No employee surveillance, productivity scoring, unrestricted mailbox ingestion, meeting recording/transcript capture, endpoint monitoring, cross-tenant data exchange, automatic messaging, calendar mutation, remote execution or autonomous workflow writes.

## 11. Implementation status

This file is a design specification only. It does not claim that provider adapters, OAuth flows, durable consent integration, evidence persistence, scheduler, UI or briefing delivery are implemented.