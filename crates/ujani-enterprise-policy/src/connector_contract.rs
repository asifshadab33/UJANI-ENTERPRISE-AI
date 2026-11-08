//! Versioned read-only connector contract and evidence validation.
//!
//! The trait is an integration boundary, not a network client. It does not
//! authenticate a tenant, create a transport, persist evidence or execute
//! provider actions. The host must authenticate the caller, select the tenant,
//! enforce permissions and resource budgets, and audit every invocation.

use std::collections::{BTreeMap, HashSet};

use crate::capability_registry::ProviderHealth;
use crate::DataClassification;

/// Version of the read-only connector request and evidence contract.
pub const CONNECTOR_CONTRACT_VERSION: u16 = 1;
/// Maximum number of filters accepted in one connector query.
pub const MAX_QUERY_FILTERS: usize = 16;
/// Maximum number of evidence records returned in one page.
pub const MAX_PAGE_SIZE: u16 = 100;
/// Maximum byte length of an opaque provider cursor.
pub const MAX_CURSOR_BYTES: usize = 512;
/// Maximum allowlisted fields carried by one evidence record.
pub const MAX_EVIDENCE_FIELDS: usize = 32;
/// Maximum byte length of an evidence field key.
pub const MAX_FIELD_KEY_BYTES: usize = 96;
/// Maximum byte length of an evidence field value.
pub const MAX_FIELD_VALUE_BYTES: usize = 1024;
/// Maximum byte length of a human-readable evidence summary.
pub const MAX_SUMMARY_BYTES: usize = 512;
/// Maximum byte length of a provider-local source reference.
pub const MAX_SOURCE_REF_BYTES: usize = 256;
/// Maximum future timestamp skew accepted for imported evidence.
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;

/// Static connector metadata; it is not proof of provider identity or health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorDescriptor {
    pub contract_version: u16,
    pub provider_id: String,
    pub provider_version: String,
    pub adapter_version: String,
    pub capabilities: Vec<String>,
    pub health: ProviderHealth,
}

/// Tenant-scoped, bounded request for read-only provider evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOnlyRequest {
    pub contract_version: u16,
    pub tenant_id: String,
    pub capability_id: String,
    pub filters: BTreeMap<String, String>,
    pub page_size: u16,
    /// Opaque, provider-issued cursor. The host must not interpret it.
    pub cursor: Option<String>,
}

/// Privacy-minimised evidence record returned by a read-only connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub tenant_id: String,
    pub provider_id: String,
    pub record_id: String,
    pub source_ref: String,
    pub observed_at_unix_ms: u64,
    pub data_classification: DataClassification,
    pub summary: String,
    pub fields: BTreeMap<String, String>,
}

/// One bounded page of records from a single tenant and provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePage {
    pub contract_version: u16,
    pub tenant_id: String,
    pub provider_id: String,
    pub records: Vec<EvidenceRecord>,
    pub next_cursor: Option<String>,
}

/// Fail-closed request, provider, tenant-boundary, or evidence validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorError {
    UnsupportedContractVersion,
    InvalidIdentifier,
    InvalidRequest,
    TenantBoundaryViolation,
    ProviderBoundaryViolation,
    MalformedEvidence,
    FutureEvidenceTimestamp,
    ProviderUnavailable,
    ProviderTimeout,
    RateLimited,
    Cancelled,
    PermissionDenied,
    UnsupportedCapability,
}

/// Age classification attached to each accepted evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFreshness {
    Fresh,
    Stale,
}

/// Synchronous read-only connector interface; host code owns auth, budgets, and audit.
pub trait ReadOnlyConnector: Send + Sync {
    /// Returns static adapter metadata. A host must not treat this as proof of
    /// provider identity or health; those require authenticated host checks.
    fn descriptor(&self) -> ConnectorDescriptor;

    /// Performs a read-only query. Implementations must not mutate provider state.
    fn query(&self, request: &ReadOnlyRequest) -> Result<EvidencePage, ConnectorError>;
}

/// Validates contract version, tenant/capability identifiers, filters, page size, and cursor.
pub fn validate_request(request: &ReadOnlyRequest) -> Result<(), ConnectorError> {
    if request.contract_version != CONNECTOR_CONTRACT_VERSION {
        return Err(ConnectorError::UnsupportedContractVersion);
    }
    if !valid_identifier(&request.tenant_id) || !valid_identifier(&request.capability_id) {
        return Err(ConnectorError::InvalidIdentifier);
    }
    if request.page_size == 0
        || request.page_size > MAX_PAGE_SIZE
        || request.filters.len() > MAX_QUERY_FILTERS
        || request
            .filters
            .iter()
            .any(|(key, value)| !valid_identifier(key) || value.len() > MAX_FIELD_VALUE_BYTES)
        || request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES)
    {
        return Err(ConnectorError::InvalidRequest);
    }
    Ok(())
}

/// Validate untrusted provider output before it is displayed, cached or correlated.
/// Stale records are retained with an explicit Stale marker so operators can see
/// old telemetry; future timestamps outside the permitted skew are rejected.
pub fn validate_evidence_page(
    page: &EvidencePage,
    expected_tenant_id: &str,
    expected_provider_id: &str,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<Vec<EvidenceFreshness>, ConnectorError> {
    if page.contract_version != CONNECTOR_CONTRACT_VERSION {
        return Err(ConnectorError::UnsupportedContractVersion);
    }
    if page.tenant_id != expected_tenant_id {
        return Err(ConnectorError::TenantBoundaryViolation);
    }
    if page.provider_id != expected_provider_id {
        return Err(ConnectorError::ProviderBoundaryViolation);
    }
    if page.records.len() > MAX_PAGE_SIZE as usize
        || page
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES)
    {
        return Err(ConnectorError::MalformedEvidence);
    }

    let mut record_ids = HashSet::with_capacity(page.records.len());
    let mut freshness = Vec::with_capacity(page.records.len());
    for record in &page.records {
        if record.tenant_id != expected_tenant_id {
            return Err(ConnectorError::TenantBoundaryViolation);
        }
        if record.provider_id != expected_provider_id {
            return Err(ConnectorError::ProviderBoundaryViolation);
        }
        if !valid_identifier(&record.record_id)
            || record.source_ref.is_empty()
            || record.source_ref.len() > MAX_SOURCE_REF_BYTES
            || record.summary.len() > MAX_SUMMARY_BYTES
            || record.fields.len() > MAX_EVIDENCE_FIELDS
            || record.fields.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > MAX_FIELD_KEY_BYTES
                    || value.len() > MAX_FIELD_VALUE_BYTES
            })
            || !record_ids.insert(record.record_id.as_str())
        {
            return Err(ConnectorError::MalformedEvidence);
        }
        if record.observed_at_unix_ms > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(ConnectorError::FutureEvidenceTimestamp);
        }
        freshness.push(
            if now_unix_ms.saturating_sub(record.observed_at_unix_ms) > max_age_ms {
                EvidenceFreshness::Stale
            } else {
                EvidenceFreshness::Fresh
            },
        );
    }
    Ok(freshness)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{
        validate_evidence_page, validate_request, ConnectorError, EvidenceFreshness, EvidencePage,
        EvidenceRecord, ReadOnlyRequest, CONNECTOR_CONTRACT_VERSION,
    };
    use crate::DataClassification;
    use std::collections::BTreeMap;

    fn request() -> ReadOnlyRequest {
        ReadOnlyRequest {
            contract_version: CONNECTOR_CONTRACT_VERSION,
            tenant_id: "tenant-a".into(),
            capability_id: "network.alerts.read".into(),
            filters: BTreeMap::new(),
            page_size: 25,
            cursor: None,
        }
    }

    fn record() -> EvidenceRecord {
        EvidenceRecord {
            tenant_id: "tenant-a".into(),
            provider_id: "suricata".into(),
            record_id: "alert-001".into(),
            source_ref: "eve:alert:1".into(),
            observed_at_unix_ms: 9_500,
            data_classification: DataClassification::Internal,
            summary: "Suspicious signature match".into(),
            fields: BTreeMap::new(),
        }
    }

    fn page(records: Vec<EvidenceRecord>) -> EvidencePage {
        EvidencePage {
            contract_version: CONNECTOR_CONTRACT_VERSION,
            tenant_id: "tenant-a".into(),
            provider_id: "suricata".into(),
            records,
            next_cursor: None,
        }
    }

    #[test]
    fn request_rejects_unknown_contract_versions_and_oversized_pages() {
        let mut item = request();
        item.contract_version = 2;
        assert_eq!(
            validate_request(&item),
            Err(ConnectorError::UnsupportedContractVersion)
        );
        let mut item = request();
        item.page_size = 101;
        assert_eq!(validate_request(&item), Err(ConnectorError::InvalidRequest));
    }

    #[test]
    fn request_bounds_filters_and_cursor() {
        let mut item = request();
        item.filters.insert("signature".into(), "x".repeat(1025));
        assert_eq!(validate_request(&item), Err(ConnectorError::InvalidRequest));
        let mut item = request();
        item.cursor = Some("x".repeat(513));
        assert_eq!(validate_request(&item), Err(ConnectorError::InvalidRequest));
    }

    #[test]
    fn evidence_enforces_tenant_and_provider_boundaries() {
        let mut item = page(vec![record()]);
        item.records[0].tenant_id = "tenant-b".into();
        assert_eq!(
            validate_evidence_page(&item, "tenant-a", "suricata", 10_000, 1_000),
            Err(ConnectorError::TenantBoundaryViolation)
        );
        let item = page(vec![record()]);
        assert_eq!(
            validate_evidence_page(&item, "tenant-a", "zeek", 10_000, 1_000),
            Err(ConnectorError::ProviderBoundaryViolation)
        );
    }

    #[test]
    fn stale_evidence_is_marked_and_future_timestamps_are_rejected() {
        let item = page(vec![record()]);
        assert_eq!(
            validate_evidence_page(&item, "tenant-a", "suricata", 20_000, 1_000),
            Ok(vec![EvidenceFreshness::Stale])
        );
        let mut item = page(vec![record()]);
        item.records[0].observed_at_unix_ms = 40_001;
        assert_eq!(
            validate_evidence_page(&item, "tenant-a", "suricata", 10_000, 1_000),
            Err(ConnectorError::FutureEvidenceTimestamp)
        );
    }

    #[test]
    fn duplicate_records_and_unbounded_fields_are_rejected() {
        let item = page(vec![record(), record()]);
        assert_eq!(
            validate_evidence_page(&item, "tenant-a", "suricata", 10_000, 1_000),
            Err(ConnectorError::MalformedEvidence)
        );
        let mut bad = record();
        bad.fields.insert("payload".into(), "x".repeat(1025));
        assert_eq!(
            validate_evidence_page(&page(vec![bad]), "tenant-a", "suricata", 10_000, 1_000),
            Err(ConnectorError::MalformedEvidence)
        );
    }

    #[test]
    fn unknown_future_evidence_is_not_accepted_as_current() {
        let mut bad = record();
        bad.observed_at_unix_ms = 50_000;
        assert_eq!(
            validate_evidence_page(&page(vec![bad]), "tenant-a", "suricata", 10_000, 1_000),
            Err(ConnectorError::FutureEvidenceTimestamp)
        );
    }
}
