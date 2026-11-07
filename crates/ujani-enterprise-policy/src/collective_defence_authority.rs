//! Transactional reference model for Collective Defence consent authority.
//!
//! This module deliberately provides an in-memory reference backend only. It is
//! useful for specifying and testing generation/CAS/audit semantics, but it is
//! NOT durable, rollback-resistant, or suitable for production sharing. A
//! production adapter must implement the same atomic contract with a durable
//! database and an external monotonic anchor before any event is transmitted.
#![forbid(unsafe_code)]

use crate::collective_defence_consent::{
    COLLECTIVE_DEFENCE_PURPOSE, MAX_CONSENT_TTL_MS, MAX_EVENT_RETENTION_SECONDS,
    SECURITY_EVENT_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

const AUDIT_DOMAIN: &[u8] = b"UJANI-COLLECTIVE-DEFENCE-CONSENT-AUDIT-V1\0";
const RECORD_DOMAIN: &[u8] = b"UJANI-COLLECTIVE-DEFENCE-CONSENT-RECORD-V1\0";
const MAX_AUDIT_RECORDS: usize = 100_000;
const MAX_IDEMPOTENCY_KEYS: usize = 100_000;

/// Fail-closed errors returned by the consent authority reference backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    InvalidIdentifier,
    InvalidPurpose,
    UnsupportedSchema,
    InvalidRetention,
    InvalidNoticeDigest,
    InvalidTimeWindow,
    InvalidGeneration,
    GenerationConflict,
    GenerationExhausted,
    IdempotencyConflict,
    CapacityExceeded,
    LockPoisoned,
    TenantNotEnabled,
    IndividualNotEnabled,
    ConsentNotCurrent,
}

/// Versioned tenant-administrator consent state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantConsentRecord {
    pub tenant_id: String,
    pub enabled: bool,
    pub generation: u64,
    pub purpose: String,
    pub schema_version: String,
    pub retention_seconds: u32,
    pub notice_version: String,
    pub notice_sha256: [u8; 32],
    pub actor_key_id: String,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Independent user consent scoped to one tenant, principal, and device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndividualConsentRecord {
    pub tenant_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub enabled: bool,
    pub tenant_generation: u64,
    pub generation: u64,
    pub purpose: String,
    pub notice_version: String,
    pub notice_sha256: [u8; 32],
    pub actor_key_id: String,
    pub updated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Append-only record describing one committed consent decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentAuditRecord {
    pub sequence: u64,
    pub event_id: [u8; 32],
    pub tenant_id: String,
    pub principal_id: Option<String>,
    pub device_id: Option<String>,
    pub action: String,
    pub previous_generation: u64,
    pub next_generation: u64,
    pub actor_key_id: String,
    pub committed_at_unix_ms: u64,
    pub previous_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

/// Pair of current tenant and individual records used for an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentSnapshot {
    pub tenant: TenantConsentRecord,
    pub individual: IndividualConsentRecord,
}

/// Backend contract. Implementations must make record mutation, audit append,
/// and idempotency outcome one atomic transaction. Production implementations
/// must additionally bind committed snapshots to an external monotonic anchor.
pub trait ConsentAuthorityBackend: Send + Sync {
    /// Persist a tenant decision if its expected generation still matches.
    fn put_tenant(
        &self,
        record: TenantConsentRecord,
        expected_generation: Option<u64>,
        idempotency_key: &str,
    ) -> Result<ConsentAuditRecord, AuthorityError>;

    /// Persist an individual decision or withdrawal using compare-and-set.
    fn put_individual(
        &self,
        record: IndividualConsentRecord,
        expected_generation: Option<u64>,
        idempotency_key: &str,
    ) -> Result<ConsentAuditRecord, AuthorityError>;

    /// Load current consent for the exact tenant, principal, and device tuple.
    fn authorization_snapshot(
        &self,
        tenant_id: &str,
        principal_id: &str,
        device_id: &str,
        now_unix_ms: u64,
    ) -> Result<ConsentSnapshot, AuthorityError>;
}

#[derive(Debug, Clone)]
struct IdempotencyOutcome {
    request_hash: [u8; 32],
    audit: ConsentAuditRecord,
}

struct AuditAppend<'a> {
    idempotency_key: &'a str,
    request_hash: [u8; 32],
    tenant_id: &'a str,
    principal_id: Option<&'a str>,
    device_id: Option<&'a str>,
    action: &'a str,
    previous_generation: u64,
    next_generation: u64,
    actor_key_id: &'a str,
    committed_at: u64,
}

#[derive(Default)]
struct State {
    tenants: HashMap<String, TenantConsentRecord>,
    individuals: HashMap<(String, String, String), IndividualConsentRecord>,
    audit: Vec<ConsentAuditRecord>,
    idempotency: HashMap<(String, String), IdempotencyOutcome>,
}

/// In-memory reference implementation. Process restart loses all state.
#[derive(Default)]
pub struct MemoryConsentAuthority {
    state: Mutex<State>,
}

/// Verify sequence numbering, hash linkage, and each record's canonical hash.
pub fn verify_audit_chain(records: &[ConsentAuditRecord]) -> bool {
    let mut previous_hash = [0u8; 32];
    for (index, record) in records.iter().enumerate() {
        let Some(expected_sequence) = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
        else {
            return false;
        };
        if record.sequence != expected_sequence
            || record.previous_hash != previous_hash
            || audit_hash(record) != record.record_hash
        {
            return false;
        }
        previous_hash = record.record_hash;
    }
    true
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-' | b'@'))
}

fn validate_tenant_record(record: &TenantConsentRecord) -> Result<(), AuthorityError> {
    if record.purpose != COLLECTIVE_DEFENCE_PURPOSE {
        return Err(AuthorityError::InvalidPurpose);
    }
    if record.schema_version != SECURITY_EVENT_SCHEMA_VERSION {
        return Err(AuthorityError::UnsupportedSchema);
    }
    if record.retention_seconds > MAX_EVENT_RETENTION_SECONDS
        || (record.enabled && record.retention_seconds == 0)
    {
        return Err(AuthorityError::InvalidRetention);
    }
    if record.notice_sha256.iter().all(|byte| *byte == 0) {
        return Err(AuthorityError::InvalidNoticeDigest);
    }
    if record.expires_at_unix_ms <= record.updated_at_unix_ms
        || record
            .expires_at_unix_ms
            .saturating_sub(record.updated_at_unix_ms)
            > MAX_CONSENT_TTL_MS
    {
        return Err(AuthorityError::InvalidTimeWindow);
    }
    Ok(())
}

fn validate_individual_record(record: &IndividualConsentRecord) -> Result<(), AuthorityError> {
    if record.purpose != COLLECTIVE_DEFENCE_PURPOSE {
        return Err(AuthorityError::InvalidPurpose);
    }
    if record.notice_sha256.iter().all(|byte| *byte == 0) {
        return Err(AuthorityError::InvalidNoticeDigest);
    }
    if record.expires_at_unix_ms <= record.updated_at_unix_ms
        || record
            .expires_at_unix_ms
            .saturating_sub(record.updated_at_unix_ms)
            > MAX_CONSENT_TTL_MS
    {
        return Err(AuthorityError::InvalidTimeWindow);
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn tenant_request_hash(record: &TenantConsentRecord, expected: Option<u64>) -> [u8; 32] {
    let mut bytes = RECORD_DOMAIN.to_vec();
    bytes.push(b'T');
    push_string(&mut bytes, &record.tenant_id);
    bytes.push(u8::from(record.enabled));
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    push_string(&mut bytes, &record.purpose);
    push_string(&mut bytes, &record.schema_version);
    bytes.extend_from_slice(&record.retention_seconds.to_be_bytes());
    push_string(&mut bytes, &record.notice_version);
    bytes.extend_from_slice(&record.notice_sha256);
    push_string(&mut bytes, &record.actor_key_id);
    bytes.extend_from_slice(&record.updated_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&record.expires_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&expected.unwrap_or(0).to_be_bytes());
    Sha256::digest(bytes).into()
}

fn individual_request_hash(record: &IndividualConsentRecord, expected: Option<u64>) -> [u8; 32] {
    let mut bytes = RECORD_DOMAIN.to_vec();
    bytes.push(b'I');
    for value in [&record.tenant_id, &record.principal_id, &record.device_id] {
        push_string(&mut bytes, value);
    }
    bytes.push(u8::from(record.enabled));
    bytes.extend_from_slice(&record.tenant_generation.to_be_bytes());
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    push_string(&mut bytes, &record.purpose);
    push_string(&mut bytes, &record.notice_version);
    bytes.extend_from_slice(&record.notice_sha256);
    push_string(&mut bytes, &record.actor_key_id);
    bytes.extend_from_slice(&record.updated_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&record.expires_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&expected.unwrap_or(0).to_be_bytes());
    Sha256::digest(bytes).into()
}

fn audit_hash(record: &ConsentAuditRecord) -> [u8; 32] {
    let mut bytes = AUDIT_DOMAIN.to_vec();
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.extend_from_slice(&record.event_id);
    push_string(&mut bytes, &record.tenant_id);
    push_string(&mut bytes, record.principal_id.as_deref().unwrap_or(""));
    push_string(&mut bytes, record.device_id.as_deref().unwrap_or(""));
    push_string(&mut bytes, &record.action);
    bytes.extend_from_slice(&record.previous_generation.to_be_bytes());
    bytes.extend_from_slice(&record.next_generation.to_be_bytes());
    push_string(&mut bytes, &record.actor_key_id);
    bytes.extend_from_slice(&record.committed_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&record.previous_hash);
    Sha256::digest(bytes).into()
}

impl MemoryConsentAuthority {
    /// Returns the reference backend's complete audit sequence for internal verification.
    ///
    /// A production API must apply tenant authorization before exposing audit records.
    pub fn audit_log(&self) -> Result<Vec<ConsentAuditRecord>, AuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| AuthorityError::LockPoisoned)?
            .audit
            .clone())
    }

    /// Loads one tenant's current record from this in-memory reference backend.
    pub fn tenant_record(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantConsentRecord>, AuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| AuthorityError::LockPoisoned)?
            .tenants
            .get(tenant_id)
            .cloned())
    }

    fn append_audit(
        state: &mut State,
        command: AuditAppend<'_>,
    ) -> Result<ConsentAuditRecord, AuthorityError> {
        let idempotency_scope = (
            command.tenant_id.to_owned(),
            command.idempotency_key.to_owned(),
        );
        if let Some(existing) = state.idempotency.get(&idempotency_scope) {
            return if existing.request_hash == command.request_hash {
                Ok(existing.audit.clone())
            } else {
                Err(AuthorityError::IdempotencyConflict)
            };
        }
        if state.audit.len() >= MAX_AUDIT_RECORDS || state.idempotency.len() >= MAX_IDEMPOTENCY_KEYS
        {
            return Err(AuthorityError::CapacityExceeded);
        }
        let sequence = u64::try_from(state.audit.len())
            .map_err(|_| AuthorityError::CapacityExceeded)?
            .checked_add(1)
            .ok_or(AuthorityError::GenerationExhausted)?;
        let previous_hash = state.audit.last().map(|a| a.record_hash).unwrap_or([0; 32]);
        let event_id: [u8; 32] = Sha256::digest(
            [
                command.request_hash.as_slice(),
                command.idempotency_key.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let mut audit = ConsentAuditRecord {
            sequence,
            event_id,
            tenant_id: command.tenant_id.to_owned(),
            principal_id: command.principal_id.map(str::to_owned),
            device_id: command.device_id.map(str::to_owned),
            action: command.action.to_owned(),
            previous_generation: command.previous_generation,
            next_generation: command.next_generation,
            actor_key_id: command.actor_key_id.to_owned(),
            committed_at_unix_ms: command.committed_at,
            previous_hash,
            record_hash: [0; 32],
        };
        audit.record_hash = audit_hash(&audit);
        state.audit.push(audit.clone());
        state.idempotency.insert(
            idempotency_scope,
            IdempotencyOutcome {
                request_hash: command.request_hash,
                audit: audit.clone(),
            },
        );
        Ok(audit)
    }
}

impl ConsentAuthorityBackend for MemoryConsentAuthority {
    fn put_tenant(
        &self,
        record: TenantConsentRecord,
        expected_generation: Option<u64>,
        idempotency_key: &str,
    ) -> Result<ConsentAuditRecord, AuthorityError> {
        if !valid_id(&record.tenant_id, 128)
            || !valid_id(&record.actor_key_id, 128)
            || !valid_id(&record.notice_version, 64)
            || idempotency_key.is_empty()
            || idempotency_key.len() > 128
        {
            return Err(AuthorityError::InvalidIdentifier);
        }
        if record.generation == 0 {
            return Err(AuthorityError::InvalidGeneration);
        }
        validate_tenant_record(&record)?;
        let request_hash = tenant_request_hash(&record, expected_generation);
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityError::LockPoisoned)?;
        if let Some(existing) = state
            .idempotency
            .get(&(record.tenant_id.clone(), idempotency_key.to_owned()))
        {
            return if existing.request_hash == request_hash {
                Ok(existing.audit.clone())
            } else {
                Err(AuthorityError::IdempotencyConflict)
            };
        }
        let current = state.tenants.get(&record.tenant_id).map(|r| r.generation);
        if current != expected_generation
            || record.generation
                != current
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(AuthorityError::GenerationExhausted)?
        {
            return Err(AuthorityError::GenerationConflict);
        }
        let audit = Self::append_audit(
            &mut state,
            AuditAppend {
                idempotency_key,
                request_hash,
                tenant_id: &record.tenant_id,
                principal_id: None,
                device_id: None,
                action: if record.enabled {
                    "tenant.enable"
                } else {
                    "tenant.disable"
                },
                previous_generation: current.unwrap_or(0),
                next_generation: record.generation,
                actor_key_id: &record.actor_key_id,
                committed_at: record.updated_at_unix_ms,
            },
        )?;
        state.tenants.insert(record.tenant_id.clone(), record);
        Ok(audit)
    }

    fn put_individual(
        &self,
        record: IndividualConsentRecord,
        expected_generation: Option<u64>,
        idempotency_key: &str,
    ) -> Result<ConsentAuditRecord, AuthorityError> {
        if !valid_id(&record.tenant_id, 128)
            || !valid_id(&record.principal_id, 128)
            || !valid_id(&record.device_id, 128)
            || !valid_id(&record.actor_key_id, 128)
            || !valid_id(&record.notice_version, 64)
            || idempotency_key.is_empty()
            || idempotency_key.len() > 128
        {
            return Err(AuthorityError::InvalidIdentifier);
        }
        if record.generation == 0 || record.tenant_generation == 0 {
            return Err(AuthorityError::InvalidGeneration);
        }
        validate_individual_record(&record)?;
        let request_hash = individual_request_hash(&record, expected_generation);
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityError::LockPoisoned)?;
        if let Some(existing) = state
            .idempotency
            .get(&(record.tenant_id.clone(), idempotency_key.to_owned()))
        {
            return if existing.request_hash == request_hash {
                Ok(existing.audit.clone())
            } else {
                Err(AuthorityError::IdempotencyConflict)
            };
        }
        let tenant = state
            .tenants
            .get(&record.tenant_id)
            .ok_or(AuthorityError::TenantNotEnabled)?;
        // A user must be able to withdraw even after the tenant disables the
        // feature. New individual opt-ins still require tenant enablement.
        if tenant.generation != record.tenant_generation || (record.enabled && !tenant.enabled) {
            return Err(AuthorityError::TenantNotEnabled);
        }
        let key = (
            record.tenant_id.clone(),
            record.principal_id.clone(),
            record.device_id.clone(),
        );
        let current = state.individuals.get(&key).map(|r| r.generation);
        if current != expected_generation
            || record.generation
                != current
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(AuthorityError::GenerationExhausted)?
        {
            return Err(AuthorityError::GenerationConflict);
        }
        let audit = Self::append_audit(
            &mut state,
            AuditAppend {
                idempotency_key,
                request_hash,
                tenant_id: &record.tenant_id,
                principal_id: Some(&record.principal_id),
                device_id: Some(&record.device_id),
                action: if record.enabled {
                    "individual.enable"
                } else {
                    "individual.withdraw"
                },
                previous_generation: current.unwrap_or(0),
                next_generation: record.generation,
                actor_key_id: &record.actor_key_id,
                committed_at: record.updated_at_unix_ms,
            },
        )?;
        state.individuals.insert(key, record);
        Ok(audit)
    }

    fn authorization_snapshot(
        &self,
        tenant_id: &str,
        principal_id: &str,
        device_id: &str,
        now: u64,
    ) -> Result<ConsentSnapshot, AuthorityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthorityError::LockPoisoned)?;
        if state.audit.len() >= MAX_AUDIT_RECORDS || state.idempotency.len() >= MAX_IDEMPOTENCY_KEYS
        {
            return Err(AuthorityError::CapacityExceeded);
        }
        let tenant = state
            .tenants
            .get(tenant_id)
            .cloned()
            .ok_or(AuthorityError::TenantNotEnabled)?;
        if !tenant.enabled || tenant.expires_at_unix_ms <= now {
            return Err(AuthorityError::TenantNotEnabled);
        }
        let key = (
            tenant_id.to_owned(),
            principal_id.to_owned(),
            device_id.to_owned(),
        );
        let individual = state
            .individuals
            .get(&key)
            .cloned()
            .ok_or(AuthorityError::IndividualNotEnabled)?;
        if !individual.enabled || individual.expires_at_unix_ms <= now {
            return Err(AuthorityError::IndividualNotEnabled);
        }
        if individual.tenant_generation != tenant.generation {
            return Err(AuthorityError::ConsentNotCurrent);
        }
        Ok(ConsentSnapshot { tenant, individual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(enabled: bool, generation: u64, now: u64) -> TenantConsentRecord {
        TenantConsentRecord {
            tenant_id: "tenant-a".into(),
            enabled,
            generation,
            purpose: "collective-defence.read-only.v1".into(),
            schema_version: "1.0".into(),
            retention_seconds: if enabled { 86_400 } else { 0 },
            notice_version: "notice-v1".into(),
            notice_sha256: [1; 32],
            actor_key_id: "admin-key".into(),
            updated_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
        }
    }
    fn individual(
        enabled: bool,
        tenant_generation: u64,
        generation: u64,
        now: u64,
    ) -> IndividualConsentRecord {
        IndividualConsentRecord {
            tenant_id: "tenant-a".into(),
            principal_id: "user-a".into(),
            device_id: "device-a".into(),
            enabled,
            tenant_generation,
            generation,
            purpose: "collective-defence.read-only.v1".into(),
            notice_version: "notice-v1".into(),
            notice_sha256: [2; 32],
            actor_key_id: "user-key".into(),
            updated_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
        }
    }

    #[test]
    fn two_independent_decisions_are_required() {
        let store = MemoryConsentAuthority::default();
        store.put_tenant(tenant(true, 1, 100), None, "t-1").unwrap();
        assert_eq!(
            store.authorization_snapshot("tenant-a", "user-a", "device-a", 101),
            Err(AuthorityError::IndividualNotEnabled)
        );
        store
            .put_individual(individual(true, 1, 1, 102), None, "i-1")
            .unwrap();
        assert!(store
            .authorization_snapshot("tenant-a", "user-a", "device-a", 103)
            .is_ok());
    }

    #[test]
    fn tenant_disable_invalidates_every_individual_snapshot() {
        let store = MemoryConsentAuthority::default();
        store.put_tenant(tenant(true, 1, 100), None, "t-1").unwrap();
        store
            .put_individual(individual(true, 1, 1, 101), None, "i-1")
            .unwrap();
        store
            .put_tenant(tenant(false, 2, 102), Some(1), "t-2")
            .unwrap();
        assert_eq!(
            store.authorization_snapshot("tenant-a", "user-a", "device-a", 103),
            Err(AuthorityError::TenantNotEnabled)
        );
        assert_eq!(
            store.put_individual(individual(true, 2, 2, 104), Some(1), "i-2"),
            Err(AuthorityError::TenantNotEnabled)
        );
    }

    #[test]
    fn individual_withdrawal_invalidates_only_that_device() {
        let store = MemoryConsentAuthority::default();
        store.put_tenant(tenant(true, 1, 100), None, "t-1").unwrap();
        store
            .put_individual(individual(true, 1, 1, 101), None, "i-1")
            .unwrap();
        store
            .put_individual(individual(false, 1, 2, 102), Some(1), "i-2")
            .unwrap();
        assert_eq!(
            store.authorization_snapshot("tenant-a", "user-a", "device-a", 103),
            Err(AuthorityError::IndividualNotEnabled)
        );
    }

    #[test]
    fn individual_withdrawal_remains_available_after_tenant_disable() {
        let store = MemoryConsentAuthority::default();
        store.put_tenant(tenant(true, 1, 100), None, "t-1").unwrap();
        store
            .put_individual(individual(true, 1, 1, 101), None, "i-1")
            .unwrap();
        store
            .put_tenant(tenant(false, 2, 102), Some(1), "t-2")
            .unwrap();
        let withdrawal = individual(false, 2, 2, 103);
        assert!(store
            .put_individual(withdrawal, Some(1), "i-withdraw")
            .is_ok());
        assert_eq!(
            store.authorization_snapshot("tenant-a", "user-a", "device-a", 104),
            Err(AuthorityError::TenantNotEnabled)
        );
    }

    #[test]
    fn compare_and_set_and_idempotency_are_enforced() {
        let store = MemoryConsentAuthority::default();
        let record = tenant(true, 1, 100);
        let first = store.put_tenant(record.clone(), None, "request-1").unwrap();
        let retry = store.put_tenant(record, None, "request-1").unwrap();
        assert_eq!(first, retry);
        assert_eq!(
            store.put_tenant(tenant(false, 2, 101), None, "request-2"),
            Err(AuthorityError::GenerationConflict)
        );
        assert_eq!(
            store.put_tenant(tenant(false, 2, 101), Some(1), "request-1"),
            Err(AuthorityError::IdempotencyConflict)
        );
    }

    #[test]
    fn idempotency_keys_are_scoped_to_the_tenant() {
        let store = MemoryConsentAuthority::default();
        store
            .put_tenant(tenant(true, 1, 100), None, "shared-request-key")
            .unwrap();

        let mut tenant_b = tenant(true, 1, 100);
        tenant_b.tenant_id = "tenant-b".into();
        assert!(store
            .put_tenant(tenant_b, None, "shared-request-key")
            .is_ok());
    }

    #[test]
    fn consent_records_reject_invalid_policy_and_notice_fields() {
        let store = MemoryConsentAuthority::default();

        let mut invalid_purpose = tenant(true, 1, 100);
        invalid_purpose.purpose = "other-purpose".into();
        assert_eq!(
            store.put_tenant(invalid_purpose, None, "bad-purpose"),
            Err(AuthorityError::InvalidPurpose)
        );

        let mut invalid_schema = tenant(true, 1, 100);
        invalid_schema.schema_version = "2.0".into();
        assert_eq!(
            store.put_tenant(invalid_schema, None, "bad-schema"),
            Err(AuthorityError::UnsupportedSchema)
        );

        let mut invalid_retention = tenant(true, 1, 100);
        invalid_retention.retention_seconds = 0;
        assert_eq!(
            store.put_tenant(invalid_retention, None, "bad-retention"),
            Err(AuthorityError::InvalidRetention)
        );

        let mut invalid_notice = individual(true, 1, 1, 100);
        invalid_notice.notice_sha256 = [0; 32];
        assert_eq!(
            store.put_individual(invalid_notice, None, "bad-notice"),
            Err(AuthorityError::InvalidNoticeDigest)
        );

        let mut excessive_ttl = tenant(true, 1, 100);
        excessive_ttl.expires_at_unix_ms = 100 + MAX_CONSENT_TTL_MS + 1;
        assert_eq!(
            store.put_tenant(excessive_ttl, None, "bad-ttl"),
            Err(AuthorityError::InvalidTimeWindow)
        );
    }

    #[test]
    fn non_positive_consent_windows_return_time_window_errors() {
        let store = MemoryConsentAuthority::default();

        let mut invalid_tenant = tenant(true, 1, 100);
        invalid_tenant.expires_at_unix_ms = invalid_tenant.updated_at_unix_ms;
        assert_eq!(
            store.put_tenant(invalid_tenant, None, "bad-tenant-window"),
            Err(AuthorityError::InvalidTimeWindow)
        );

        store
            .put_tenant(tenant(true, 1, 100), None, "tenant-valid")
            .unwrap();
        let mut invalid_individual = individual(true, 1, 1, 101);
        invalid_individual.expires_at_unix_ms = invalid_individual.updated_at_unix_ms;
        assert_eq!(
            store.put_individual(invalid_individual, None, "bad-individual-window"),
            Err(AuthorityError::InvalidTimeWindow)
        );
    }

    #[test]
    fn audit_records_form_a_hash_chain() {
        let store = MemoryConsentAuthority::default();
        store.put_tenant(tenant(true, 1, 100), None, "t-1").unwrap();
        store
            .put_tenant(tenant(false, 2, 101), Some(1), "t-2")
            .unwrap();
        let audit = store.audit_log().unwrap();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[1].previous_hash, audit[0].record_hash);
        assert_ne!(audit[1].record_hash, [0; 32]);
        assert!(verify_audit_chain(&audit));

        let mut tampered = audit.clone();
        tampered[0].action.push_str(".tampered");
        assert!(!verify_audit_chain(&tampered));
    }
}
