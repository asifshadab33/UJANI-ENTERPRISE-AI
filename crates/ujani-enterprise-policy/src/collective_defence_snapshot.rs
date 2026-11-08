//! Versioned canonical encoding for durable Collective Defence consent snapshots.
//!
//! This module defines deterministic bytes for a future storage/anchor adapter.
//! It does not persist data, authenticate callers, or provide rollback protection.

use crate::collective_defence_authority::{
    verify_audit_chain, ConsentAuditRecord, IndividualConsentRecord, TenantConsentRecord,
};
use crate::collective_defence_consent::{
    COLLECTIVE_DEFENCE_PURPOSE, MAX_CONSENT_TTL_MS, MAX_EVENT_RETENTION_SECONDS,
    SECURITY_EVENT_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const SNAPSHOT_DOMAIN: &[u8] = b"UJANI-COLLECTIVE-DEFENCE-CONSENT-SNAPSHOT-V1\0";
pub const CONSENT_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const MAX_SNAPSHOT_RECORDS: usize = 100_000;
pub const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_NOTICE_VERSION_BYTES: usize = 64;
const MAX_ACTION_BYTES: usize = 64;

/// Canonical idempotency outcome reference. The audit record itself is stored once
/// in the audit sequence; this record binds a tenant-scoped retry key to its
/// request digest and committed audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalIdempotencyRecord {
    pub tenant_id: String,
    pub idempotency_key: String,
    pub request_sha256: [u8; 32],
    pub audit_event_id: [u8; 32],
}

/// A complete, versioned authority snapshot suitable for canonical hashing.
///
/// Records are sorted by their stable scope keys during encoding. Audit records
/// remain in sequence order because their hash links are order-dependent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalConsentSnapshot {
    pub schema_version: u16,
    pub snapshot_generation: u64,
    pub tenants: Vec<TenantConsentRecord>,
    pub individuals: Vec<IndividualConsentRecord>,
    pub audit: Vec<ConsentAuditRecord>,
    pub idempotency: Vec<CanonicalIdempotencyRecord>,
}

/// Fail-closed canonical encoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotEncodingError {
    UnsupportedVersion,
    InvalidRecord,
    DuplicateRecord,
    InvalidAuditChain,
    OrphanIdempotencyRecord,
    CapacityExceeded,
    SnapshotTooLarge,
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'@'))
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), SnapshotEncodingError> {
    let next = out
        .len()
        .checked_add(value.len())
        .ok_or(SnapshotEncodingError::SnapshotTooLarge)?;
    if next > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotEncodingError::SnapshotTooLarge);
    }
    out.extend_from_slice(value);
    Ok(())
}

fn push_string(
    out: &mut Vec<u8>,
    value: &str,
    max: usize,
) -> Result<(), SnapshotEncodingError> {
    if value.is_empty() || value.len() > max {
        return Err(SnapshotEncodingError::InvalidRecord);
    }
    let length = u32::try_from(value.len()).map_err(|_| SnapshotEncodingError::InvalidRecord)?;
    push_bytes(out, &length.to_be_bytes())?;
    push_bytes(out, value.as_bytes())
}

fn push_optional_string(
    out: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), SnapshotEncodingError> {
    match value {
        None => push_bytes(out, &[0]),
        Some(value) => {
            push_bytes(out, &[1])?;
            push_string(out, value, MAX_IDENTIFIER_BYTES)
        }
    }
}

fn validate_tenant(record: &TenantConsentRecord) -> bool {
    valid_identifier(&record.tenant_id, MAX_IDENTIFIER_BYTES)
        && record.generation > 0
        && record.purpose == COLLECTIVE_DEFENCE_PURPOSE
        && record.schema_version == SECURITY_EVENT_SCHEMA_VERSION
        && record.retention_seconds <= MAX_EVENT_RETENTION_SECONDS
        && (!record.enabled || record.retention_seconds > 0)
        && !record.notice_version.is_empty()
        && record.notice_version.len() <= MAX_NOTICE_VERSION_BYTES
        && record.notice_sha256.iter().any(|byte| *byte != 0)
        && valid_identifier(&record.actor_key_id, MAX_IDENTIFIER_BYTES)
        && record.expires_at_unix_ms > record.updated_at_unix_ms
        && record.expires_at_unix_ms.saturating_sub(record.updated_at_unix_ms)
            <= MAX_CONSENT_TTL_MS
}

fn validate_individual(record: &IndividualConsentRecord) -> bool {
    valid_identifier(&record.tenant_id, MAX_IDENTIFIER_BYTES)
        && valid_identifier(&record.principal_id, MAX_IDENTIFIER_BYTES)
        && valid_identifier(&record.device_id, MAX_IDENTIFIER_BYTES)
        && record.generation > 0
        && record.tenant_generation > 0
        && record.purpose == COLLECTIVE_DEFENCE_PURPOSE
        && !record.notice_version.is_empty()
        && record.notice_version.len() <= MAX_NOTICE_VERSION_BYTES
        && record.notice_sha256.iter().any(|byte| *byte != 0)
        && valid_identifier(&record.actor_key_id, MAX_IDENTIFIER_BYTES)
        && record.expires_at_unix_ms > record.updated_at_unix_ms
        && record.expires_at_unix_ms.saturating_sub(record.updated_at_unix_ms)
            <= MAX_CONSENT_TTL_MS
}

fn encode_tenant(out: &mut Vec<u8>, record: &TenantConsentRecord) -> Result<(), SnapshotEncodingError> {
    if !validate_tenant(record) {
        return Err(SnapshotEncodingError::InvalidRecord);
    }
    push_bytes(out, b"T")?;
    push_string(out, &record.tenant_id, MAX_IDENTIFIER_BYTES)?;
    push_bytes(out, &[u8::from(record.enabled)])?;
    push_bytes(out, &record.generation.to_be_bytes())?;
    push_string(out, &record.purpose, MAX_IDENTIFIER_BYTES)?;
    push_string(out, &record.schema_version, MAX_NOTICE_VERSION_BYTES)?;
    push_bytes(out, &record.retention_seconds.to_be_bytes())?;
    push_string(out, &record.notice_version, MAX_NOTICE_VERSION_BYTES)?;
    push_bytes(out, &record.notice_sha256)?;
    push_string(out, &record.actor_key_id, MAX_IDENTIFIER_BYTES)?;
    push_bytes(out, &record.updated_at_unix_ms.to_be_bytes())?;
    push_bytes(out, &record.expires_at_unix_ms.to_be_bytes())
}

fn encode_individual(
    out: &mut Vec<u8>,
    record: &IndividualConsentRecord,
) -> Result<(), SnapshotEncodingError> {
    if !validate_individual(record) {
        return Err(SnapshotEncodingError::InvalidRecord);
    }
    push_bytes(out, b"I")?;
    push_string(out, &record.tenant_id, MAX_IDENTIFIER_BYTES)?;
    push_string(out, &record.principal_id, MAX_IDENTIFIER_BYTES)?;
    push_string(out, &record.device_id, MAX_IDENTIFIER_BYTES)?;
    push_bytes(out, &[u8::from(record.enabled)])?;
    push_bytes(out, &record.tenant_generation.to_be_bytes())?;
    push_bytes(out, &record.generation.to_be_bytes())?;
    push_string(out, &record.purpose, MAX_IDENTIFIER_BYTES)?;
    push_string(out, &record.notice_version, MAX_NOTICE_VERSION_BYTES)?;
    push_bytes(out, &record.notice_sha256)?;
    push_string(out, &record.actor_key_id, MAX_IDENTIFIER_BYTES)?;
    push_bytes(out, &record.updated_at_unix_ms.to_be_bytes())?;
    push_bytes(out, &record.expires_at_unix_ms.to_be_bytes())
}

fn encode_audit(out: &mut Vec<u8>, record: &ConsentAuditRecord) -> Result<(), SnapshotEncodingError> {
    if !valid_identifier(&record.tenant_id, MAX_IDENTIFIER_BYTES)
        || !valid_identifier(&record.action, MAX_ACTION_BYTES)
        || !valid_identifier(&record.actor_key_id, MAX_IDENTIFIER_BYTES)
        || record.next_generation <= record.previous_generation
        || record.principal_id.is_some() != record.device_id.is_some()
        || record.principal_id.as_deref().is_some_and(|v| !valid_identifier(v, MAX_IDENTIFIER_BYTES))
        || record.device_id.as_deref().is_some_and(|v| !valid_identifier(v, MAX_IDENTIFIER_BYTES))
    {
        return Err(SnapshotEncodingError::InvalidRecord);
    }
    push_bytes(out, b"A")?;
    push_bytes(out, &record.sequence.to_be_bytes())?;
    push_bytes(out, &record.event_id)?;
    push_string(out, &record.tenant_id, MAX_IDENTIFIER_BYTES)?;
    push_optional_string(out, record.principal_id.as_deref())?;
    push_optional_string(out, record.device_id.as_deref())?;
    push_string(out, &record.action, MAX_ACTION_BYTES)?;
    push_bytes(out, &record.previous_generation.to_be_bytes())?;
    push_bytes(out, &record.next_generation.to_be_bytes())?;
    push_string(out, &record.actor_key_id, MAX_IDENTIFIER_BYTES)?;
    push_bytes(out, &record.committed_at_unix_ms.to_be_bytes())?;
    push_bytes(out, &record.previous_hash)?;
    push_bytes(out, &record.record_hash)
}

impl CanonicalConsentSnapshot {
    /// Encode the complete snapshot in stable, versioned, domain-separated form.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SnapshotEncodingError> {
        if self.schema_version != CONSENT_SNAPSHOT_SCHEMA_VERSION {
            return Err(SnapshotEncodingError::UnsupportedVersion);
        }
        if self.tenants.len() > MAX_SNAPSHOT_RECORDS
            || self.individuals.len() > MAX_SNAPSHOT_RECORDS
            || self.audit.len() > MAX_SNAPSHOT_RECORDS
            || self.idempotency.len() > MAX_SNAPSHOT_RECORDS
        {
            return Err(SnapshotEncodingError::CapacityExceeded);
        }
        if !verify_audit_chain(&self.audit) {
            return Err(SnapshotEncodingError::InvalidAuditChain);
        }

        let mut tenants: Vec<_> = self.tenants.iter().collect();
        tenants.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        if tenants.windows(2).any(|pair| pair[0].tenant_id == pair[1].tenant_id) {
            return Err(SnapshotEncodingError::DuplicateRecord);
        }

        let mut individuals: Vec<_> = self.individuals.iter().collect();
        individuals.sort_by(|a, b| {
            (&a.tenant_id, &a.principal_id, &a.device_id)
                .cmp(&(&b.tenant_id, &b.principal_id, &b.device_id))
        });
        if individuals.windows(2).any(|pair| {
            pair[0].tenant_id == pair[1].tenant_id
                && pair[0].principal_id == pair[1].principal_id
                && pair[0].device_id == pair[1].device_id
        }) {
            return Err(SnapshotEncodingError::DuplicateRecord);
        }

        let mut audit_ids = BTreeMap::new();
        for record in &self.audit {
            if audit_ids.insert(record.event_id, record.tenant_id.as_str()).is_some() {
                return Err(SnapshotEncodingError::DuplicateRecord);
            }
        }

        let mut idempotency: Vec<_> = self.idempotency.iter().collect();
        idempotency.sort_by(|a, b| {
            (&a.tenant_id, &a.idempotency_key).cmp(&(&b.tenant_id, &b.idempotency_key))
        });
        let mut idempotency_keys = BTreeSet::new();
        for record in &idempotency {
            if !valid_identifier(&record.tenant_id, MAX_IDENTIFIER_BYTES)
                || !valid_identifier(&record.idempotency_key, MAX_IDENTIFIER_BYTES)
                || record.request_sha256.iter().all(|byte| *byte == 0)
                || !idempotency_keys.insert((&record.tenant_id, &record.idempotency_key))
                || audit_ids.get(&record.audit_event_id) != Some(&record.tenant_id.as_str())
            {
                return Err(SnapshotEncodingError::OrphanIdempotencyRecord);
            }
        }

        let mut out = Vec::new();
        push_bytes(&mut out, SNAPSHOT_DOMAIN)?;
        push_bytes(&mut out, &self.schema_version.to_be_bytes())?;
        push_bytes(&mut out, &self.snapshot_generation.to_be_bytes())?;
        for count in [tenants.len(), individuals.len(), self.audit.len(), idempotency.len()] {
            let count = u32::try_from(count).map_err(|_| SnapshotEncodingError::CapacityExceeded)?;
            push_bytes(&mut out, &count.to_be_bytes())?;
        }
        for record in tenants {
            encode_tenant(&mut out, record)?;
        }
        for record in individuals {
            encode_individual(&mut out, record)?;
        }
        for record in &self.audit {
            encode_audit(&mut out, record)?;
        }
        for record in idempotency {
            push_bytes(&mut out, b"K")?;
            push_string(&mut out, &record.tenant_id, MAX_IDENTIFIER_BYTES)?;
            push_string(&mut out, &record.idempotency_key, MAX_IDENTIFIER_BYTES)?;
            push_bytes(&mut out, &record.request_sha256)?;
            push_bytes(&mut out, &record.audit_event_id)?;
        }
        if out.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotEncodingError::SnapshotTooLarge);
        }
        Ok(out)
    }

    /// Hash the exact canonical bytes to bind them to a separate monotonic anchor.
    pub fn sha256(&self) -> Result<[u8; 32], SnapshotEncodingError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collective_defence_authority::{
        ConsentAuthorityBackend, MemoryConsentAuthority,
    };

    fn tenant(enabled: bool, generation: u64, now: u64, id: &str) -> TenantConsentRecord {
        TenantConsentRecord {
            tenant_id: id.into(),
            enabled,
            generation,
            purpose: COLLECTIVE_DEFENCE_PURPOSE.into(),
            schema_version: SECURITY_EVENT_SCHEMA_VERSION.into(),
            retention_seconds: if enabled { 86_400 } else { 0 },
            notice_version: "notice-v1".into(),
            notice_sha256: [1; 32],
            actor_key_id: "admin-key".into(),
            updated_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
        }
    }

    fn individual(tenant_id: &str, principal: &str, device: &str, now: u64) -> IndividualConsentRecord {
        IndividualConsentRecord {
            tenant_id: tenant_id.into(),
            principal_id: principal.into(),
            device_id: device.into(),
            enabled: true,
            tenant_generation: 1,
            generation: 1,
            purpose: COLLECTIVE_DEFENCE_PURPOSE.into(),
            notice_version: "notice-v1".into(),
            notice_sha256: [2; 32],
            actor_key_id: "user-key".into(),
            updated_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
        }
    }

    fn audit_fixture() -> (Vec<ConsentAuditRecord>, Vec<CanonicalIdempotencyRecord>) {
        let store = MemoryConsentAuthority::default();
        let record = tenant(true, 1, 100, "tenant-a");
        let audit = store.put_tenant(record, None, "request-1").unwrap();
        (
            vec![audit.clone()],
            vec![CanonicalIdempotencyRecord {
                tenant_id: "tenant-a".into(),
                idempotency_key: "request-1".into(),
                request_sha256: [7; 32],
                audit_event_id: audit.event_id,
            }],
        )
    }

    #[test]
    fn canonical_encoding_is_independent_of_input_record_order() {
        let (audit, idempotency) = audit_fixture();
        let a = CanonicalConsentSnapshot {
            schema_version: CONSENT_SNAPSHOT_SCHEMA_VERSION,
            snapshot_generation: 1,
            tenants: vec![tenant(true, 1, 100, "tenant-a"), tenant(true, 1, 100, "tenant-b")],
            individuals: vec![
                individual("tenant-b", "user-b", "device-b", 100),
                individual("tenant-a", "user-a", "device-a", 100),
            ],
            audit,
            idempotency,
        };
        let mut b = a.clone();
        b.tenants.reverse();
        b.individuals.reverse();
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
        assert_eq!(a.sha256().unwrap(), b.sha256().unwrap());
    }

    #[test]
    fn canonical_encoding_rejects_duplicate_scopes_and_unknown_versions() {
        let (audit, idempotency) = audit_fixture();
        let mut snapshot = CanonicalConsentSnapshot {
            schema_version: CONSENT_SNAPSHOT_SCHEMA_VERSION,
            snapshot_generation: 1,
            tenants: vec![tenant(true, 1, 100, "tenant-a")],
            individuals: vec![],
            audit,
            idempotency,
        };
        snapshot.tenants.push(snapshot.tenants[0].clone());
        assert_eq!(snapshot.canonical_bytes(), Err(SnapshotEncodingError::DuplicateRecord));
        snapshot.tenants.pop();
        snapshot.schema_version = 99;
        assert_eq!(snapshot.canonical_bytes(), Err(SnapshotEncodingError::UnsupportedVersion));
    }

    #[test]
    fn canonical_encoding_rejects_tampered_audit_and_orphan_idempotency() {
        let (mut audit, idempotency) = audit_fixture();
        let mut snapshot = CanonicalConsentSnapshot {
            schema_version: CONSENT_SNAPSHOT_SCHEMA_VERSION,
            snapshot_generation: 1,
            tenants: vec![tenant(true, 1, 100, "tenant-a")],
            individuals: vec![],
            audit: audit.clone(),
            idempotency: idempotency.clone(),
        };
        audit[0].action.push_str(".tampered");
        snapshot.audit = audit;
        assert_eq!(snapshot.canonical_bytes(), Err(SnapshotEncodingError::InvalidAuditChain));
        snapshot.audit = vec![];
        assert_eq!(snapshot.canonical_bytes(), Err(SnapshotEncodingError::OrphanIdempotencyRecord));
        snapshot.audit = audit_fixture().0;
        snapshot.idempotency[0].audit_event_id = [9; 32];
        assert_eq!(snapshot.canonical_bytes(), Err(SnapshotEncodingError::OrphanIdempotencyRecord));
    }
}
