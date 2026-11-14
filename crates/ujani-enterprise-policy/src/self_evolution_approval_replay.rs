//! Stable, adapter-neutral mapping from a verified approval to the durable replay row.
//!
//! This module does not connect to a database or consume an approval. A trusted host
//! supplies tenant and approver-subject identity from authenticated session/key
//! enrollment, then persists this record atomically using the migration's unique
//! tenant/approval and tenant/nonce constraints.

use crate::self_evolution_approval::VerifiedSelfEvolutionApproval;
use sha2::{Digest, Sha256};

const TARGET_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SELF-EVOLUTION-TARGET-V1\0";
const SCOPE_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SELF-EVOLUTION-SCOPE-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRecordError {
    InvalidTenantId,
    InvalidApproverSubjectId,
    InvalidScope,
}

/// Data required by migrations/0006_self_evolution_approval_replay.sql.
/// tenant_id and approver_subject_id are trusted host identity, never approval
/// payload fields. Timestamps are milliseconds since Unix epoch and must be
/// converted to UTC timestamptz by the database adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEvolutionApprovalReplayRecord {
    pub tenant_id: String,
    pub approval_id: String,
    pub approver_subject_id: String,
    pub approver_key_id: String,
    pub nonce: [u8; 16],
    pub repository: String,
    pub base_ref: String,
    pub source_revision: String,
    pub proposal_sha256: [u8; 32],
    pub target_sha256: [u8; 32],
    pub approved_scope_sha256: [u8; 32],
    pub approved_scope_count: u32,
    pub expires_at_unix_ms: u64,
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

/// Hash the exact trusted repository target with unambiguous length-prefixed fields.
pub fn self_evolution_target_sha256(repository: &str, base_ref: &str, source_revision: &str) -> [u8; 32] {
    hash_fields(TARGET_DOMAIN, &[repository.as_bytes(), base_ref.as_bytes(), source_revision.as_bytes()])
}

/// Hash approved paths independent of input ordering while preserving path spelling/case.
pub fn self_evolution_scope_sha256(scope: &[String]) -> Result<[u8; 32], ReplayRecordError> {
    if scope.is_empty() || scope.len() > 32 {
        return Err(ReplayRecordError::InvalidScope);
    }
    let mut paths = scope.to_vec();
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReplayRecordError::InvalidScope);
    }
    let refs: Vec<&[u8]> = paths.iter().map(|path| path.as_bytes()).collect();
    Ok(hash_fields(SCOPE_DOMAIN, &refs))
}

impl SelfEvolutionApprovalReplayRecord {
    /// Map only a cryptographically verified approval. Identity fields must come
    /// from authenticated tenant/session and enrolled-key-to-subject mapping.
    pub fn from_verified(
        tenant_id: &str,
        approver_subject_id: &str,
        approval: &VerifiedSelfEvolutionApproval,
    ) -> Result<Self, ReplayRecordError> {
        if !valid_identity(tenant_id) { return Err(ReplayRecordError::InvalidTenantId); }
        if !valid_identity(approver_subject_id) { return Err(ReplayRecordError::InvalidApproverSubjectId); }
        let scope = approval.approved_scope();
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            approval_id: approval.approval_id().to_owned(),
            approver_subject_id: approver_subject_id.to_owned(),
            approver_key_id: approval.approver_key_id().to_owned(),
            nonce: *approval.nonce(),
            repository: approval.repository().to_owned(),
            base_ref: approval.base_ref().to_owned(),
            source_revision: approval.source_revision().to_owned(),
            proposal_sha256: *approval.proposal_sha256(),
            target_sha256: self_evolution_target_sha256(approval.repository(), approval.base_ref(), approval.source_revision()),
            approved_scope_sha256: self_evolution_scope_sha256(scope)?,
            approved_scope_count: scope.len() as u32,
            expires_at_unix_ms: approval.expires_at_unix_ms(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_digest_binds_each_target_component() {
        let revision_a = "a".repeat(40);
        let revision_b = "b".repeat(40);
        let baseline = self_evolution_target_sha256("owner/repo", "main", &revision_a);
        assert_ne!(baseline, self_evolution_target_sha256("owner/other", "main", &revision_a));
        assert_ne!(baseline, self_evolution_target_sha256("owner/repo", "release", &revision_a));
        assert_ne!(baseline, self_evolution_target_sha256("owner/repo", "main", &revision_b));
    }

    #[test]
    fn scope_digest_is_order_independent_but_path_sensitive() {
        let first = vec!["apps/help".to_owned(), "docs/help".to_owned()];
        let reordered = vec!["docs/help".to_owned(), "apps/help".to_owned()];
        let changed = vec!["apps/help".to_owned(), "docs/private".to_owned()];
        assert_eq!(self_evolution_scope_sha256(&first), self_evolution_scope_sha256(&reordered));
        assert_ne!(self_evolution_scope_sha256(&first), self_evolution_scope_sha256(&changed));
    }

    #[test]
    fn scope_digest_rejects_empty_oversized_and_duplicate_lists() {
        assert_eq!(self_evolution_scope_sha256(&[]), Err(ReplayRecordError::InvalidScope));
        let oversized = (0..33).map(|index| format!("path-{index}")).collect::<Vec<_>>();
        assert_eq!(self_evolution_scope_sha256(&oversized), Err(ReplayRecordError::InvalidScope));
        let duplicate = vec!["apps/help".to_owned(), "apps/help".to_owned()];
        assert_eq!(self_evolution_scope_sha256(&duplicate), Err(ReplayRecordError::InvalidScope));
    }

    #[test]
    fn identity_validation_fails_closed() {
        assert!(!valid_identity(""));
        assert!(!valid_identity("tenant with spaces"));
        let too_long = "x".repeat(129);
        assert!(!valid_identity(&too_long));
        assert!(valid_identity("tenant-a"));
    }
}
