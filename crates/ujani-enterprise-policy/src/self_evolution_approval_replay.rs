//! Typed host boundary for consuming verified Enterprise Self-Evolution approvals.
//!
//! This module never applies patches or executes code. A production store must
//! call the tenant-scoped SQL consumption function in the same transaction as
//! any future approval-authorized state transition. It must use authenticated
//! tenant/operator identity, persist before returning success, serialize
//! concurrent calls across processes, and let the database check expiry after
//! its advisory locks have been acquired. Memory stores are tests only.

use crate::operator_control_plane::valid_identifier;
use crate::self_evolution_approval::VerifiedSelfEvolutionApproval;
use sha2::{Digest, Sha256};
const TARGET_DIGEST_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SELF-EVOLUTION-TARGET-V1\0";
const SCOPE_DIGEST_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SELF-EVOLUTION-SCOPE-SET-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalReplayStoreError {
    /// The approval ID or nonce has already been consumed, or the approval expired while waiting.
    AlreadyConsumedOrExpired,
    /// The durable store could not confirm the claim. Callers must fail closed.
    StorageUnavailable,
    /// The store rejected malformed or inconsistent record data.
    InvalidRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalConsumptionError {
    InvalidAuthenticatedContext,
    Store(ApprovalReplayStoreError),
}

/// Private fields ensure a replay record can only be derived from a verified approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEvolutionApprovalReplayRecord {
    tenant_id: String,
    approver_subject_id: String,
    approval_id: String,
    approver_key_id: String,
    nonce: [u8; 16],
    repository: String,
    base_ref: String,
    source_revision: String,
    proposal_sha256: [u8; 32],
    target_sha256: [u8; 32],
    approved_scope_sha256: [u8; 32],
    approved_scope_count: i32,
    expires_at_unix_ms: u64,
}

impl SelfEvolutionApprovalReplayRecord {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn approver_subject_id(&self) -> &str {
        &self.approver_subject_id
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub fn approver_key_id(&self) -> &str {
        &self.approver_key_id
    }

    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn base_ref(&self) -> &str {
        &self.base_ref
    }

    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub fn proposal_sha256(&self) -> &[u8; 32] {
        &self.proposal_sha256
    }

    pub fn target_sha256(&self) -> &[u8; 32] {
        &self.target_sha256
    }

    pub fn approved_scope_sha256(&self) -> &[u8; 32] {
        &self.approved_scope_sha256
    }

    pub fn approved_scope_count(&self) -> i32 {
        self.approved_scope_count
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

/// Trusted host persistence boundary for single-use approval receipts.
///
/// Implementations must atomically claim both (tenant, approval_id) and
/// (tenant, nonce), check expiry after acquiring their durable transaction
/// locks, persist the record before returning Ok, and serialize concurrent
/// calls across threads/processes. Storage errors and ambiguous results fail
/// closed. The PostgreSQL implementation should call
/// `ujani_control.consume_self_evolution_approval`.
pub trait SelfEvolutionApprovalReplayStore {
    fn consume_once(
        &mut self,
        record: &SelfEvolutionApprovalReplayRecord,
    ) -> Result<(), ApprovalReplayStoreError>;
}

/// Consume an already-verified approval exactly once.
///
/// `tenant_id` and `approver_subject_id` must come from authenticated,
/// current operator context, never from the signed payload or browser input.
/// The store owns the final expiry check so it can sample time after locking.
pub fn consume_verified_self_evolution_approval(
    approval: &VerifiedSelfEvolutionApproval,
    tenant_id: &str,
    approver_subject_id: &str,
    store: &mut impl SelfEvolutionApprovalReplayStore,
) -> Result<(), ApprovalConsumptionError> {
    if !valid_identifier(tenant_id, 128) || !valid_identifier(approver_subject_id, 128) {
        return Err(ApprovalConsumptionError::InvalidAuthenticatedContext);
    }

    let record = SelfEvolutionApprovalReplayRecord {
        tenant_id: tenant_id.to_owned(),
        approver_subject_id: approver_subject_id.to_owned(),
        approval_id: approval.approval_id().to_owned(),
        approver_key_id: approval.approver_key_id().to_owned(),
        nonce: *approval.nonce(),
        repository: approval.repository().to_owned(),
        base_ref: approval.base_ref().to_owned(),
        source_revision: approval.source_revision().to_owned(),
        proposal_sha256: *approval.proposal_sha256(),
        target_sha256: target_digest(
            approval.repository(),
            approval.base_ref(),
            approval.source_revision(),
        ),
        approved_scope_sha256: approved_scope_digest(approval.approved_scope()),
        approved_scope_count: i32::try_from(approval.approved_scope().len())
            .map_err(|_| ApprovalConsumptionError::Store(ApprovalReplayStoreError::InvalidRecord))?,
        expires_at_unix_ms: approval.expires_at_unix_ms(),
    };

    store
        .consume_once(&record)
        .map_err(ApprovalConsumptionError::Store)
}

fn append_length_prefixed(bytes: &mut Vec<u8>, value: &str) {
    // All fields have already been validated and are bounded well below u32::MAX.
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn target_digest(repository: &str, base_ref: &str, source_revision: &str) -> [u8; 32] {
    let mut bytes = TARGET_DIGEST_DOMAIN.to_vec();
    append_length_prefixed(&mut bytes, repository);
    append_length_prefixed(&mut bytes, base_ref);
    append_length_prefixed(&mut bytes, source_revision);
    Sha256::digest(bytes).into()
}

fn approved_scope_digest(scopes: &[String]) -> [u8; 32] {
    let mut bytes = SCOPE_DIGEST_DOMAIN.to_vec();
    bytes.extend_from_slice(&(scopes.len() as u32).to_be_bytes());
    for scope in scopes {
        append_length_prefixed(&mut bytes, scope);
    }
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_evolution::{
        FindingCategory, FindingSeverity, ProposedChange, ProposedChangeKind, ProposalTarget,
        SelfEvolutionFinding, SelfEvolutionProposalV1, SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
    };
    use crate::self_evolution_approval::{
        approval_signing_bytes, self_evolution_proposal_digest, verify_self_evolution_approval,
        SelfEvolutionApprovalClaims, SignedSelfEvolutionApproval,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashSet;

    #[derive(Default)]
    struct MemoryStore {
        approval_ids: HashSet<(String, String)>,
        nonces: HashSet<(String, [u8; 16])>,
        fail_closed: bool,
        now_unix_ms: u64,
    }

    impl SelfEvolutionApprovalReplayStore for MemoryStore {
        fn consume_once(
            &mut self,
            record: &SelfEvolutionApprovalReplayRecord,
        ) -> Result<(), ApprovalReplayStoreError> {
            if self.fail_closed {
                return Err(ApprovalReplayStoreError::StorageUnavailable);
            }
            if record.expires_at_unix_ms <= self.now_unix_ms {
                return Err(ApprovalReplayStoreError::AlreadyConsumedOrExpired);
            }
            let approval_key = (record.tenant_id.clone(), record.approval_id.clone());
            let nonce_key = (record.tenant_id.clone(), record.nonce);
            if self.approval_ids.contains(&approval_key) || self.nonces.contains(&nonce_key) {
                return Err(ApprovalReplayStoreError::AlreadyConsumedOrExpired);
            }
            self.approval_ids.insert(approval_key);
            self.nonces.insert(nonce_key);
            Ok(())
        }
    }

    fn verified_approval() -> VerifiedSelfEvolutionApproval {
        let target = ProposalTarget {
            repository: "asifshadab33/UJANI-ENTERPRISE-AI".into(),
            base_ref: "main".into(),
            source_revision: "a".repeat(40),
        };
        let proposal = SelfEvolutionProposalV1 {
            schema_version: SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
            summary: "Improve a non-core operator console label.".into(),
            findings: vec![SelfEvolutionFinding {
                category: FindingCategory::Accessibility,
                severity: FindingSeverity::Low,
                path: "apps/operator-console/app.js".into(),
                line_start: Some(1),
                line_end: Some(2),
                description: "A control needs a clearer accessible name.".into(),
                recommendation: "Add an explicit accessible label.".into(),
            }],
            changes: vec![ProposedChange {
                path: "apps/operator-console/app.js".into(),
                operation: ProposedChangeKind::Modify,
                summary: "Add an accessible label.".into(),
                patch_sha256: "b".repeat(64),
            }],
        };
        let key = SigningKey::from_bytes(&[11; 32]);
        let claims = SelfEvolutionApprovalClaims {
            approval_id: "approval-001".into(),
            repository: target.repository.clone(),
            base_ref: target.base_ref.clone(),
            source_revision: target.source_revision.clone(),
            proposal_sha256: self_evolution_proposal_digest(&proposal).unwrap(),
            approved_scope: vec!["apps/operator-console".into()],
            approver_key_id: "admin-key-01".into(),
            nonce: [9; 16],
            issued_at_unix_ms: 1_000,
            expires_unix_ms: 60_000,
        };
        let signed = SignedSelfEvolutionApproval {
            signature: key.sign(&approval_signing_bytes(&claims)).to_bytes(),
            claims,
        };
        verify_self_evolution_approval(
            &signed,
            &[("admin-key-01".into(), key.verifying_key())],
            &target,
            &proposal,
            2_000,
        )
        .unwrap()
    }

    #[test]
    fn replay_digests_change_when_target_or_scope_changes() {
        assert_ne!(
            target_digest("owner/repository", "main", &"a".repeat(40)),
            target_digest("owner/repository", "release", &"a".repeat(40))
        );
        assert_ne!(
            approved_scope_digest(&["apps/console".into()]),
            approved_scope_digest(&["crates/core".into()])
        );
    }

    #[test]
    fn consumes_verified_approval_once_and_binds_authenticated_context() {
        let approval = verified_approval();
        let mut store = MemoryStore::default();
        assert_eq!(
            consume_verified_self_evolution_approval(
                &approval,
                "tenant-a",
                "admin-a",
                &mut store,
            ),
            Ok(())
        );
        assert_eq!(store.approval_ids.len(), 1);
        assert_eq!(store.nonces.len(), 1);
        assert_eq!(
            consume_verified_self_evolution_approval(
                &approval,
                "tenant-a",
                "admin-a",
                &mut store,
            ),
            Err(ApprovalConsumptionError::Store(
                ApprovalReplayStoreError::AlreadyConsumedOrExpired
            ))
        );
    }

    #[test]
    fn rejects_invalid_authenticated_context_before_storage() {
        let approval = verified_approval();
        let mut store = MemoryStore::default();
        assert_eq!(
            consume_verified_self_evolution_approval(&approval, "", "admin-a", &mut store),
            Err(ApprovalConsumptionError::InvalidAuthenticatedContext)
        );
        assert!(store.approval_ids.is_empty());
    }

    #[test]
    fn fails_closed_when_storage_is_unavailable_or_approval_expired() {
        let approval = verified_approval();
        let mut unavailable = MemoryStore {
            fail_closed: true,
            ..MemoryStore::default()
        };
        assert_eq!(
            consume_verified_self_evolution_approval(
                &approval,
                "tenant-a",
                "admin-a",
                &mut unavailable,
            ),
            Err(ApprovalConsumptionError::Store(
                ApprovalReplayStoreError::StorageUnavailable
            ))
        );

        let mut expired = MemoryStore {
            now_unix_ms: 60_000,
            ..MemoryStore::default()
        };
        assert_eq!(
            consume_verified_self_evolution_approval(
                &approval,
                "tenant-a",
                "admin-a",
                &mut expired,
            ),
            Err(ApprovalConsumptionError::Store(
                ApprovalReplayStoreError::AlreadyConsumedOrExpired
            ))
        );
        assert!(expired.approval_ids.is_empty());
    }
}
