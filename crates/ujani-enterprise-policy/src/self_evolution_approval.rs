//! Explicit administrator approval contract for model-authored self-evolution proposals.
//!
//! This module verifies a signed, short-lived approval bound to the exact proposal,
//! trusted repository target and host-selected write scope. It does not apply patches,
//! write files, execute code, install updates, or provide durable replay protection.
//! The hosting service must atomically consume the nonce in durable storage before
//! authorizing any later, separately reviewed change workflow.

use crate::self_evolution::{ProposalTarget, SelfEvolutionProposalV1, MAX_PROPOSAL_SCOPE_PATHS};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SELF_EVOLUTION_APPROVAL_TTL_MAX_MS: u64 = 15 * 60 * 1000;
const APPROVAL_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SELF-EVOLUTION-APPROVAL-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfEvolutionApprovalClaims {
    pub approval_id: String,
    pub repository: String,
    pub base_ref: String,
    pub source_revision: String,
    pub proposal_sha256: [u8; 32],
    pub approved_scope: Vec<String>,
    pub approver_key_id: String,
    pub nonce: [u8; 16],
    pub issued_at_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSelfEvolutionApproval {
    pub claims: SelfEvolutionApprovalClaims,
    pub signature: [u8; 64],
}

/// Private fields ensure only successful cryptographic verification can construct this token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSelfEvolutionApproval(SelfEvolutionApprovalClaims);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionApprovalError {
    InvalidClaims,
    UnknownApproverKey,
    InvalidSignature,
    ProposalDigestMismatch,
    InvalidProposal,
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn valid_revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Canonical bytes that an enrolled administrator must sign for these exact claims.
/// External signers must use this function rather than reimplementing the encoding.
pub fn approval_signing_bytes(claims: &SelfEvolutionApprovalClaims) -> Vec<u8> {
    let mut bytes = APPROVAL_DOMAIN.to_vec();
    for value in [
        claims.approval_id.as_str(),
        claims.repository.as_str(),
        claims.base_ref.as_str(),
        claims.source_revision.as_str(),
        claims.approver_key_id.as_str(),
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&claims.proposal_sha256);
    bytes.extend_from_slice(&(claims.approved_scope.len() as u32).to_be_bytes());
    for scope in &claims.approved_scope {
        bytes.extend_from_slice(&(scope.len() as u32).to_be_bytes());
        bytes.extend_from_slice(scope.as_bytes());
    }
    bytes.extend_from_slice(&claims.nonce);
    bytes.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.expires_unix_ms.to_be_bytes());
    bytes
}

/// Hash the typed proposal representation that the host has already parsed and validated.
pub fn self_evolution_proposal_digest(
    proposal: &SelfEvolutionProposalV1,
) -> Result<[u8; 32], SelfEvolutionApprovalError> {
    let encoded =
        serde_json::to_vec(proposal).map_err(|_| SelfEvolutionApprovalError::InvalidProposal)?;
    Ok(Sha256::digest(encoded).into())
}

/// Verify an enrolled administrator's signature and bind the approval to this exact proposal.
///
/// The caller must durably and atomically consume the nonce before any follow-on operation.
/// This verifier alone is not replay protection and grants no patch-application authority.
pub fn verify_self_evolution_approval(
    signed: &SignedSelfEvolutionApproval,
    enrolled_admin_keys: &[(String, VerifyingKey)],
    trusted_target: &ProposalTarget,
    proposal: &SelfEvolutionProposalV1,
    now_unix_ms: u64,
) -> Result<VerifiedSelfEvolutionApproval, SelfEvolutionApprovalError> {
    let claims = &signed.claims;
    if !valid_identifier(&claims.approval_id, 128)
        || !valid_identifier(&claims.approver_key_id, 128)
        || claims.repository != trusted_target.repository
        || claims.base_ref != trusted_target.base_ref
        || claims.source_revision != trusted_target.source_revision
        || !valid_revision(&claims.source_revision)
        || claims.approved_scope.is_empty()
        || claims.approved_scope.len() > MAX_PROPOSAL_SCOPE_PATHS
        || claims.nonce.iter().all(|byte| *byte == 0)
        || claims.issued_at_unix_ms > now_unix_ms.saturating_add(30_000)
        || claims.expires_unix_ms <= now_unix_ms
        || claims.expires_unix_ms <= claims.issued_at_unix_ms
        || claims
            .expires_unix_ms
            .saturating_sub(claims.issued_at_unix_ms)
            > SELF_EVOLUTION_APPROVAL_TTL_MAX_MS
    {
        return Err(SelfEvolutionApprovalError::InvalidClaims);
    }

    let key = enrolled_admin_keys
        .iter()
        .find(|(key_id, _)| key_id == &claims.approver_key_id)
        .map(|(_, key)| key)
        .ok_or(SelfEvolutionApprovalError::UnknownApproverKey)?;
    let signature = Signature::from_bytes(&signed.signature);
    key.verify_strict(&approval_signing_bytes(claims), &signature)
        .map_err(|_| SelfEvolutionApprovalError::InvalidSignature)?;

    let digest = self_evolution_proposal_digest(proposal)?;
    if digest != claims.proposal_sha256 {
        return Err(SelfEvolutionApprovalError::ProposalDigestMismatch);
    }
    proposal
        .validate_against(trusted_target, &claims.approved_scope)
        .map_err(|_| SelfEvolutionApprovalError::InvalidProposal)?;

    Ok(VerifiedSelfEvolutionApproval(claims.clone()))
}

impl VerifiedSelfEvolutionApproval {
    pub fn approval_id(&self) -> &str {
        &self.0.approval_id
    }

    pub fn approver_key_id(&self) -> &str {
        &self.0.approver_key_id
    }

    pub fn nonce(&self) -> &[u8; 16] {
        &self.0.nonce
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.0.expires_unix_ms
    }

    pub fn approved_scope(&self) -> &[String] {
        &self.0.approved_scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_evolution::{
        FindingCategory, FindingSeverity, ProposedChange, ProposedChangeKind, SelfEvolutionFinding,
        SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn target() -> ProposalTarget {
        ProposalTarget {
            repository: "asifshadab33/UJANI-ENTERPRISE-AI".into(),
            base_ref: "main".into(),
            source_revision: "a".repeat(40),
        }
    }

    fn proposal() -> SelfEvolutionProposalV1 {
        SelfEvolutionProposalV1 {
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
        }
    }

    fn signed_approval(
        proposal: &SelfEvolutionProposalV1,
        target: &ProposalTarget,
        signing_key: &SigningKey,
    ) -> SignedSelfEvolutionApproval {
        let claims = SelfEvolutionApprovalClaims {
            approval_id: "approval-001".into(),
            repository: target.repository.clone(),
            base_ref: target.base_ref.clone(),
            source_revision: target.source_revision.clone(),
            proposal_sha256: self_evolution_proposal_digest(proposal).unwrap(),
            approved_scope: vec!["apps/operator-console".into()],
            approver_key_id: "admin-key-01".into(),
            nonce: [7; 16],
            issued_at_unix_ms: 1_000,
            expires_unix_ms: 10_000,
        };
        let signature = signing_key
            .sign(&approval_signing_bytes(&claims))
            .to_bytes();
        SignedSelfEvolutionApproval { claims, signature }
    }

    #[test]
    fn accepts_exact_proposal_target_and_enrolled_admin_signature() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let proposal = proposal();
        let target = target();
        let signed = signed_approval(&proposal, &target, &key);
        let verified = verify_self_evolution_approval(
            &signed,
            &[("admin-key-01".into(), key.verifying_key())],
            &target,
            &proposal,
            2_000,
        )
        .unwrap();
        assert_eq!(verified.approval_id(), "approval-001");
        assert_eq!(verified.nonce(), &[7; 16]);
    }

    #[test]
    fn rejects_modified_proposal_after_approval() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let target = target();
        let signed = signed_approval(&proposal(), &target, &key);
        let mut changed = proposal();
        changed.summary = "A different proposal".into();
        assert_eq!(
            verify_self_evolution_approval(
                &signed,
                &[("admin-key-01".into(), key.verifying_key())],
                &target,
                &changed,
                2_000,
            ),
            Err(SelfEvolutionApprovalError::ProposalDigestMismatch)
        );
    }

    #[test]
    fn rejects_wrong_target_expiry_and_unknown_approver() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let target = target();
        let proposal = proposal();
        let signed = signed_approval(&proposal, &target, &key);
        let mut other_target = target.clone();
        other_target.base_ref = "release".into();
        assert_eq!(
            verify_self_evolution_approval(
                &signed,
                &[("admin-key-01".into(), key.verifying_key())],
                &other_target,
                &proposal,
                2_000,
            ),
            Err(SelfEvolutionApprovalError::InvalidClaims)
        );
        assert_eq!(
            verify_self_evolution_approval(&signed, &[], &target, &proposal, 2_000),
            Err(SelfEvolutionApprovalError::UnknownApproverKey)
        );
        assert_eq!(
            verify_self_evolution_approval(
                &signed,
                &[("admin-key-01".into(), key.verifying_key())],
                &target,
                &proposal,
                10_000,
            ),
            Err(SelfEvolutionApprovalError::InvalidClaims)
        );
    }

    #[test]
    fn rejects_tampered_signature_and_protected_scope() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let target = target();
        let proposal = proposal();
        let mut tampered = signed_approval(&proposal, &target, &key);
        tampered.claims.nonce = [8; 16];
        assert_eq!(
            verify_self_evolution_approval(
                &tampered,
                &[("admin-key-01".into(), key.verifying_key())],
                &target,
                &proposal,
                2_000,
            ),
            Err(SelfEvolutionApprovalError::InvalidSignature)
        );

        let mut protected = signed_approval(&proposal, &target, &key);
        protected.claims.approved_scope = vec!["crates/ujani-enterprise-policy".into()];
        protected.signature = key
            .sign(&approval_signing_bytes(&protected.claims))
            .to_bytes();
        assert_eq!(
            verify_self_evolution_approval(
                &protected,
                &[("admin-key-01".into(), key.verifying_key())],
                &target,
                &proposal,
                2_000,
            ),
            Err(SelfEvolutionApprovalError::InvalidProposal)
        );
    }
}
