//! Side-effect-free validation of approved Enterprise Self-Evolution patch artifacts.
//!
//! A validated bundle is still only data. This module does not write files,
//! stage repository changes, execute generated code, install updates or roll back.
//! The host must obtain workspace file hashes through a root-bound, no-follow
//! filesystem reader before calling this validator.

use crate::self_evolution::{
    ProposalTarget, ProposalValidationError, ProposedChangeKind, SelfEvolutionProposalV1,
    MAX_PROPOSAL_CHANGES,
};
use crate::self_evolution_approval::self_evolution_proposal_digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SELF_EVOLUTION_PATCH_BUNDLE_SCHEMA_VERSION: u16 = 1;
pub const MAX_PATCH_FILE_BYTES: usize = 1_048_576;
pub const MAX_PATCH_TOTAL_BYTES: usize = 8_388_608;
const PATCH_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-SELF-EVOLUTION-PATCH-ARTIFACT-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfEvolutionPatchArtifactV1 {
    pub path: String,
    pub operation: ProposedChangeKind,
    /// SHA-256 of the exact existing file. Required for modify/delete; absent for add.
    pub base_sha256: Option<String>,
    /// Complete UTF-8 replacement content for add/modify; absent for delete.
    pub new_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfEvolutionPatchBundleV1 {
    pub schema_version: u16,
    /// Digest of the exact proposal approved by the human approver.
    pub proposal_sha256: String,
    pub artifacts: Vec<SelfEvolutionPatchArtifactV1>,
}

/// Trusted host snapshot of one path in the selected workspace.
/// A missing SHA-256 means the path did not exist when the snapshot was taken.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceFileState {
    pub path: String,
    pub sha256: Option<String>,
}

/// Constructible only by successful validation. This is not an install permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSelfEvolutionPatchBundleV1 {
    proposal_sha256: String,
    artifacts: Vec<SelfEvolutionPatchArtifactV1>,
    total_content_bytes: usize,
}

impl ValidatedSelfEvolutionPatchBundleV1 {
    pub fn proposal_sha256(&self) -> &str {
        &self.proposal_sha256
    }

    pub fn artifacts(&self) -> &[SelfEvolutionPatchArtifactV1] {
        &self.artifacts
    }

    pub fn total_content_bytes(&self) -> usize {
        self.total_content_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionPatchValidationError {
    Proposal(ProposalValidationError),
    InvalidBundleVersion,
    InvalidProposalDigest,
    WorkspaceRevisionMismatch,
    EmptyPatchBundle,
    TooManyArtifacts,
    ArtifactCountMismatch,
    DuplicateArtifact,
    MissingArtifact,
    ArtifactPathMismatch,
    ArtifactOperationMismatch,
    InvalidBaseDigest,
    InvalidContent,
    ContentTooLarge,
    TotalContentTooLarge,
    PatchDigestMismatch,
    WorkspaceSnapshotMismatch,
    InvalidWorkspaceSnapshot,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_content(value: &str) -> bool {
    !value.as_bytes().contains(&0)
        && !value.chars().any(|character| {
            (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

fn operation_tag(operation: ProposedChangeKind) -> &'static [u8] {
    match operation {
        ProposedChangeKind::Add => b"add",
        ProposedChangeKind::Modify => b"modify",
        ProposedChangeKind::Delete => b"delete",
    }
}

fn add_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Stable digest binding the path, operation, base file hash and replacement bytes.
/// The proposal's patch_sha256 must equal this digest before approval can be used.
pub fn patch_artifact_sha256(artifact: &SelfEvolutionPatchArtifactV1) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PATCH_DOMAIN);
    add_field(&mut hasher, artifact.path.as_bytes());
    add_field(&mut hasher, operation_tag(artifact.operation));
    match &artifact.base_sha256 {
        Some(value) => {
            hasher.update([1]);
            add_field(&mut hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
    match &artifact.new_content {
        Some(value) => {
            hasher.update([1]);
            add_field(&mut hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Validate exact proposal, approval digest, target revision, approved scope,
/// patch contents and the trusted workspace snapshot. No filesystem access occurs.
pub fn validate_patch_bundle(
    proposal: &SelfEvolutionProposalV1,
    trusted_target: &ProposalTarget,
    approved_scope: &[String],
    approved_proposal_sha256: &str,
    workspace_revision: &str,
    bundle: &SelfEvolutionPatchBundleV1,
    workspace_files: &[WorkspaceFileState],
) -> Result<ValidatedSelfEvolutionPatchBundleV1, SelfEvolutionPatchValidationError> {
    proposal
        .validate_against(trusted_target, approved_scope)
        .map_err(SelfEvolutionPatchValidationError::Proposal)?;

    if bundle.schema_version != SELF_EVOLUTION_PATCH_BUNDLE_SCHEMA_VERSION {
        return Err(SelfEvolutionPatchValidationError::InvalidBundleVersion);
    }
    if proposal.changes.is_empty() || bundle.artifacts.is_empty() {
        return Err(SelfEvolutionPatchValidationError::EmptyPatchBundle);
    }
    if bundle.artifacts.len() > MAX_PROPOSAL_CHANGES {
        return Err(SelfEvolutionPatchValidationError::TooManyArtifacts);
    }
    if bundle.artifacts.len() != proposal.changes.len()
        || workspace_files.len() != proposal.changes.len()
    {
        return Err(SelfEvolutionPatchValidationError::ArtifactCountMismatch);
    }
    if !workspace_revision.eq_ignore_ascii_case(&trusted_target.source_revision) {
        return Err(SelfEvolutionPatchValidationError::WorkspaceRevisionMismatch);
    }

    let computed_digest = self_evolution_proposal_digest(proposal)
        .map_err(|_| SelfEvolutionPatchValidationError::InvalidProposalDigest)?;
    let computed_proposal_digest = hex(&computed_digest);
    if !valid_sha256(approved_proposal_sha256)
        || !computed_proposal_digest.eq_ignore_ascii_case(approved_proposal_sha256)
        || !bundle
            .proposal_sha256
            .eq_ignore_ascii_case(&computed_proposal_digest)
    {
        return Err(SelfEvolutionPatchValidationError::InvalidProposalDigest);
    }

    let mut artifacts_by_path = BTreeMap::new();
    for artifact in &bundle.artifacts {
        let key = artifact.path.to_ascii_lowercase();
        if artifacts_by_path.insert(key, artifact).is_some() {
            return Err(SelfEvolutionPatchValidationError::DuplicateArtifact);
        }
    }
    let mut workspace_by_path = BTreeMap::new();
    for state in workspace_files {
        let key = state.path.to_ascii_lowercase();
        if let Some(digest) = &state.sha256 {
            if !valid_sha256(digest) {
                return Err(SelfEvolutionPatchValidationError::InvalidWorkspaceSnapshot);
            }
        }
        if workspace_by_path.insert(key, state).is_some() {
            return Err(SelfEvolutionPatchValidationError::InvalidWorkspaceSnapshot);
        }
    }

    let mut total_content_bytes = 0usize;
    for change in &proposal.changes {
        let key = change.path.to_ascii_lowercase();
        let artifact = artifacts_by_path
            .get(&key)
            .ok_or(SelfEvolutionPatchValidationError::MissingArtifact)?;
        let workspace_state = workspace_by_path
            .get(&key)
            .ok_or(SelfEvolutionPatchValidationError::InvalidWorkspaceSnapshot)?;

        if artifact.path != change.path || workspace_state.path != change.path {
            return Err(SelfEvolutionPatchValidationError::ArtifactPathMismatch);
        }
        if artifact.operation != change.operation {
            return Err(SelfEvolutionPatchValidationError::ArtifactOperationMismatch);
        }
        if !valid_sha256(&change.patch_sha256)
            || !patch_artifact_sha256(artifact).eq_ignore_ascii_case(&change.patch_sha256)
        {
            return Err(SelfEvolutionPatchValidationError::PatchDigestMismatch);
        }

        match (
            artifact.operation,
            &artifact.base_sha256,
            &artifact.new_content,
            &workspace_state.sha256,
        ) {
            (ProposedChangeKind::Add, None, Some(content), None) => {
                if !valid_content(content) {
                    return Err(SelfEvolutionPatchValidationError::InvalidContent);
                }
                let size = content.len();
                if size > MAX_PATCH_FILE_BYTES {
                    return Err(SelfEvolutionPatchValidationError::ContentTooLarge);
                }
                total_content_bytes = total_content_bytes.saturating_add(size);
            }
            (ProposedChangeKind::Modify, Some(base), Some(content), Some(current))
                if valid_sha256(base) && base.eq_ignore_ascii_case(current) =>
            {
                if !valid_content(content) {
                    return Err(SelfEvolutionPatchValidationError::InvalidContent);
                }
                let size = content.len();
                if size > MAX_PATCH_FILE_BYTES {
                    return Err(SelfEvolutionPatchValidationError::ContentTooLarge);
                }
                total_content_bytes = total_content_bytes.saturating_add(size);
            }
            (ProposedChangeKind::Delete, Some(base), None, Some(current))
                if valid_sha256(base) && base.eq_ignore_ascii_case(current) => {}
            (ProposedChangeKind::Modify | ProposedChangeKind::Delete, Some(base), _, _)
                if !valid_sha256(base) =>
            {
                return Err(SelfEvolutionPatchValidationError::InvalidBaseDigest);
            }
            _ => return Err(SelfEvolutionPatchValidationError::WorkspaceSnapshotMismatch),
        }

        if total_content_bytes > MAX_PATCH_TOTAL_BYTES {
            return Err(SelfEvolutionPatchValidationError::TotalContentTooLarge);
        }
    }

    Ok(ValidatedSelfEvolutionPatchBundleV1 {
        proposal_sha256: computed_proposal_digest,
        artifacts: bundle.artifacts.clone(),
        total_content_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::self_evolution::{
        FindingCategory, FindingSeverity, ProposedChange, SelfEvolutionFinding,
        SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
    };

    fn target() -> ProposalTarget {
        ProposalTarget {
            repository: "asifshadab33/UJANI-ENTERPRISE-AI".into(),
            base_ref: "main".into(),
            source_revision: "a".repeat(40),
        }
    }

    fn scope() -> Vec<String> {
        vec!["apps/operator-console".into()]
    }

    fn setup_modify() -> (
        SelfEvolutionProposalV1,
        SelfEvolutionPatchBundleV1,
        Vec<WorkspaceFileState>,
        String,
    ) {
        let mut proposal = SelfEvolutionProposalV1 {
            schema_version: SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
            summary: "Improve a non-core operator-console label.".into(),
            findings: vec![SelfEvolutionFinding {
                category: FindingCategory::Accessibility,
                severity: FindingSeverity::Low,
                path: "apps/operator-console/app.js".into(),
                line_start: Some(1),
                line_end: Some(2),
                description: "The result label is unclear.".into(),
                recommendation: "Use an explicit accessible label.".into(),
            }],
            changes: vec![ProposedChange {
                path: "apps/operator-console/app.js".into(),
                operation: ProposedChangeKind::Modify,
                summary: "Add an accessible label.".into(),
                patch_sha256: "0".repeat(64),
            }],
        };
        let artifact = SelfEvolutionPatchArtifactV1 {
            path: proposal.changes[0].path.clone(),
            operation: ProposedChangeKind::Modify,
            base_sha256: Some("b".repeat(64)),
            new_content: Some("const label = 'Results';\n".into()),
        };
        proposal.changes[0].patch_sha256 = patch_artifact_sha256(&artifact);
        let digest = hex(&self_evolution_proposal_digest(&proposal).unwrap());
        let bundle = SelfEvolutionPatchBundleV1 {
            schema_version: SELF_EVOLUTION_PATCH_BUNDLE_SCHEMA_VERSION,
            proposal_sha256: digest.clone(),
            artifacts: vec![artifact],
        };
        let workspace = vec![WorkspaceFileState {
            path: proposal.changes[0].path.clone(),
            sha256: Some("b".repeat(64)),
        }];
        (proposal, bundle, workspace, digest)
    }

    #[test]
    fn accepts_exact_approved_patch_and_workspace_revision() {
        let (proposal, bundle, workspace, digest) = setup_modify();
        let validated = validate_patch_bundle(
            &proposal,
            &target(),
            &scope(),
            &digest,
            &"a".repeat(40),
            &bundle,
            &workspace,
        )
        .unwrap();
        assert_eq!(validated.proposal_sha256(), digest);
        assert_eq!(validated.artifacts().len(), 1);
        assert!(validated.total_content_bytes() > 0);
    }

    #[test]
    fn rejects_tampered_patch_and_mismatched_approval() {
        let (proposal, mut bundle, workspace, digest) = setup_modify();
        bundle.artifacts[0].new_content = Some("different content".into());
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::PatchDigestMismatch)
        );
        let (proposal, bundle, workspace, digest) = setup_modify();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &"f".repeat(64),
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::InvalidProposalDigest)
        );
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn rejects_stale_workspace_and_wrong_source_revision() {
        let (proposal, bundle, mut workspace, digest) = setup_modify();
        workspace[0].sha256 = Some("c".repeat(64));
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::WorkspaceSnapshotMismatch)
        );
        let (proposal, bundle, workspace, digest) = setup_modify();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"d".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::WorkspaceRevisionMismatch)
        );
    }

    #[test]
    fn add_and_delete_require_exact_workspace_preconditions() {
        let mut proposal = SelfEvolutionProposalV1 {
            schema_version: SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
            summary: "Add and remove non-core files.".into(),
            findings: vec![],
            changes: vec![
                ProposedChange {
                    path: "apps/operator-console/NewPanel.js".into(),
                    operation: ProposedChangeKind::Add,
                    summary: "Add panel.".into(),
                    patch_sha256: "0".repeat(64),
                },
                ProposedChange {
                    path: "apps/operator-console/OldPanel.js".into(),
                    operation: ProposedChangeKind::Delete,
                    summary: "Remove obsolete panel.".into(),
                    patch_sha256: "0".repeat(64),
                },
            ],
        };
        let artifacts = vec![
            SelfEvolutionPatchArtifactV1 {
                path: proposal.changes[0].path.clone(),
                operation: ProposedChangeKind::Add,
                base_sha256: None,
                new_content: Some("export {}\n".into()),
            },
            SelfEvolutionPatchArtifactV1 {
                path: proposal.changes[1].path.clone(),
                operation: ProposedChangeKind::Delete,
                base_sha256: Some("e".repeat(64)),
                new_content: None,
            },
        ];
        for (change, artifact) in proposal.changes.iter_mut().zip(artifacts.iter()) {
            change.patch_sha256 = patch_artifact_sha256(artifact);
        }
        let digest = hex(&self_evolution_proposal_digest(&proposal).unwrap());
        let bundle = SelfEvolutionPatchBundleV1 {
            schema_version: 1,
            proposal_sha256: digest.clone(),
            artifacts,
        };
        let workspace = vec![
            WorkspaceFileState {
                path: proposal.changes[0].path.clone(),
                sha256: None,
            },
            WorkspaceFileState {
                path: proposal.changes[1].path.clone(),
                sha256: Some("e".repeat(64)),
            },
        ];
        assert!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            )
            .is_ok()
        );

        let mut duplicate_bundle = bundle.clone();
        duplicate_bundle.artifacts[1].path = duplicate_bundle.artifacts[0].path.clone();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &duplicate_bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::DuplicateArtifact)
        );

        let mut missing_bundle = bundle.clone();
        missing_bundle.artifacts[1].path = "apps/operator-console/Missing.js".into();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &missing_bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::MissingArtifact)
        );

        let mut wrong_workspace = workspace.clone();
        wrong_workspace[0].sha256 = Some("1".repeat(64));
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &wrong_workspace
            ),
            Err(SelfEvolutionPatchValidationError::WorkspaceSnapshotMismatch)
        );
    }

    #[test]
    fn rejects_artifact_count_mismatch_and_wrong_operation() {
        let (proposal, mut bundle, workspace, digest) = setup_modify();
        bundle.artifacts.push(bundle.artifacts[0].clone());
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::ArtifactCountMismatch)
        );
        let (proposal, mut bundle, workspace, digest) = setup_modify();
        bundle.artifacts.clear();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::EmptyPatchBundle)
        );
        let (proposal, mut bundle, workspace, digest) = setup_modify();
        bundle.artifacts[0].operation = ProposedChangeKind::Delete;
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::ArtifactOperationMismatch)
        );
    }

    #[test]
    fn rejects_oversized_and_unsafe_content() {
        let (mut proposal, mut bundle, workspace, _) = setup_modify();
        bundle.artifacts[0].new_content = Some("x".repeat(MAX_PATCH_FILE_BYTES + 1));
        proposal.changes[0].patch_sha256 = patch_artifact_sha256(&bundle.artifacts[0]);
        let digest = hex(&self_evolution_proposal_digest(&proposal).unwrap());
        bundle.proposal_sha256 = digest.clone();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::ContentTooLarge)
        );

        let (mut proposal, mut bundle, workspace, _) = setup_modify();
        bundle.artifacts[0].new_content = Some("unsafe\0content".into());
        proposal.changes[0].patch_sha256 = patch_artifact_sha256(&bundle.artifacts[0]);
        let digest = hex(&self_evolution_proposal_digest(&proposal).unwrap());
        bundle.proposal_sha256 = digest.clone();
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::InvalidContent)
        );
    }
    #[test]
    fn rejects_total_patch_size_over_limit() {
        let mut proposal = SelfEvolutionProposalV1 {
            schema_version: SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
            summary: "Validate the aggregate patch size limit.".into(),
            findings: vec![],
            changes: Vec::new(),
        };
        let mut artifacts = Vec::new();
        let mut workspace = Vec::new();
        for index in 0..9 {
            let path = format!("apps/operator-console/generated-{index}.js");
            let content = if index == 8 {
                "x".to_string()
            } else {
                "x".repeat(MAX_PATCH_FILE_BYTES)
            };
            let artifact = SelfEvolutionPatchArtifactV1 {
                path: path.clone(),
                operation: ProposedChangeKind::Modify,
                base_sha256: Some("b".repeat(64)),
                new_content: Some(content),
            };
            proposal.changes.push(ProposedChange {
                path: path.clone(),
                operation: ProposedChangeKind::Modify,
                summary: format!("Update generated file {index}."),
                patch_sha256: patch_artifact_sha256(&artifact),
            });
            artifacts.push(artifact);
            workspace.push(WorkspaceFileState {
                path,
                sha256: Some("b".repeat(64)),
            });
        }
        let digest = hex(&self_evolution_proposal_digest(&proposal).unwrap());
        let bundle = SelfEvolutionPatchBundleV1 {
            schema_version: SELF_EVOLUTION_PATCH_BUNDLE_SCHEMA_VERSION,
            proposal_sha256: digest.clone(),
            artifacts,
        };
        assert_eq!(
            validate_patch_bundle(
                &proposal,
                &target(),
                &scope(),
                &digest,
                &"a".repeat(40),
                &bundle,
                &workspace
            ),
            Err(SelfEvolutionPatchValidationError::TotalContentTooLarge)
        );
    }

}
