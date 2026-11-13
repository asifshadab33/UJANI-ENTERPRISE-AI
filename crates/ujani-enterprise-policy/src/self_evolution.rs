//! Side-effect-free validator for model-authored Enterprise AI self-evolution proposals.
//!
//! This module validates untrusted proposal metadata and changed paths only. It does not
//! read repository files, generate patches, execute code, approve changes, sign artifacts,
//! install updates, or access the network.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION: u16 = 1;
pub const MAX_PROPOSAL_SCOPE_PATHS: usize = 32;
pub const MAX_PROPOSAL_FINDINGS: usize = 100;
pub const MAX_PROPOSAL_CHANGES: usize = 128;

const PROTECTED_PATHS: &[&str] = &[
    ".github/workflows",
    "scripts",
    "migrations",
    "Cargo.toml",
    "Cargo.lock",
    "crates/ujani-enterprise-policy",
    "apps/operator-console/package.json",
    "apps/operator-console/package-lock.json",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Bug, Reliability, Performance, Accessibility, Documentation,
    Feature, Compatibility, Privacy, Security,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposedChangeKind { Add, Modify, Delete }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProposalTarget {
    pub repository: String,
    pub base_ref: String,
    pub source_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfEvolutionFinding {
    pub category: FindingCategory,
    pub severity: FindingSeverity,
    pub path: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProposedChange {
    pub path: String,
    pub operation: ProposedChangeKind,
    pub summary: String,
    pub patch_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfEvolutionProposalV1 {
    pub schema_version: u16,
    pub proposal_id: String,
    pub target: ProposalTarget,
    pub summary: String,
    /// Relative file/directory prefixes explicitly approved for this proposal.
    pub scope: Vec<String>,
    pub findings: Vec<SelfEvolutionFinding>,
    pub changes: Vec<ProposedChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalValidationError {
    UnsupportedVersion, InvalidIdentifier, InvalidTarget, InvalidText, InvalidScope,
    InvalidPath, ProtectedPath, OutOfScope, DuplicatePath, TooManyFindings,
    TooManyChanges, InvalidLineRange, InvalidPatchDigest,
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && value.trim() == value
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_path_component(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".."
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!((parts.next(), parts.next(), parts.next()),
        (Some(owner), Some(repo), None) if valid_path_component(owner) && valid_path_component(repo))
}

fn valid_git_ref(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.starts_with('/')
        && !value.ends_with('/') && !value.contains("//") && !value.contains("..")
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && value.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && !part.ends_with(".lock"))
}

fn valid_revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_relative_path(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value.starts_with('/')
        || value.contains('\\') || value.contains(':')
        || value.bytes().any(|b| b.is_ascii_control()) {
        return false;
    }
    value.split('/').all(|part| valid_path_component(part) && !part.eq_ignore_ascii_case(".git"))
}

fn is_protected_path(path: &str) -> bool {
    let candidate = path.to_ascii_lowercase();
    PROTECTED_PATHS.iter().any(|protected| {
        let protected = protected.to_ascii_lowercase();
        candidate == protected || candidate.starts_with(&(protected + "/"))
    })
}

fn path_is_in_scope(path: &str, scope: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let scope = scope.to_ascii_lowercase();
    path == scope || path.starts_with(&(scope + "/"))
}

fn valid_patch_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl SelfEvolutionProposalV1 {
    /// Validate an untrusted proposal before any file write is considered.
    /// The caller must separately bind repository/revision to trusted checkout state.
    pub fn validate(&self) -> Result<(), ProposalValidationError> {
        if self.schema_version != SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION {
            return Err(ProposalValidationError::UnsupportedVersion);
        }
        if !valid_identifier(&self.proposal_id, 128) {
            return Err(ProposalValidationError::InvalidIdentifier);
        }
        if !valid_repository(&self.target.repository) || !valid_git_ref(&self.target.base_ref)
            || !valid_revision(&self.target.source_revision) {
            return Err(ProposalValidationError::InvalidTarget);
        }
        if !valid_text(&self.summary, 2_000) {
            return Err(ProposalValidationError::InvalidText);
        }
        if self.scope.is_empty() || self.scope.len() > MAX_PROPOSAL_SCOPE_PATHS {
            return Err(ProposalValidationError::InvalidScope);
        }

        let mut scopes = BTreeSet::new();
        for scope in &self.scope {
            if !valid_relative_path(scope) {
                return Err(ProposalValidationError::InvalidScope);
            }
            if is_protected_path(scope) {
                return Err(ProposalValidationError::ProtectedPath);
            }
            if !scopes.insert(scope.to_ascii_lowercase()) {
                return Err(ProposalValidationError::DuplicatePath);
            }
        }

        if self.findings.len() > MAX_PROPOSAL_FINDINGS {
            return Err(ProposalValidationError::TooManyFindings);
        }
        for finding in &self.findings {
            if !valid_relative_path(&finding.path) || !valid_text(&finding.description, 3_000)
                || !valid_text(&finding.recommendation, 3_000) {
                return Err(ProposalValidationError::InvalidPath);
            }
            match (finding.line_start, finding.line_end) {
                (None, None) => {}
                (Some(start), Some(end)) if start > 0 && end >= start && end <= 10_000_000 => {}
                _ => return Err(ProposalValidationError::InvalidLineRange),
            }
        }

        if self.changes.len() > MAX_PROPOSAL_CHANGES {
            return Err(ProposalValidationError::TooManyChanges);
        }
        let mut changed_paths = BTreeSet::new();
        for change in &self.changes {
            if !valid_relative_path(&change.path) || !valid_text(&change.summary, 1_000) {
                return Err(ProposalValidationError::InvalidPath);
            }
            if is_protected_path(&change.path) {
                return Err(ProposalValidationError::ProtectedPath);
            }
            if !self.scope.iter().any(|scope| path_is_in_scope(&change.path, scope)) {
                return Err(ProposalValidationError::OutOfScope);
            }
            if !changed_paths.insert(change.path.to_ascii_lowercase()) {
                return Err(ProposalValidationError::DuplicatePath);
            }
            if !valid_patch_digest(&change.patch_sha256) {
                return Err(ProposalValidationError::InvalidPatchDigest);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_proposal() -> SelfEvolutionProposalV1 {
        SelfEvolutionProposalV1 {
            schema_version: SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
            proposal_id: "proposal-2026-001".into(),
            target: ProposalTarget {
                repository: "asifshadab33/UJANI-ENTERPRISE-AI".into(),
                base_ref: "main".into(),
                source_revision: "a".repeat(40),
            },
            summary: "Improve the operator console presentation.".into(),
            scope: vec!["apps/operator-console".into()],
            findings: vec![SelfEvolutionFinding {
                category: FindingCategory::Accessibility,
                severity: FindingSeverity::Low,
                path: "apps/desktop/src/app.js".into(),
                line_start: Some(10), line_end: Some(15),
                description: "The operator status label is not explicit.".into(),
                recommendation: "Add an accessible label.".into(),
            }],
            changes: vec![ProposedChange {
                path: "apps/desktop/src/app.js".into(),
                operation: ProposedChangeKind::Modify,
                summary: "Add an accessible label to the operator status control.".into(),
                patch_sha256: "b".repeat(64),
            }],
        }
    }

    #[test]
    fn accepts_a_scoped_non_core_proposal() {
        assert_eq!(valid_proposal().validate(), Ok(()));
    }

    #[test]
    fn rejects_path_traversal_and_absolute_paths() {
        let mut proposal = valid_proposal();
        proposal.changes[0].path = "../security_store.rs".into();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::InvalidPath));
        proposal.changes[0].path = "/tmp/generated.rs".into();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::InvalidPath));
    }

    #[test]
    fn rejects_protected_core_changes_case_insensitively() {
        let mut proposal = valid_proposal();
        proposal.scope = vec!["apps/desktop/src-tauri/src".into()];
        proposal.changes[0].path = "apps/desktop/src-tauri/src/SECURITY_STORE.rs".into();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::ProtectedPath));
    }

    #[test]
    fn rejects_changes_outside_the_user_approved_scope_case_insensitively() {
        let mut proposal = valid_proposal();
        proposal.scope = vec!["apps/desktop/src/app.js".into()];
        proposal.changes[0].path = "APPS/desktop/src/styles.css".into();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::OutOfScope));
    }

    #[test]
    fn rejects_duplicate_paths_and_invalid_patch_digests() {
        let mut proposal = valid_proposal();
        proposal.changes.push(proposal.changes[0].clone());
        assert_eq!(proposal.validate(), Err(ProposalValidationError::DuplicatePath));
        let mut proposal = valid_proposal();
        proposal.changes[0].patch_sha256 = "not-a-digest".into();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::InvalidPatchDigest));
    }

    #[test]
    fn rejects_invalid_revision_and_unknown_schema_version() {
        let mut proposal = valid_proposal();
        proposal.target.source_revision = "not-a-commit".into();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::InvalidTarget));
        let mut proposal = valid_proposal();
        proposal.schema_version = 2;
        assert_eq!(proposal.validate(), Err(ProposalValidationError::UnsupportedVersion));
    }

    #[test]
    fn rejects_protected_scopes_and_excessive_change_counts() {
        let mut proposal = valid_proposal();
        proposal.scope = vec![".github/workflows".into()];
        assert_eq!(proposal.validate(), Err(ProposalValidationError::ProtectedPath));
        let mut proposal = valid_proposal();
        proposal.changes = (0..=MAX_PROPOSAL_CHANGES).map(|index| ProposedChange {
            path: format!("apps/desktop/src/Component{index}.tsx"),
            operation: ProposedChangeKind::Add,
            summary: "Add a scoped component.".into(),
            patch_sha256: "c".repeat(64),
        }).collect();
        assert_eq!(proposal.validate(), Err(ProposalValidationError::TooManyChanges));
    }
}
