//! Side-effect-free validator for model-authored self-evolution proposals.
//!
//! The model supplies findings and proposed changes only. Repository identity,
//! source revision, approved write scope, proposal ID, model identity and approval
//! are supplied and recorded by trusted host code. This module performs no file
//! access, patch application, code execution, signing, installation or networking.

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

/// Trusted host context. Never accept this value as model-authored authority.
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

/// Untrusted model output. Trusted task identity and permissions are deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfEvolutionProposalV1 {
    pub schema_version: u16,
    pub summary: String,
    pub findings: Vec<SelfEvolutionFinding>,
    pub changes: Vec<ProposedChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalValidationError {
    UnsupportedVersion,
    InvalidTarget,
    InvalidText,
    InvalidScope,
    InvalidPath,
    ProtectedPath,
    OutOfScope,
    DuplicatePath,
    TooManyFindings,
    TooManyChanges,
    InvalidLineRange,
    InvalidPatchDigest,
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_path_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(owner), Some(repository), None)
            if valid_path_component(owner) && valid_path_component(repository)
    )
}

fn valid_git_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(".lock")
        })
}

fn valid_revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }

    value
        .split('/')
        .all(|part| valid_path_component(part) && !part.eq_ignore_ascii_case(".git"))
}

fn is_protected_path(path: &str) -> bool {
    let candidate = path.to_ascii_lowercase();
    let contains_secret_material = candidate.split('/').any(|segment| {
        segment == ".env"
            || segment.starts_with(".env.")
            || segment == ".ssh"
            || segment == ".npmrc"
            || segment == ".pypirc"
            || segment == ".netrc"
            || segment == ".aws"
            || segment == ".azure"
            || segment == ".kube"
            || segment == ".docker"
            || segment == ".git-credentials"
            || segment == "kubeconfig"
            || segment == "service_account.json"
            || segment == "token"
            || segment == "access_token"
            || segment == "refresh_token"
            || segment == "credentials"
            || segment == "secret"
            || segment == "secrets"
            || segment == "id_rsa"
            || segment == "id_ed25519"
            || segment.starts_with("credentials.")
            || segment.starts_with("secret.")
            || segment.starts_with("secrets.")
            || segment.ends_with(".secret")
            || segment.ends_with(".pem")
            || segment.ends_with(".key")
            || segment.ends_with(".p12")
            || segment.ends_with(".pfx")
            || segment.ends_with(".jks")
            || segment.ends_with(".keystore")
            || segment.ends_with(".crt")
            || segment.ends_with(".p8")
    });

    contains_secret_material
        || PROTECTED_PATHS.iter().any(|protected| {
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
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl SelfEvolutionProposalV1 {
    /// Validate model output against repository and scope supplied by trusted host code.
    /// The model cannot choose or widen either value.
    pub fn validate_against(
        &self,
        trusted_target: &ProposalTarget,
        approved_scope: &[String],
    ) -> Result<(), ProposalValidationError> {
        if !valid_repository(&trusted_target.repository)
            || !valid_git_ref(&trusted_target.base_ref)
            || !valid_revision(&trusted_target.source_revision)
        {
            return Err(ProposalValidationError::InvalidTarget);
        }
        if self.schema_version != SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION {
            return Err(ProposalValidationError::UnsupportedVersion);
        }
        if !valid_text(&self.summary, 2_000) {
            return Err(ProposalValidationError::InvalidText);
        }
        if approved_scope.is_empty() || approved_scope.len() > MAX_PROPOSAL_SCOPE_PATHS {
            return Err(ProposalValidationError::InvalidScope);
        }

        let mut scopes = BTreeSet::new();
        for scope in approved_scope {
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
            if !valid_relative_path(&finding.path)
                || !valid_text(&finding.description, 3_000)
                || !valid_text(&finding.recommendation, 3_000)
            {
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
            if !approved_scope
                .iter()
                .any(|scope| path_is_in_scope(&change.path, scope))
            {
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

    fn trusted_target() -> ProposalTarget {
        ProposalTarget {
            repository: "asifshadab33/UJANI-ENTERPRISE-AI".into(),
            base_ref: "main".into(),
            source_revision: "a".repeat(40),
        }
    }

    fn approved_scope() -> Vec<String> {
        vec!["apps/operator-console".into()]
    }

    fn valid_proposal() -> SelfEvolutionProposalV1 {
        SelfEvolutionProposalV1 {
            schema_version: SELF_EVOLUTION_PROPOSAL_SCHEMA_VERSION,
            summary: "Improve an accessible label in a non-core interface module.".into(),
            findings: vec![SelfEvolutionFinding {
                category: FindingCategory::Accessibility,
                severity: FindingSeverity::Low,
                path: "apps/operator-console/app.js".into(),
                line_start: Some(10),
                line_end: Some(15),
                description: "The result label is not explicit.".into(),
                recommendation: "Add an accessible label.".into(),
            }],
            changes: vec![ProposedChange {
                path: "apps/operator-console/app.js".into(),
                operation: ProposedChangeKind::Modify,
                summary: "Add an accessible label to the result control.".into(),
                patch_sha256: "b".repeat(64),
            }],
        }
    }

    fn validate(proposal: &SelfEvolutionProposalV1, scope: &[String]) -> Result<(), ProposalValidationError> {
        proposal.validate_against(&trusted_target(), scope)
    }

    #[test]
    fn accepts_a_scoped_non_core_proposal() {
        assert_eq!(validate(&valid_proposal(), &approved_scope()), Ok(()));
    }

    #[test]
    fn rejects_path_traversal_and_absolute_paths() {
        let mut proposal = valid_proposal();
        proposal.changes[0].path = "../security_store.rs".into();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::InvalidPath));
        proposal.changes[0].path = "/tmp/generated.rs".into();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::InvalidPath));
    }

    #[test]
    fn rejects_protected_core_changes_case_insensitively() {
        let mut proposal = valid_proposal();
        proposal.changes[0].path = "crates/ujani-enterprise-policy/src/device_trust.rs".into();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::ProtectedPath));
    }

    #[test]
    fn rejects_changes_outside_the_host_approved_scope_case_insensitively() {
        let mut proposal = valid_proposal();
        proposal.changes[0].path = "APPS/operator-console/styles.css".into();
        let scope = vec!["apps/operator-console/app.js".into()];
        assert_eq!(validate(&proposal, &scope), Err(ProposalValidationError::OutOfScope));
    }

    #[test]
    fn rejects_duplicate_paths_and_invalid_patch_digests() {
        let mut proposal = valid_proposal();
        proposal.changes.push(proposal.changes[0].clone());
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::DuplicatePath));
        let mut proposal = valid_proposal();
        proposal.changes[0].patch_sha256 = "not-a-digest".into();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::InvalidPatchDigest));
    }

    #[test]
    fn rejects_invalid_trusted_target_and_unknown_schema_version() {
        let mut target = trusted_target();
        target.source_revision = "not-a-commit".into();
        assert_eq!(valid_proposal().validate_against(&target, &approved_scope()), Err(ProposalValidationError::InvalidTarget));
        let mut proposal = valid_proposal();
        proposal.schema_version = 2;
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::UnsupportedVersion));
    }

    #[test]
    fn rejects_protected_or_invalid_host_scopes() {
        let protected = vec![".github/workflows".into()];
        assert_eq!(validate(&valid_proposal(), &protected), Err(ProposalValidationError::ProtectedPath));
        let traversal = vec!["../".into()];
        assert_eq!(validate(&valid_proposal(), &traversal), Err(ProposalValidationError::InvalidScope));
    }

    #[test]
    fn rejects_secret_and_credential_bundle_paths() {
        let mut proposal = valid_proposal();
        proposal.changes[0].path = "apps/operator-console/.env.production".into();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::ProtectedPath));
        proposal.changes[0].path = "apps/operator-console/credentials.json".into();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::ProtectedPath));
    }

    #[test]
    fn rejects_invalid_finding_line_ranges_and_excessive_change_counts() {
        let mut proposal = valid_proposal();
        proposal.findings[0].line_start = Some(20);
        proposal.findings[0].line_end = Some(10);
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::InvalidLineRange));
        let mut proposal = valid_proposal();
        proposal.changes = (0..=MAX_PROPOSAL_CHANGES).map(|index| ProposedChange {
            path: format!("apps/operator-console/Component{index}.tsx"),
            operation: ProposedChangeKind::Add,
            summary: "Add a scoped component.".into(),
            patch_sha256: "c".repeat(64),
        }).collect();
        assert_eq!(validate(&proposal, &approved_scope()), Err(ProposalValidationError::TooManyChanges));
    }
}
