//! Enterprise administrator policy for the optional Self-Evolution module.
//!
//! This is a side-effect-free authorization contract. It does not install a
//! module, access source repositories, apply patches, execute code, sign builds
//! or deploy artifacts. The authenticated control plane must supply the policy
//! and approval evidence; worker devices must never evaluate model authority.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleInstallState {
    NotInstalled,
    Installed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionBlock {
    ModuleNotInstalled,
    AdministratorProhibited,
    AdministratorActivationRequired,
    ModelNotApproved,
    ScopeNotApproved,
    ProtectedScope,
    TrustedBuildEnvironmentRequired,
    PrimaryApprovalRequired,
    SecondaryApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseSelfEvolutionPolicy {
    /// False is the default and must override any endpoint/user preference.
    pub permitted_by_administrator: bool,
    /// Separate from permission: administrator must explicitly activate the module.
    pub activated_by_administrator: bool,
    pub approved_model_ids: BTreeSet<String>,
    pub approved_write_scopes: BTreeSet<String>,
    pub require_dual_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEvolutionRequest {
    pub selected_model_id: String,
    pub requested_write_scope: String,
    pub trusted_source_and_build_environment_configured: bool,
    pub primary_approval_present: bool,
    pub secondary_approval_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfEvolutionPermission {
    pub may_analyse: bool,
    pub may_prepare_proposals: bool,
    /// Only authorizes moving a proposal into the trusted review pipeline.
    /// It does not authorize applying, executing, signing or deploying changes.
    pub may_submit_for_review: bool,
    pub blocked_by: Option<SelfEvolutionBlock>,
}

const PROTECTED_SCOPES: &[&str] = &[
    ".github/workflows",
    "scripts",
    "migrations",
    "Cargo.toml",
    "Cargo.lock",
    "crates/ujani-enterprise-policy",
    "apps/operator-console/package.json",
    "apps/operator-console/package-lock.json",
];

fn is_protected_scope(value: &str) -> bool {
    let candidate = value.to_ascii_lowercase();
    PROTECTED_SCOPES.iter().any(|protected| {
        let protected = protected.to_ascii_lowercase();
        candidate == protected
            || candidate.starts_with(&(protected.clone() + "/"))
            || protected.starts_with(&(candidate.clone() + "/"))
    }) || candidate.split('/').any(|segment| {
        segment == ".env"
            || segment.starts_with(".env.")
            || segment == ".ssh"
            || segment == ".npmrc"
            || segment == ".netrc"
            || segment == "credentials"
            || segment == "secrets"
            || segment.ends_with(".pem")
            || segment.ends_with(".key")
            || segment.ends_with(".p12")
            || segment.ends_with(".pfx")
    })
}

fn normalize_scope(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 512 || value.starts_with('/') || value.contains('\\') {
        return None;
    }
    let segments: Vec<&str> = value.split('/').collect();
    if segments.iter().any(|segment| {
        segment.is_empty()
            || *segment == "."
            || *segment == ".."
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    }) {
        return None;
    }
    Some(segments.join("/").to_ascii_lowercase())
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte))
}

pub fn evaluate_enterprise_self_evolution(
    installation: ModuleInstallState,
    policy: &EnterpriseSelfEvolutionPolicy,
    request: &SelfEvolutionRequest,
) -> SelfEvolutionPermission {
    let normalized_scope = normalize_scope(&request.requested_write_scope);
    let blocked_by = if installation == ModuleInstallState::NotInstalled {
        Some(SelfEvolutionBlock::ModuleNotInstalled)
    } else if !policy.permitted_by_administrator {
        Some(SelfEvolutionBlock::AdministratorProhibited)
    } else if !policy.activated_by_administrator {
        Some(SelfEvolutionBlock::AdministratorActivationRequired)
    } else if !valid_identifier(&request.selected_model_id)
        || !policy
            .approved_model_ids
            .contains(&request.selected_model_id)
    {
        Some(SelfEvolutionBlock::ModelNotApproved)
    } else if normalized_scope.is_none()
        || !policy.approved_write_scopes.iter().any(|approved| {
            normalize_scope(approved)
                .zip(normalized_scope.as_ref())
                .is_some_and(|(approved, requested)| {
                    requested == &approved || requested.starts_with(&(approved + "/"))
                })
        })
    {
        Some(SelfEvolutionBlock::ScopeNotApproved)
    } else if is_protected_scope(normalized_scope.as_deref().unwrap_or_default()) {
        Some(SelfEvolutionBlock::ProtectedScope)
    } else if !request.trusted_source_and_build_environment_configured {
        Some(SelfEvolutionBlock::TrustedBuildEnvironmentRequired)
    } else {
        None
    };

    let may_prepare = blocked_by.is_none();
    let approval_block = if !may_prepare {
        blocked_by
    } else if !request.primary_approval_present {
        Some(SelfEvolutionBlock::PrimaryApprovalRequired)
    } else if policy.require_dual_approval && !request.secondary_approval_present {
        Some(SelfEvolutionBlock::SecondaryApprovalRequired)
    } else {
        None
    };

    SelfEvolutionPermission {
        may_analyse: may_prepare,
        may_prepare_proposals: may_prepare,
        may_submit_for_review: approval_block.is_none(),
        blocked_by: approval_block.or(blocked_by),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EnterpriseSelfEvolutionPolicy {
        EnterpriseSelfEvolutionPolicy {
            permitted_by_administrator: true,
            activated_by_administrator: true,
            approved_model_ids: BTreeSet::from(["local-coder-v1".into()]),
            approved_write_scopes: BTreeSet::from(["apps/operator-console/help".into()]),
            require_dual_approval: true,
        }
    }

    fn request() -> SelfEvolutionRequest {
        SelfEvolutionRequest {
            selected_model_id: "local-coder-v1".into(),
            requested_write_scope: "apps/operator-console/help".into(),
            trusted_source_and_build_environment_configured: true,
            primary_approval_present: true,
            secondary_approval_present: true,
        }
    }

    #[test]
    fn administrator_prohibition_overrides_endpoint_installation_and_user_choice() {
        let mut p = policy();
        p.permitted_by_administrator = false;
        let result =
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &request());
        assert!(!result.may_analyse);
        assert!(!result.may_prepare_proposals);
        assert!(!result.may_submit_for_review);
        assert_eq!(
            result.blocked_by,
            Some(SelfEvolutionBlock::AdministratorProhibited)
        );
    }

    #[test]
    fn installation_does_not_activate_the_module() {
        let result = evaluate_enterprise_self_evolution(
            ModuleInstallState::NotInstalled,
            &policy(),
            &request(),
        );
        assert!(!result.may_prepare_proposals);
        assert_eq!(
            result.blocked_by,
            Some(SelfEvolutionBlock::ModuleNotInstalled)
        );
        let mut p = policy();
        p.activated_by_administrator = false;
        let result =
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &request());
        assert!(!result.may_prepare_proposals);
        assert_eq!(
            result.blocked_by,
            Some(SelfEvolutionBlock::AdministratorActivationRequired)
        );
    }

    #[test]
    fn model_and_scope_must_be_explicitly_allowlisted() {
        let mut r = request();
        r.selected_model_id = "unapproved-model".into();
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &policy(), &r)
                .blocked_by,
            Some(SelfEvolutionBlock::ModelNotApproved)
        );
        r = request();
        r.requested_write_scope = "crates/ujani-enterprise-policy".into();
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &policy(), &r)
                .blocked_by,
            Some(SelfEvolutionBlock::ScopeNotApproved)
        );
    }

    #[test]
    fn administrator_allowlist_cannot_include_protected_core_or_secret_paths() {
        let mut p = policy();
        p.approved_write_scopes = BTreeSet::from(["crates/ujani-enterprise-policy".into()]);
        let mut r = request();
        r.requested_write_scope = "crates/ujani-enterprise-policy".into();
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            Some(SelfEvolutionBlock::ProtectedScope)
        );

        p.approved_write_scopes = BTreeSet::from(["apps/operator-console/help".into()]);
        r = request();
        r.requested_write_scope = "apps/operator-console/help/.env.production".into();
        p.approved_write_scopes
            .insert(r.requested_write_scope.clone());
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            Some(SelfEvolutionBlock::ProtectedScope)
        );
    }

    #[test]
    fn trusted_build_environment_is_mandatory() {
        let mut r = request();
        r.trusted_source_and_build_environment_configured = false;
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &policy(), &r)
                .blocked_by,
            Some(SelfEvolutionBlock::TrustedBuildEnvironmentRequired)
        );
    }

    #[test]
    fn dual_approval_is_enforced_when_configured() {
        let mut r = request();
        r.secondary_approval_present = false;
        let result =
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &policy(), &r);
        assert!(result.may_prepare_proposals);
        assert!(!result.may_submit_for_review);
        assert_eq!(
            result.blocked_by,
            Some(SelfEvolutionBlock::SecondaryApprovalRequired)
        );
    }

    #[test]
    fn single_approval_policy_is_supported_but_not_implicit() {
        let mut p = policy();
        p.require_dual_approval = false;
        let mut r = request();
        r.secondary_approval_present = false;
        let result = evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r);
        assert!(result.may_submit_for_review);
    }
    #[test]
    fn scope_aliases_and_parent_directories_cannot_bypass_protected_paths() {
        let mut p = policy();
        let mut r = request();
        r.requested_write_scope = "./crates/ujani-enterprise-policy".into();
        p.approved_write_scopes = BTreeSet::from([r.requested_write_scope.clone()]);
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            Some(SelfEvolutionBlock::ScopeNotApproved)
        );

        r.requested_write_scope = "crates".into();
        p.approved_write_scopes = BTreeSet::from(["crates".into()]);
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            Some(SelfEvolutionBlock::ProtectedScope)
        );

        r.requested_write_scope = "crates/ujani-enterprise-policy-extra".into();
        p.approved_write_scopes = BTreeSet::from([r.requested_write_scope.clone()]);
        assert_ne!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            Some(SelfEvolutionBlock::ProtectedScope)
        );
    }
}
