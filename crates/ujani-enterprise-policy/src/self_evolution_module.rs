//! Enterprise administrator policy for the optional Self-Evolution module.
//!
//! This is a side-effect-free authorization contract. It does not install a
//! module, access source repositories, apply patches, execute code, sign builds
//! or deploy artifacts. The authenticated control plane supplies policy; typed
//! approval and durable replay integration are deliberately not available yet.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleInstallState {
    NotInstalled,
    Installed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionBlock {
    AdministratorRequired,
    ExplicitUserOptInRequired,
    AlreadyInstalled,
    TooManyChanges,
    ModuleNotInstalled,
    AdministratorProhibited,
    AdministratorActivationRequired,
    ModelNotApproved,
    ScopeNotApproved,
    ProtectedScope,
    TrustedBuildEnvironmentRequired,
    ApprovalPolicyInvalid,
    ApprovalPipelineUnavailable,
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
    /// Administrator-configured upper bound for one generated proposal.
    pub max_proposal_changes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEvolutionRequest {
    pub selected_model_id: String,
    pub requested_write_scope: String,
    /// Supplied by the trusted host after source and build-environment checks.
    pub trusted_source_and_build_environment_configured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfEvolutionPermission {
    pub may_analyse: bool,
    pub may_prepare_proposals: bool,
    /// Reserved for a future trusted review pipeline; currently always false.
    /// It never authorizes applying, executing, signing or deploying changes.
    pub may_submit_for_review: bool,
    pub blocked_by: Option<SelfEvolutionBlock>,
    /// Submission remains fail-closed until typed approval and durable replay are integrated.
    pub submission_blocked_by: Option<SelfEvolutionBlock>,
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
                .is_some_and(|(approved, requested)| requested == &approved)
        })
    {
        Some(SelfEvolutionBlock::ScopeNotApproved)
    } else if is_protected_scope(normalized_scope.as_deref().unwrap_or_default()) {
        Some(SelfEvolutionBlock::ProtectedScope)
    } else if !policy.require_dual_approval
        || policy.max_proposal_changes == 0
        || policy.max_proposal_changes > crate::self_evolution::MAX_PROPOSAL_CHANGES
    {
        Some(SelfEvolutionBlock::ApprovalPolicyInvalid)
    } else if !request.trusted_source_and_build_environment_configured {
        Some(SelfEvolutionBlock::TrustedBuildEnvironmentRequired)
    } else {
        None
    };

    let may_prepare = blocked_by.is_none();

    SelfEvolutionPermission {
        may_analyse: may_prepare,
        may_prepare_proposals: may_prepare,
        may_submit_for_review: false,
        blocked_by,
        submission_blocked_by: Some(
            blocked_by.unwrap_or(SelfEvolutionBlock::ApprovalPipelineUnavailable),
        ),
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
            max_proposal_changes: 8,
        }
    }

    fn request() -> SelfEvolutionRequest {
        SelfEvolutionRequest {
            selected_model_id: "local-coder-v1".into(),
            requested_write_scope: "apps/operator-console/help".into(),
            trusted_source_and_build_environment_configured: true,
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
    fn administrator_policy_must_require_dual_approval() {
        let mut p = policy();
        p.require_dual_approval = false;
        let result =
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &request());
        assert!(!result.may_prepare_proposals);
        assert_eq!(
            result.blocked_by,
            Some(SelfEvolutionBlock::ApprovalPolicyInvalid)
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
    fn review_submission_fails_closed_until_typed_approval_pipeline_is_integrated() {
        let result = evaluate_enterprise_self_evolution(
            ModuleInstallState::Installed,
            &policy(),
            &request(),
        );
        assert!(result.may_prepare_proposals);
        assert!(!result.may_submit_for_review);
        assert_eq!(result.blocked_by, None);
        assert_eq!(
            result.submission_blocked_by,
            Some(SelfEvolutionBlock::ApprovalPipelineUnavailable)
        );
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

    #[test]
    fn a_child_scope_requires_its_own_explicit_approval() {
        let mut p = policy();
        let mut r = request();
        r.requested_write_scope = "apps/operator-console/help/extra".into();
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            Some(SelfEvolutionBlock::ScopeNotApproved)
        );

        p.approved_write_scopes
            .insert(r.requested_write_scope.clone());
        assert_eq!(
            evaluate_enterprise_self_evolution(ModuleInstallState::Installed, &p, &r).blocked_by,
            None
        );
    }
}

/// Explicit action requested from the optional Self-Evolution feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionAction {
    ViewStatus,
    InstallFeature,
    GenerateProposal,
    StageChanges,
    ApplyChanges,
}

/// A narrow capability returned only after the existing Enterprise policy checks pass.
/// It carries no filesystem handle and cannot stage or apply changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalGenerationPermit {
    approved_scope: Vec<String>,
    max_changes: usize,
}

impl ProposalGenerationPermit {
    pub fn approved_scope(&self) -> &[String] {
        &self.approved_scope
    }
    pub fn max_changes(&self) -> usize {
        self.max_changes
    }
}

/// Apply authenticated role and explicit owner opt-in checks around the existing
/// Enterprise Self-Evolution policy. actor_role must come from a verified
/// operator session; explicit_user_opt_in must come from trusted, current
/// device-owner consent state, never from a browser-supplied boolean.
///
/// This extends evaluate_enterprise_self_evolution rather than maintaining a
/// second model/scope/protected-path validator. Installation is only authorized
/// here; this function does not install anything. Staging and applying remain blocked.
pub fn authorize_enterprise_self_evolution_action(
    installation: ModuleInstallState,
    policy: &EnterpriseSelfEvolutionPolicy,
    request: &SelfEvolutionRequest,
    actor_role: crate::operator_control_plane::OperatorRole,
    action: SelfEvolutionAction,
    explicit_user_opt_in: bool,
    requested_change_count: usize,
) -> Result<Option<ProposalGenerationPermit>, SelfEvolutionBlock> {
    use crate::operator_control_plane::OperatorRole;

    if action == SelfEvolutionAction::ViewStatus {
        return Ok(None);
    }
    if actor_role != OperatorRole::Administrator {
        return Err(SelfEvolutionBlock::AdministratorRequired);
    }
    if action == SelfEvolutionAction::InstallFeature {
        if installation == ModuleInstallState::Installed {
            return Err(SelfEvolutionBlock::AlreadyInstalled);
        }
        if !policy.permitted_by_administrator {
            return Err(SelfEvolutionBlock::AdministratorProhibited);
        }
        if !explicit_user_opt_in {
            return Err(SelfEvolutionBlock::ExplicitUserOptInRequired);
        }
        return Ok(None);
    }
    if installation == ModuleInstallState::NotInstalled {
        return Err(SelfEvolutionBlock::ModuleNotInstalled);
    }
    if !explicit_user_opt_in {
        return Err(SelfEvolutionBlock::ExplicitUserOptInRequired);
    }
    if matches!(
        action,
        SelfEvolutionAction::StageChanges | SelfEvolutionAction::ApplyChanges
    ) {
        return Err(SelfEvolutionBlock::ApprovalPipelineUnavailable);
    }
    if requested_change_count == 0 || requested_change_count > policy.max_proposal_changes
    {
        return Err(SelfEvolutionBlock::TooManyChanges);
    }
    let permission = evaluate_enterprise_self_evolution(installation, policy, request);
    if let Some(blocked_by) = permission.blocked_by {
        return Err(blocked_by);
    }
    let approved_scope = normalize_scope(&request.requested_write_scope)
        .ok_or(SelfEvolutionBlock::ScopeNotApproved)?;
    Ok(Some(ProposalGenerationPermit {
        approved_scope: vec![approved_scope],
        max_changes: policy.max_proposal_changes,
    }))
}

#[cfg(test)]
mod action_gate_tests {
    use super::*;
    use crate::operator_control_plane::OperatorRole;
    use std::collections::BTreeSet;

    fn policy() -> EnterpriseSelfEvolutionPolicy {
        EnterpriseSelfEvolutionPolicy {
            permitted_by_administrator: true,
            activated_by_administrator: true,
            approved_model_ids: BTreeSet::from(["local-coder-v1".into()]),
            approved_write_scopes: BTreeSet::from(["apps/operator-console/help".into()]),
            require_dual_approval: true,
            max_proposal_changes: 8,
        }
    }
    fn request() -> SelfEvolutionRequest {
        SelfEvolutionRequest {
            selected_model_id: "local-coder-v1".into(),
            requested_write_scope: "apps/operator-console/help".into(),
            trusted_source_and_build_environment_configured: true,
        }
    }
    #[test]
    fn non_admin_cannot_install_or_generate_proposals() {
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::NotInstalled,
                &policy(),
                &request(),
                OperatorRole::Operator,
                SelfEvolutionAction::InstallFeature,
                true,
                1
            ),
            Err(SelfEvolutionBlock::AdministratorRequired)
        );
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::Installed,
                &policy(),
                &request(),
                OperatorRole::Viewer,
                SelfEvolutionAction::GenerateProposal,
                true,
                1
            ),
            Err(SelfEvolutionBlock::AdministratorRequired)
        );
    }
    #[test]
    fn installation_requires_admin_permission_and_explicit_owner_opt_in() {
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::NotInstalled,
                &policy(),
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                false,
                0
            ),
            Err(SelfEvolutionBlock::ExplicitUserOptInRequired)
        );
        let mut denied = policy();
        denied.permitted_by_administrator = false;
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::NotInstalled,
                &denied,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                true,
                0
            ),
            Err(SelfEvolutionBlock::AdministratorProhibited)
        );
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::NotInstalled,
                &policy(),
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                true,
                0
            ),
            Ok(None)
        );
    }
    #[test]
    fn proposal_generation_reuses_existing_policy_and_returns_bounded_permit() {
        let permit = authorize_enterprise_self_evolution_action(
            ModuleInstallState::Installed,
            &policy(),
            &request(),
            OperatorRole::Administrator,
            SelfEvolutionAction::GenerateProposal,
            true,
            2,
        )
        .unwrap()
        .unwrap();
        assert_eq!(permit.approved_scope()[0], "apps/operator-console/help");
        assert_eq!(
            permit.max_changes(),
            8
        );
        let mut denied = policy();
        denied.approved_model_ids.clear();
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::Installed,
                &denied,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                1
            ),
            Err(SelfEvolutionBlock::ModelNotApproved)
        );
    }
    #[test]
    fn stage_and_apply_remain_blocked_and_change_count_is_bounded() {
        for action in [
            SelfEvolutionAction::StageChanges,
            SelfEvolutionAction::ApplyChanges,
        ] {
            assert_eq!(
                authorize_enterprise_self_evolution_action(
                    ModuleInstallState::Installed,
                    &policy(),
                    &request(),
                    OperatorRole::Administrator,
                    action,
                    true,
                    1
                ),
                Err(SelfEvolutionBlock::ApprovalPipelineUnavailable)
            );
        }
        assert_eq!(
            authorize_enterprise_self_evolution_action(
                ModuleInstallState::Installed,
                &policy(),
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                policy().max_proposal_changes + 1
            ),
            Err(SelfEvolutionBlock::TooManyChanges)
        );
    }
}
