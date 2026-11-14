//! Action-level authorization for the optional Enterprise Self-Evolution feature.
//!
//! This layer deliberately wraps the existing model/scope policy instead of
//! reimplementing it. Callers must supply OperatorRole from a verified session
//! and owner opt-in from current trusted consent storage, never from UI input.
//! It authorizes proposal preparation only; review submission, staging and apply
//! remain blocked until signed approval and durable single-use replay are wired.
use crate::operator_session_revocation::CurrentOperatorSession;
use crate::self_evolution::{MAX_PROPOSAL_CHANGES, MAX_PROPOSAL_SCOPE_PATHS};
use crate::self_evolution_module::{
    evaluate_enterprise_self_evolution, EnterpriseSelfEvolutionPolicy, ModuleInstallState,
    SelfEvolutionBlock, SelfEvolutionRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionAction {
    ViewStatus,
    InstallFeature,
    GenerateProposal,
    SubmitForReview,
    StageChanges,
    ApplyChanges,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionActionError {
    AdministratorRequired,
    InvalidAuthenticatedSession,
    ExplicitOwnerOptInRequired,
    AlreadyInstalled,
    ModuleNotInstalled,
    ProposalGenerationDisabled,
    InvalidChangeLimit,
    TooManyChanges,
    ApprovalPipelineUnavailable,
    PolicyBlocked(SelfEvolutionBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalGenerationPermit {
    approved_scope: String,
    max_changes: usize,
}

impl ProposalGenerationPermit {
    pub fn approved_scope(&self) -> &str {
        &self.approved_scope
    }

    pub fn max_changes(&self) -> usize {
        self.max_changes
    }
}

/// Validate the administrator's entire configured scope set by reusing the existing
/// policy evaluator. This prevents a dangerous or malformed unused scope from
/// remaining dormant until a later request selects it.
fn validate_approved_scope_configuration(
    installation: ModuleInstallState,
    policy: &EnterpriseSelfEvolutionPolicy,
    request: &SelfEvolutionRequest,
) -> Result<(), SelfEvolutionActionError> {
    if policy.approved_write_scopes.is_empty()
        || policy.approved_write_scopes.len() > MAX_PROPOSAL_SCOPE_PATHS
    {
        return Err(SelfEvolutionActionError::PolicyBlocked(
            SelfEvolutionBlock::ApprovalPolicyInvalid,
        ));
    }

    for scope in &policy.approved_write_scopes {
        let mut scoped_request = request.clone();
        scoped_request.requested_write_scope = scope.clone();
        if let Some(blocked_by) =
            evaluate_enterprise_self_evolution(installation, policy, &scoped_request).blocked_by
        {
            return Err(SelfEvolutionActionError::PolicyBlocked(blocked_by));
        }
    }
    Ok(())
}

/// Authorize one action using a revocation-checked operator session and trusted owner consent.
///
/// `proposal_generation_enabled`, `max_changes_per_proposal`, and
/// `owner_opted_in` must come from trusted administrator/consent state.
/// This function has no installation, repository, filesystem, signing or
/// execution side effects.
#[allow(clippy::too_many_arguments)]
pub fn authorize_self_evolution_action(
    installation: ModuleInstallState,
    policy: &EnterpriseSelfEvolutionPolicy,
    request: &SelfEvolutionRequest,
    session: &CurrentOperatorSession,
    now_unix_ms: u64,
    action: SelfEvolutionAction,
    owner_opted_in: bool,
    proposal_generation_enabled: bool,
    max_changes_per_proposal: usize,
    requested_change_count: usize,
) -> Result<Option<ProposalGenerationPermit>, SelfEvolutionActionError> {
    if !session.is_current_at(now_unix_ms) {
        return Err(SelfEvolutionActionError::InvalidAuthenticatedSession);
    }
    if action == SelfEvolutionAction::ViewStatus {
        return Ok(None);
    }

    if session.role() != crate::operator_control_plane::OperatorRole::Administrator {
        return Err(SelfEvolutionActionError::AdministratorRequired);
    }

    if action == SelfEvolutionAction::InstallFeature {
        if installation == ModuleInstallState::Installed {
            return Err(SelfEvolutionActionError::AlreadyInstalled);
        }
        if !policy.permitted_by_administrator {
            return Err(SelfEvolutionActionError::PolicyBlocked(
                SelfEvolutionBlock::AdministratorProhibited,
            ));
        }
        if !owner_opted_in {
            return Err(SelfEvolutionActionError::ExplicitOwnerOptInRequired);
        }
        return Ok(None);
    }

    if installation == ModuleInstallState::NotInstalled {
        return Err(SelfEvolutionActionError::ModuleNotInstalled);
    }
    if !owner_opted_in {
        return Err(SelfEvolutionActionError::ExplicitOwnerOptInRequired);
    }

    match action {
        SelfEvolutionAction::SubmitForReview
        | SelfEvolutionAction::StageChanges
        | SelfEvolutionAction::ApplyChanges => {
            return Err(SelfEvolutionActionError::ApprovalPipelineUnavailable);
        }
        SelfEvolutionAction::ViewStatus | SelfEvolutionAction::InstallFeature => {
            return Ok(None);
        }
        SelfEvolutionAction::GenerateProposal => {}
    }

    if !proposal_generation_enabled {
        return Err(SelfEvolutionActionError::ProposalGenerationDisabled);
    }
    if max_changes_per_proposal == 0 || max_changes_per_proposal > MAX_PROPOSAL_CHANGES {
        return Err(SelfEvolutionActionError::InvalidChangeLimit);
    }
    if requested_change_count == 0 || requested_change_count > max_changes_per_proposal {
        return Err(SelfEvolutionActionError::TooManyChanges);
    }

    validate_approved_scope_configuration(installation, policy, request)?;

    let permission = evaluate_enterprise_self_evolution(installation, policy, request);
    if let Some(blocked_by) = permission.blocked_by {
        return Err(SelfEvolutionActionError::PolicyBlocked(blocked_by));
    }

    Ok(Some(ProposalGenerationPermit {
        approved_scope: request.requested_write_scope.clone(),
        max_changes: max_changes_per_proposal,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_control_plane::OperatorRole;
    use crate::operator_session_revocation::test_current_operator_session;
    use std::collections::BTreeSet;

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
        }
    }

    fn authorize(
        role: OperatorRole,
        action: SelfEvolutionAction,
        owner_opted_in: bool,
    ) -> Result<Option<ProposalGenerationPermit>, SelfEvolutionActionError> {
        let session = test_current_operator_session("tenant-a", "admin-a", role, 90_000);
        authorize_self_evolution_action(
            ModuleInstallState::Installed,
            &policy(),
            &request(),
            &session,
            2_000,
            action,
            owner_opted_in,
            true,
            8,
            2,
        )
    }

    #[test]
    fn only_administrator_can_change_self_evolution_state() {
        assert_eq!(
            authorize(
                OperatorRole::Operator,
                SelfEvolutionAction::GenerateProposal,
                true
            ),
            Err(SelfEvolutionActionError::AdministratorRequired)
        );
        assert_eq!(
            authorize(
                OperatorRole::Viewer,
                SelfEvolutionAction::ApplyChanges,
                true
            ),
            Err(SelfEvolutionActionError::AdministratorRequired)
        );
    }

    #[test]
    fn proposal_generation_requires_current_owner_opt_in() {
        assert_eq!(
            authorize(
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                false
            ),
            Err(SelfEvolutionActionError::ExplicitOwnerOptInRequired)
        );
    }

    #[test]
    fn proposal_generation_reuses_existing_model_and_scope_policy() {
        let permit = authorize(
            OperatorRole::Administrator,
            SelfEvolutionAction::GenerateProposal,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(permit.approved_scope(), "apps/operator-console/help");
        assert_eq!(permit.max_changes(), 8);

        let mut unapproved = policy();
        unapproved.approved_model_ids.clear();
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::Installed,
                &unapproved,
                &request(),
                &test_current_operator_session("tenant-a", "admin-a", OperatorRole::Administrator, 90_000),
                2_000,
                SelfEvolutionAction::GenerateProposal,
                true,
                true,
                8,
                1,
            ),
            Err(SelfEvolutionActionError::PolicyBlocked(
                SelfEvolutionBlock::ModelNotApproved
            ))
        );
    }

    #[test]
    fn proposal_generation_has_separate_switch_and_bounded_change_count() {
        let base = policy();
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::Installed,
                &base,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                false,
                8,
                1,
            ),
            Err(SelfEvolutionActionError::ProposalGenerationDisabled)
        );
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::Installed,
                &base,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                true,
                8,
                9,
            ),
            Err(SelfEvolutionActionError::TooManyChanges)
        );
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::Installed,
                &base,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                true,
                MAX_PROPOSAL_CHANGES + 1,
                1,
            ),
            Err(SelfEvolutionActionError::InvalidChangeLimit)
        );
    }

    #[test]
    fn all_configured_scopes_are_validated_not_only_the_requested_scope() {
        let mut configured = policy();
        configured.approved_write_scopes.insert(".git".into());
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::Installed,
                &configured,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                true,
                8,
                1,
            ),
            Err(SelfEvolutionActionError::PolicyBlocked(
                SelfEvolutionBlock::ProtectedScope
            ))
        );

        let mut oversized = policy();
        oversized.approved_write_scopes = (0..=MAX_PROPOSAL_SCOPE_PATHS)
            .map(|index| format!("apps/operator-console/scope-{index}"))
            .collect();
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::Installed,
                &oversized,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                true,
                true,
                8,
                1,
            ),
            Err(SelfEvolutionActionError::PolicyBlocked(
                SelfEvolutionBlock::ApprovalPolicyInvalid
            ))
        );
    }

    #[test]
    fn submit_stage_and_apply_are_blocked_until_durable_approval_pipeline_exists() {
        for action in [
            SelfEvolutionAction::SubmitForReview,
            SelfEvolutionAction::StageChanges,
            SelfEvolutionAction::ApplyChanges,
        ] {
            assert_eq!(
                authorize(OperatorRole::Administrator, action, true),
                Err(SelfEvolutionActionError::ApprovalPipelineUnavailable)
            );
        }
    }

    #[test]
    fn install_requires_admin_permission_and_owner_opt_in() {
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::NotInstalled,
                &policy(),
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                false,
                false,
                0,
                0,
            ),
            Err(SelfEvolutionActionError::ExplicitOwnerOptInRequired)
        );
        let mut prohibited = policy();
        prohibited.permitted_by_administrator = false;
        assert_eq!(
            authorize_self_evolution_action(
                ModuleInstallState::NotInstalled,
                &prohibited,
                &request(),
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                true,
                false,
                0,
                0,
            ),
            Err(SelfEvolutionActionError::PolicyBlocked(
                SelfEvolutionBlock::AdministratorProhibited
            ))
        );
    }
}
