//! Action-level authorization for the optional Enterprise Self-Evolution feature.
//!
//! This layer deliberately wraps the existing model/scope policy instead of
//! reimplementing it. Callers must supply OperatorRole from a verified session
//! and owner opt-in from current trusted consent storage, never from UI input.
//! It authorizes proposal preparation only; review submission, staging and apply
//! remain blocked until signed approval and durable single-use replay are wired.
use crate::operator_control_plane::OperatorRole;
use crate::self_evolution::MAX_PROPOSAL_CHANGES;
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

/// Authorize one action using authenticated operator role and trusted owner consent.
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
    actor_role: OperatorRole,
    action: SelfEvolutionAction,
    owner_opted_in: bool,
    proposal_generation_enabled: bool,
    max_changes_per_proposal: usize,
    requested_change_count: usize,
) -> Result<Option<ProposalGenerationPermit>, SelfEvolutionActionError> {
    if action == SelfEvolutionAction::ViewStatus {
        return Ok(None);
    }

    if actor_role != OperatorRole::Administrator {
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
        authorize_self_evolution_action(
            ModuleInstallState::Installed,
            &policy(),
            &request(),
            role,
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
                OperatorRole::Administrator,
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
