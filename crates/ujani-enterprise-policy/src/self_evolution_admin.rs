//! Administrator-only feature gate for optional Enterprise self-evolution.
//!
//! This is a policy contract, not an installer, patch applier or execution engine.
//! The feature is opt-in and remains inert until explicitly installed and enabled.
//! Proposal generation is the only allowed mutation-adjacent operation here;
//! staging/application fail closed until a separate signed-approval pipeline exists.

use crate::operator_control_plane::OperatorRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionAction {
    ViewStatus,
    InstallFeature,
    GenerateProposal,
    StageChanges,
    ApplyChanges,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEvolutionFeatureConfig {
    pub installed: bool,
    pub enabled: bool,
    pub proposal_generation_enabled: bool,
    /// This must remain true; false is an invalid, fail-open policy configuration.
    pub require_admin_approval: bool,
    pub max_proposal_changes: usize,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfEvolutionGateError {
    AdministratorRequired,
    ExplicitUserOptInRequired,
    AlreadyInstalled,
    FeatureNotInstalled,
    FeatureDisabled,
    ProposalGenerationDisabled,
    InvalidPolicy,
    ScopeNotAllowed,
    TooManyChanges,
    ApprovalPipelineUnavailable,
}

/// An authorization result for proposal generation. It deliberately carries no
/// filesystem capability and cannot authorize staging, patch application or code execution.
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

/// Check an administrator request against the configured optional feature.
///
/// The host must obtain `actor_role` from a verified operator session and must
/// persist policy changes through its authenticated, audited admin repository.
/// Never populate these values from model output or browser-submitted role claims.
pub fn authorize_self_evolution_action(
    config: &SelfEvolutionFeatureConfig,
    actor_role: OperatorRole,
    action: SelfEvolutionAction,
    requested_scope: &[String],
    requested_change_count: usize,
    explicit_user_opt_in: bool,
) -> Result<Option<ProposalGenerationPermit>, SelfEvolutionGateError> {
    if action == SelfEvolutionAction::ViewStatus {
        return Ok(None);
    }

    if actor_role != OperatorRole::Administrator {
        return Err(SelfEvolutionGateError::AdministratorRequired);
    }

    if action == SelfEvolutionAction::InstallFeature {
        if config.installed {
            return Err(SelfEvolutionGateError::AlreadyInstalled);
        }
        if !explicit_user_opt_in {
            return Err(SelfEvolutionGateError::ExplicitUserOptInRequired);
        }
        return Ok(None);
    }

    if !config.installed {
        return Err(SelfEvolutionGateError::FeatureNotInstalled);
    }
    if !config.enabled {
        return Err(SelfEvolutionGateError::FeatureDisabled);
    }

    // Until the signed approval and durable replay ledger are wired into the
    // Enterprise host, there is intentionally no staging or apply capability.
    if matches!(
        action,
        SelfEvolutionAction::StageChanges | SelfEvolutionAction::ApplyChanges
    ) {
        return Err(SelfEvolutionGateError::ApprovalPipelineUnavailable);
    }

    if !config.proposal_generation_enabled {
        return Err(SelfEvolutionGateError::ProposalGenerationDisabled);
    }
    if !config.require_admin_approval
        || config.max_proposal_changes == 0
        || config.max_proposal_changes > 128
        || config.allowed_scopes.is_empty()
        || config.allowed_scopes.len() > 32
    {
        return Err(SelfEvolutionGateError::InvalidPolicy);
    }
    if requested_change_count == 0 || requested_change_count > config.max_proposal_changes {
        return Err(SelfEvolutionGateError::TooManyChanges);
    }

    let mut normalized_scopes = Vec::with_capacity(requested_scope.len());
    for scope in requested_scope {
        if !valid_scope(scope) {
            return Err(SelfEvolutionGateError::ScopeNotAllowed);
        }
        let normalized = scope.to_ascii_lowercase();
        if normalized_scopes.contains(&normalized) {
            return Err(SelfEvolutionGateError::InvalidPolicy);
        }
        normalized_scopes.push(normalized);
    }
    if normalized_scopes.is_empty()
        || !normalized_scopes.iter().all(|requested| {
            config.allowed_scopes.iter().any(|allowed| {
                valid_scope(allowed)
                    && (requested == &allowed.to_ascii_lowercase()
                        || requested.starts_with(&(allowed.to_ascii_lowercase() + "/")))
            })
        })
    {
        return Err(SelfEvolutionGateError::ScopeNotAllowed);
    }

    Ok(Some(ProposalGenerationPermit {
        approved_scope: requested_scope.to_vec(),
        max_changes: config.max_proposal_changes,
    }))
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 512
        && !scope.starts_with('/')
        && !scope.contains('\\')
        && !scope.contains(':')
        && scope.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.eq_ignore_ascii_case(".git")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SelfEvolutionFeatureConfig {
        SelfEvolutionFeatureConfig {
            installed: true,
            enabled: true,
            proposal_generation_enabled: true,
            require_admin_approval: true,
            max_proposal_changes: 8,
            allowed_scopes: vec!["apps/operator-console".into()],
        }
    }

    #[test]
    fn optional_install_requires_admin_and_explicit_opt_in() {
        let mut config = config();
        config.installed = false;
        assert_eq!(
            authorize_self_evolution_action(
                &config,
                OperatorRole::Operator,
                SelfEvolutionAction::InstallFeature,
                &[],
                0,
                true
            ),
            Err(SelfEvolutionGateError::AdministratorRequired)
        );
        assert_eq!(
            authorize_self_evolution_action(
                &config,
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                &[],
                0,
                false
            ),
            Err(SelfEvolutionGateError::ExplicitUserOptInRequired)
        );
        assert_eq!(
            authorize_self_evolution_action(
                &config,
                OperatorRole::Administrator,
                SelfEvolutionAction::InstallFeature,
                &[],
                0,
                true
            ),
            Ok(None)
        );
    }

    #[test]
    fn only_admin_can_generate_bounded_proposals_in_configured_scope() {
        assert_eq!(
            authorize_self_evolution_action(
                &config(),
                OperatorRole::Viewer,
                SelfEvolutionAction::GenerateProposal,
                &["apps/operator-console".into()],
                1,
                false
            ),
            Err(SelfEvolutionGateError::AdministratorRequired)
        );
        let permit = authorize_self_evolution_action(
            &config(),
            OperatorRole::Administrator,
            SelfEvolutionAction::GenerateProposal,
            &["apps/operator-console/components".into()],
            2,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(permit.max_changes(), 8);
        assert_eq!(
            permit.approved_scope(),
            &["apps/operator-console/components"]
        );
    }

    #[test]
    fn disabled_uninstalled_and_fail_open_policies_are_rejected() {
        let mut disabled = config();
        disabled.enabled = false;
        assert_eq!(
            authorize_self_evolution_action(
                &disabled,
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                &["apps/operator-console".into()],
                1,
                false
            ),
            Err(SelfEvolutionGateError::FeatureDisabled)
        );
        let mut not_installed = config();
        not_installed.installed = false;
        assert_eq!(
            authorize_self_evolution_action(
                &not_installed,
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                &["apps/operator-console".into()],
                1,
                false
            ),
            Err(SelfEvolutionGateError::FeatureNotInstalled)
        );
        let mut fail_open = config();
        fail_open.require_admin_approval = false;
        assert_eq!(
            authorize_self_evolution_action(
                &fail_open,
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                &["apps/operator-console".into()],
                1,
                false
            ),
            Err(SelfEvolutionGateError::InvalidPolicy)
        );
    }

    #[test]
    fn rejects_scope_escape_duplicates_and_unbounded_change_counts() {
        for scope in [
            "../crates",
            "apps/operator-console/../../crates",
            ".git/config",
        ] {
            assert_eq!(
                authorize_self_evolution_action(
                    &config(),
                    OperatorRole::Administrator,
                    SelfEvolutionAction::GenerateProposal,
                    &[scope.into()],
                    1,
                    false
                ),
                Err(SelfEvolutionGateError::ScopeNotAllowed)
            );
        }
        assert_eq!(
            authorize_self_evolution_action(
                &config(),
                OperatorRole::Administrator,
                SelfEvolutionAction::GenerateProposal,
                &["apps/operator-console".into()],
                9,
                false
            ),
            Err(SelfEvolutionGateError::TooManyChanges)
        );
    }

    #[test]
    fn stage_and_apply_remain_unavailable_until_signed_approval_is_integrated() {
        for action in [
            SelfEvolutionAction::StageChanges,
            SelfEvolutionAction::ApplyChanges,
        ] {
            assert_eq!(
                authorize_self_evolution_action(
                    &config(),
                    OperatorRole::Administrator,
                    action,
                    &["apps/operator-console".into()],
                    1,
                    true
                ),
                Err(SelfEvolutionGateError::ApprovalPipelineUnavailable)
            );
        }
    }
}
