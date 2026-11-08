//! Energy-aware placement comparison for equivalent completed workloads.
//!
//! This module is a deterministic policy helper only. It does not read power
//! meters, estimate data-centre energy, schedule jobs, or authorise execution.
//! Callers must provide defensible readings with provenance and must verify
//! that the compared workloads meet the same output-quality target.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyBasis {
    /// Directly measured energy, for example with an external power meter.
    Measured,
    /// Modelled or software-estimated energy; must be labelled as an estimate.
    Estimated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnergyReading {
    /// Energy in milliwatt-hours (mWh).
    pub milliwatt_hours: u64,
    pub basis: EnergyBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnergyScenario {
    pub equivalent_workload_verified: bool,
    pub central_baseline: EnergyReading,
    pub incremental_device: EnergyReading,
    pub network_overhead: EnergyReading,
    pub retry_and_failure_overhead: EnergyReading,
    pub additional_cooling_overhead: EnergyReading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnergyComparison {
    pub central_baseline_mwh: u64,
    pub distributed_total_mwh: u64,
    pub estimated_saving_mwh: u64,
    /// True if any input component is modelled rather than directly measured.
    pub contains_estimates: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyDecision {
    DistributedPreferred(EnergyComparison),
    CentralPreferred(EnergyComparison),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyComparisonError {
    EquivalentWorkloadNotVerified,
    MissingCentralBaseline,
    ArithmeticOverflow,
}

/// Compare equivalent successful work and prefer distributed placement only
/// when its complete energy cost is strictly lower than the central baseline.
///
/// The distributed total includes incremental device energy, network transfer,
/// retries/failures and additional cooling. A PC's entire power draw must not be
/// counted as incremental if it would have been on anyway; equally, incremental
/// energy must never be assumed to be zero without evidence.
///
/// This result is not a claim that a data centre reduced its metered electricity
/// use. It is a workload-level comparison and does not authorise dispatch.
pub fn compare_energy_scenarios(
    scenario: EnergyScenario,
) -> Result<EnergyDecision, EnergyComparisonError> {
    if !scenario.equivalent_workload_verified {
        return Err(EnergyComparisonError::EquivalentWorkloadNotVerified);
    }
    let central = scenario.central_baseline.milliwatt_hours;
    if central == 0 {
        return Err(EnergyComparisonError::MissingCentralBaseline);
    }

    let distributed = [
        scenario.incremental_device.milliwatt_hours,
        scenario.network_overhead.milliwatt_hours,
        scenario.retry_and_failure_overhead.milliwatt_hours,
        scenario.additional_cooling_overhead.milliwatt_hours,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or(EnergyComparisonError::ArithmeticOverflow)?;

    let contains_estimates = [
        scenario.central_baseline,
        scenario.incremental_device,
        scenario.network_overhead,
        scenario.retry_and_failure_overhead,
        scenario.additional_cooling_overhead,
    ]
    .into_iter()
    .any(|reading| reading.basis == EnergyBasis::Estimated);

    let comparison = EnergyComparison {
        central_baseline_mwh: central,
        distributed_total_mwh: distributed,
        estimated_saving_mwh: central.saturating_sub(distributed),
        contains_estimates,
    };

    if distributed < central {
        Ok(EnergyDecision::DistributedPreferred(comparison))
    } else {
        // Ties are deliberately not a reason to distribute.
        Ok(EnergyDecision::CentralPreferred(comparison))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(milliwatt_hours: u64) -> EnergyReading {
        EnergyReading {
            milliwatt_hours,
            basis: EnergyBasis::Measured,
        }
    }

    fn scenario() -> EnergyScenario {
        EnergyScenario {
            equivalent_workload_verified: true,
            central_baseline: reading(1_000),
            incremental_device: reading(400),
            network_overhead: reading(100),
            retry_and_failure_overhead: reading(50),
            additional_cooling_overhead: reading(25),
        }
    }

    #[test]
    fn prefers_distributed_only_when_total_energy_is_lower() {
        let result = compare_energy_scenarios(scenario()).unwrap();
        assert_eq!(
            result,
            EnergyDecision::DistributedPreferred(EnergyComparison {
                central_baseline_mwh: 1_000,
                distributed_total_mwh: 575,
                estimated_saving_mwh: 425,
                contains_estimates: false,
            })
        );
    }

    #[test]
    fn includes_network_retries_and_cooling_in_comparison() {
        let mut input = scenario();
        input.network_overhead = reading(400);
        input.retry_and_failure_overhead = reading(150);
        input.additional_cooling_overhead = reading(100);
        assert!(matches!(
            compare_energy_scenarios(input),
            Ok(EnergyDecision::CentralPreferred(_))
        ));
    }

    #[test]
    fn ties_prefer_central_execution() {
        let mut input = scenario();
        input.incremental_device = reading(825);
        assert!(matches!(
            compare_energy_scenarios(input),
            Ok(EnergyDecision::CentralPreferred(EnergyComparison {
                distributed_total_mwh: 1_000,
                estimated_saving_mwh: 0,
                ..
            }))
        ));
    }

    #[test]
    fn refuses_comparison_without_equivalent_workload() {
        let mut input = scenario();
        input.equivalent_workload_verified = false;
        assert_eq!(
            compare_energy_scenarios(input),
            Err(EnergyComparisonError::EquivalentWorkloadNotVerified)
        );
    }

    #[test]
    fn marks_modelled_inputs_as_estimates() {
        let mut input = scenario();
        input.network_overhead.basis = EnergyBasis::Estimated;
        assert!(matches!(
            compare_energy_scenarios(input),
            Ok(EnergyDecision::DistributedPreferred(EnergyComparison {
                contains_estimates: true,
                ..
            }))
        ));
    }

    #[test]
    fn rejects_missing_baseline_and_overflow() {
        let mut input = scenario();
        input.central_baseline = reading(0);
        assert_eq!(
            compare_energy_scenarios(input),
            Err(EnergyComparisonError::MissingCentralBaseline)
        );

        let mut input = scenario();
        input.incremental_device = reading(u64::MAX);
        input.network_overhead = reading(1);
        assert_eq!(
            compare_energy_scenarios(input),
            Err(EnergyComparisonError::ArithmeticOverflow)
        );
    }
}
