//! Typed, bounded model/runtime inventory and conservative capability matching.
//!
//! This module consumes metadata only. It does not discover runtimes, start providers,
//! download models, authorize workload admission, reserve resources or dispatch work.
//! The versioned JSON Schema remains the wire-format contract; callers must validate
//! schema-required field presence before deserializing this in-process representation.

use serde::Deserialize;
use std::collections::HashSet;

pub const MODEL_RUNTIME_INVENTORY_SCHEMA_VERSION: u16 = 1;
const MAX_ACCELERATORS: usize = 32;
const MAX_RUNTIMES: usize = 16;
const MAX_MODELS: usize = 512;
const MAX_CAPABILITIES: usize = 16;
const CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKind {
    Gpu,
    Npu,
    Other,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAvailability {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelAvailability {
    Installed,
    Downloadable,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNetworkScope {
    LoopbackOnly,
    LocalSocket,
    EnterpriseInternal,
    NotApplicable,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Chat,
    Reasoning,
    Coding,
    Vision,
    Embeddings,
    ToolUse,
    Streaming,
    AudioInput,
    AudioOutput,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    RuntimeApi,
    OsApi,
    RuntimeMetadata,
    SignedCatalogue,
    PublishedCatalogue,
    Estimate,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    Verified,
    Reported,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelEvidence {
    pub source: EvidenceSource,
    pub confidence: EvidenceConfidence,
    pub observed_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelPlatform {
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorInfo {
    pub kind: AcceleratorKind,
    pub vendor: Option<String>,
    pub device_family: Option<String>,
    pub memory_mb: Option<u64>,
    pub runtime_api: Option<String>,
    pub evidence: ModelEvidence,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelHardware {
    pub cpu_logical_cores: Option<u16>,
    pub memory_total_mb: Option<u64>,
    pub memory_available_mb: Option<u64>,
    pub storage_free_mb: Option<u64>,
    pub accelerators: Vec<AcceleratorInfo>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInfo {
    pub runtime_id: String,
    pub provider: String,
    pub version: Option<String>,
    pub availability: RuntimeAvailability,
    pub network_scope: RuntimeNetworkScope,
    pub evidence: ModelEvidence,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelInfo {
    pub model_ref: String,
    pub runtime_id: String,
    pub display_name: String,
    pub family: Option<String>,
    pub version: Option<String>,
    pub availability: ModelAvailability,
    pub size_bytes: Option<u64>,
    pub context_length_tokens: Option<u64>,
    pub estimated_min_memory_mb: Option<u64>,
    pub capabilities: Vec<ModelCapability>,
    pub evidence: ModelEvidence,
}

/// Optional declarations are included only to make privacy assertions explicit.
/// Any true value rejects the snapshot; omission and false both mean "not included".
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivacyDeclaration {
    pub contains_prompts: Option<bool>,
    pub contains_user_files: Option<bool>,
    pub contains_local_paths: Option<bool>,
    pub contains_credentials: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimeInventory {
    pub schema_version: u16,
    pub generated_at_unix_ms: u64,
    pub device_ref: Option<String>,
    pub platform: ModelPlatform,
    pub hardware: ModelHardware,
    pub runtimes: Vec<RuntimeInfo>,
    pub models: Vec<ModelInfo>,
    pub privacy: Option<PrivacyDeclaration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelInventoryValidationError {
    UnsupportedSchemaVersion,
    InvalidTimestamp,
    FutureTimestamp,
    StaleInventory,
    InvalidIdentifier,
    InvalidPlatform,
    InvalidHardware,
    TooManyAccelerators,
    TooManyRuntimes,
    TooManyModels,
    DuplicateRuntime,
    DuplicateModel,
    UnknownRuntime,
    InvalidMetadata,
    InvalidEvidence,
    TooManyCapabilities,
    DuplicateCapability,
    PrivacyViolation,
    ModelNotFound,
    InvalidRequirements,
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    bounded_text(value, max_bytes)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn valid_model_ref(value: &str) -> bool {
    bounded_text(value, 160)
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains('\\')
        && !value.contains("://")
}

fn validate_evidence(
    evidence: &ModelEvidence,
    generated_at_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<(), ModelInventoryValidationError> {
    if evidence.observed_at_unix_ms == Some(0) {
        return Err(ModelInventoryValidationError::InvalidEvidence);
    }
    if evidence.observed_at_unix_ms.is_some_and(|observed| {
        observed > now_unix_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS)
            || observed > generated_at_unix_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS)
    }) {
        return Err(ModelInventoryValidationError::FutureTimestamp);
    }
    if evidence.source == EvidenceSource::Unknown
        && evidence.confidence == EvidenceConfidence::Verified
    {
        return Err(ModelInventoryValidationError::InvalidEvidence);
    }
    Ok(())
}

fn evidence_is_usable(evidence: &ModelEvidence, now_unix_ms: u64, max_age_ms: u64) -> bool {
    matches!(
        evidence.confidence,
        EvidenceConfidence::Verified | EvidenceConfidence::Reported
    ) && !matches!(
        evidence.source,
        EvidenceSource::Unknown | EvidenceSource::Estimate
    ) && evidence.observed_at_unix_ms.is_some_and(|observed| {
        observed <= now_unix_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS)
            && now_unix_ms.saturating_sub(observed) <= max_age_ms
    })
}

/// Validate structural invariants not expressible as local JSON Schema constraints.
/// This is not authentication: the caller must first authenticate the enrolled device
/// and enforce tenant scope, dual consent and replay/sequence policy at the service boundary.
pub fn validate_model_runtime_inventory(
    inventory: &ModelRuntimeInventory,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<(), ModelInventoryValidationError> {
    if inventory.schema_version != MODEL_RUNTIME_INVENTORY_SCHEMA_VERSION {
        return Err(ModelInventoryValidationError::UnsupportedSchemaVersion);
    }
    if inventory.generated_at_unix_ms == 0 {
        return Err(ModelInventoryValidationError::InvalidTimestamp);
    }
    if inventory.generated_at_unix_ms > now_unix_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS) {
        return Err(ModelInventoryValidationError::FutureTimestamp);
    }
    if now_unix_ms.saturating_sub(inventory.generated_at_unix_ms) > max_age_ms {
        return Err(ModelInventoryValidationError::StaleInventory);
    }
    if inventory
        .device_ref
        .as_ref()
        .is_some_and(|value| !valid_identifier(value, 128))
    {
        return Err(ModelInventoryValidationError::InvalidIdentifier);
    }
    if !bounded_text(&inventory.platform.os, 32)
        || !bounded_text(&inventory.platform.architecture, 32)
        || inventory
            .platform
            .os_version
            .as_ref()
            .is_some_and(|value| value.len() > 64 || value.chars().any(char::is_control))
    {
        return Err(ModelInventoryValidationError::InvalidPlatform);
    }
    if inventory.hardware.cpu_logical_cores == Some(0)
        || inventory.hardware.memory_total_mb == Some(0)
    {
        return Err(ModelInventoryValidationError::InvalidHardware);
    }
    if inventory.hardware.accelerators.len() > MAX_ACCELERATORS {
        return Err(ModelInventoryValidationError::TooManyAccelerators);
    }
    for accelerator in &inventory.hardware.accelerators {
        for (value, max_bytes) in [
            (accelerator.vendor.as_deref(), 64),
            (accelerator.device_family.as_deref(), 96),
            (accelerator.runtime_api.as_deref(), 64),
        ] {
            if value
                .is_some_and(|text| text.len() > max_bytes || text.chars().any(char::is_control))
            {
                return Err(ModelInventoryValidationError::InvalidMetadata);
            }
        }
        validate_evidence(
            &accelerator.evidence,
            inventory.generated_at_unix_ms,
            now_unix_ms,
        )?;
    }
    if inventory.runtimes.len() > MAX_RUNTIMES {
        return Err(ModelInventoryValidationError::TooManyRuntimes);
    }
    let mut runtime_ids = HashSet::with_capacity(inventory.runtimes.len());
    for runtime in &inventory.runtimes {
        if !valid_identifier(&runtime.runtime_id, 96)
            || !bounded_text(&runtime.provider, 64)
            || runtime
                .version
                .as_ref()
                .is_some_and(|value| value.len() > 64 || value.chars().any(char::is_control))
        {
            return Err(ModelInventoryValidationError::InvalidMetadata);
        }
        if !runtime_ids.insert(runtime.runtime_id.as_str()) {
            return Err(ModelInventoryValidationError::DuplicateRuntime);
        }
        validate_evidence(
            &runtime.evidence,
            inventory.generated_at_unix_ms,
            now_unix_ms,
        )?;
    }
    if inventory.models.len() > MAX_MODELS {
        return Err(ModelInventoryValidationError::TooManyModels);
    }
    let mut model_refs = HashSet::with_capacity(inventory.models.len());
    for model in &inventory.models {
        if !valid_model_ref(&model.model_ref)
            || !valid_identifier(&model.runtime_id, 96)
            || !bounded_text(&model.display_name, 160)
            || model
                .family
                .as_ref()
                .is_some_and(|value| value.len() > 96 || value.chars().any(char::is_control))
            || model
                .version
                .as_ref()
                .is_some_and(|value| value.len() > 64 || value.chars().any(char::is_control))
            || model.context_length_tokens == Some(0)
        {
            return Err(ModelInventoryValidationError::InvalidMetadata);
        }
        if !runtime_ids.contains(model.runtime_id.as_str()) {
            return Err(ModelInventoryValidationError::UnknownRuntime);
        }
        if !model_refs.insert(model.model_ref.as_str()) {
            return Err(ModelInventoryValidationError::DuplicateModel);
        }
        if model.capabilities.len() > MAX_CAPABILITIES {
            return Err(ModelInventoryValidationError::TooManyCapabilities);
        }
        let mut capabilities = HashSet::with_capacity(model.capabilities.len());
        if model
            .capabilities
            .iter()
            .any(|capability| !capabilities.insert(*capability))
        {
            return Err(ModelInventoryValidationError::DuplicateCapability);
        }
        validate_evidence(&model.evidence, inventory.generated_at_unix_ms, now_unix_ms)?;
    }
    if inventory.privacy.as_ref().is_some_and(|privacy| {
        privacy.contains_prompts == Some(true)
            || privacy.contains_user_files == Some(true)
            || privacy.contains_local_paths == Some(true)
            || privacy.contains_credentials == Some(true)
    }) {
        return Err(ModelInventoryValidationError::PrivacyViolation);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelTaskRequirements {
    pub required_capabilities: Vec<ModelCapability>,
    pub minimum_context_length_tokens: Option<u64>,
    pub minimum_memory_mb: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFitStatus {
    Compatible,
    Incompatible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFitReason {
    ModelNotInstalled,
    RuntimeUnavailable,
    RuntimeAvailabilityUnknown,
    RuntimeEvidenceNotFresh,
    ModelEvidenceNotFresh,
    RuntimeNetworkScopeUnknown,
    CapabilityNotDeclared,
    CapabilityEvidenceUnknown,
    ContextLengthUnknown,
    ContextLengthTooShort,
    HardwareMemoryUnknown,
    MemoryEstimateUnknown,
    MemoryEstimateExceedsAvailable,
    MemoryEstimateWithinAvailable,
    HardwareMemoryBelowRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCapabilityMatch {
    pub model_ref: String,
    pub status: ModelFitStatus,
    pub reasons: Vec<ModelFitReason>,
    pub evidence_confidence: EvidenceConfidence,
}

/// Match one already-installed model against task requirements. This is advisory only:
/// it never admits a workload, reserves capacity, starts a runtime or dispatches work.
/// Estimated memory that appears to fit remains Unknown rather than being promoted
/// to a verified compatibility claim.
pub fn match_model_to_task(
    inventory: &ModelRuntimeInventory,
    model_ref: &str,
    requirements: &ModelTaskRequirements,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<ModelCapabilityMatch, ModelInventoryValidationError> {
    validate_model_runtime_inventory(inventory, now_unix_ms, max_age_ms)?;
    if requirements.required_capabilities.len() > MAX_CAPABILITIES {
        return Err(ModelInventoryValidationError::InvalidRequirements);
    }
    let mut seen_required = HashSet::with_capacity(requirements.required_capabilities.len());
    if requirements.required_capabilities.iter().any(|capability| {
        *capability == ModelCapability::Unknown || !seen_required.insert(*capability)
    }) {
        return Err(ModelInventoryValidationError::InvalidRequirements);
    }
    let model = inventory
        .models
        .iter()
        .find(|model| model.model_ref == model_ref)
        .ok_or(ModelInventoryValidationError::ModelNotFound)?;
    let runtime = inventory
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime_id == model.runtime_id)
        .ok_or(ModelInventoryValidationError::UnknownRuntime)?;
    let mut reasons = Vec::new();
    let mut incompatible = false;
    let mut unknown = false;

    if model.availability != ModelAvailability::Installed {
        reasons.push(ModelFitReason::ModelNotInstalled);
        incompatible = true;
    }
    match runtime.availability {
        RuntimeAvailability::Available => {}
        RuntimeAvailability::Unavailable => {
            reasons.push(ModelFitReason::RuntimeUnavailable);
            incompatible = true;
        }
        RuntimeAvailability::Unknown => {
            reasons.push(ModelFitReason::RuntimeAvailabilityUnknown);
            unknown = true;
        }
    }
    if !evidence_is_usable(&runtime.evidence, now_unix_ms, max_age_ms) {
        reasons.push(ModelFitReason::RuntimeEvidenceNotFresh);
        unknown = true;
    }
    if !evidence_is_usable(&model.evidence, now_unix_ms, max_age_ms) {
        reasons.push(ModelFitReason::ModelEvidenceNotFresh);
        unknown = true;
    }
    if runtime.network_scope == RuntimeNetworkScope::Unknown {
        reasons.push(ModelFitReason::RuntimeNetworkScopeUnknown);
        unknown = true;
    }

    let capability_evidence_usable = evidence_is_usable(&model.evidence, now_unix_ms, max_age_ms);
    for capability in &requirements.required_capabilities {
        if model.capabilities.contains(capability) {
            if !capability_evidence_usable {
                unknown = true;
            }
        } else if capability_evidence_usable
            && !model.capabilities.contains(&ModelCapability::Unknown)
        {
            reasons.push(ModelFitReason::CapabilityNotDeclared);
            incompatible = true;
        } else {
            reasons.push(ModelFitReason::CapabilityEvidenceUnknown);
            unknown = true;
        }
    }

    if let Some(required_context) = requirements.minimum_context_length_tokens {
        match model.context_length_tokens {
            Some(actual) if actual >= required_context => {}
            Some(_) => {
                reasons.push(ModelFitReason::ContextLengthTooShort);
                incompatible = true;
            }
            None => {
                reasons.push(ModelFitReason::ContextLengthUnknown);
                unknown = true;
            }
        }
    }
    if let Some(required_memory) = requirements.minimum_memory_mb {
        match inventory.hardware.memory_available_mb {
            Some(available) if available < required_memory => {
                reasons.push(ModelFitReason::HardwareMemoryBelowRequirement);
                incompatible = true;
            }
            Some(_) => {}
            None => {
                reasons.push(ModelFitReason::HardwareMemoryUnknown);
                unknown = true;
            }
        }
    }
    if requirements.minimum_memory_mb.is_some() {
        if let Some(estimated_memory) = model.estimated_min_memory_mb {
            if let Some(available_memory) = inventory.hardware.memory_available_mb {
                if estimated_memory > available_memory {
                    reasons.push(ModelFitReason::MemoryEstimateExceedsAvailable);
                    incompatible = true;
                } else {
                    reasons.push(ModelFitReason::MemoryEstimateWithinAvailable);
                    unknown = true;
                }
            } else {
                reasons.push(ModelFitReason::HardwareMemoryUnknown);
                unknown = true;
            }
        } else {
            reasons.push(ModelFitReason::MemoryEstimateUnknown);
            unknown = true;
        }
    }

    let status = if incompatible {
        ModelFitStatus::Incompatible
    } else if unknown {
        ModelFitStatus::Unknown
    } else {
        ModelFitStatus::Compatible
    };
    Ok(ModelCapabilityMatch {
        model_ref: model.model_ref.clone(),
        status,
        reasons,
        evidence_confidence: model.evidence.confidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(confidence: EvidenceConfidence) -> ModelEvidence {
        ModelEvidence {
            source: EvidenceSource::RuntimeApi,
            confidence,
            observed_at_unix_ms: Some(1_000),
        }
    }

    fn inventory() -> ModelRuntimeInventory {
        ModelRuntimeInventory {
            schema_version: 1,
            generated_at_unix_ms: 1_000,
            device_ref: Some("device-01".into()),
            platform: ModelPlatform {
                os: "linux".into(),
                os_version: None,
                architecture: "x86_64".into(),
            },
            hardware: ModelHardware {
                cpu_logical_cores: Some(8),
                memory_total_mb: Some(16_384),
                memory_available_mb: Some(8_192),
                storage_free_mb: None,
                accelerators: vec![],
            },
            runtimes: vec![RuntimeInfo {
                runtime_id: "ollama-local".into(),
                provider: "ollama".into(),
                version: Some("0.5.0".into()),
                availability: RuntimeAvailability::Available,
                network_scope: RuntimeNetworkScope::LoopbackOnly,
                evidence: evidence(EvidenceConfidence::Verified),
            }],
            models: vec![ModelInfo {
                model_ref: "qwen2.5:7b".into(),
                runtime_id: "ollama-local".into(),
                display_name: "Qwen 2.5 7B".into(),
                family: Some("qwen2.5".into()),
                version: None,
                availability: ModelAvailability::Installed,
                size_bytes: Some(4_500_000_000),
                context_length_tokens: Some(32_768),
                estimated_min_memory_mb: Some(6_000),
                capabilities: vec![ModelCapability::Chat, ModelCapability::Coding],
                evidence: evidence(EvidenceConfidence::Verified),
            }],
            privacy: Some(PrivacyDeclaration {
                contains_prompts: Some(false),
                contains_user_files: Some(false),
                contains_local_paths: Some(false),
                contains_credentials: Some(false),
            }),
        }
    }

    fn requirements() -> ModelTaskRequirements {
        ModelTaskRequirements {
            required_capabilities: vec![ModelCapability::Chat, ModelCapability::Coding],
            minimum_context_length_tokens: Some(16_000),
            minimum_memory_mb: Some(4_096),
        }
    }

    #[test]
    fn validates_bounded_installed_runtime_inventory() {
        assert_eq!(
            validate_model_runtime_inventory(&inventory(), 1_100, 10_000),
            Ok(())
        );
    }

    #[test]
    fn rejects_duplicate_runtime_ids_and_dangling_model_runtime_references() {
        let mut value = inventory();
        value.runtimes.push(value.runtimes[0].clone());
        assert_eq!(
            validate_model_runtime_inventory(&value, 1_100, 10_000),
            Err(ModelInventoryValidationError::DuplicateRuntime)
        );

        let mut value = inventory();
        value.models[0].runtime_id = "missing-runtime".into();
        assert_eq!(
            validate_model_runtime_inventory(&value, 1_100, 10_000),
            Err(ModelInventoryValidationError::UnknownRuntime)
        );
    }

    #[test]
    fn rejects_future_stale_and_privacy_violating_snapshots() {
        let mut value = inventory();
        value.generated_at_unix_ms = 50_000;
        assert_eq!(
            validate_model_runtime_inventory(&value, 1_000, 10_000),
            Err(ModelInventoryValidationError::FutureTimestamp)
        );

        let mut value = inventory();
        assert_eq!(
            validate_model_runtime_inventory(&value, 20_000, 1_000),
            Err(ModelInventoryValidationError::StaleInventory)
        );

        let mut value = inventory();
        value.privacy.as_mut().unwrap().contains_prompts = Some(true);
        assert_eq!(
            validate_model_runtime_inventory(&value, 1_100, 10_000),
            Err(ModelInventoryValidationError::PrivacyViolation)
        );
    }

    #[test]
    fn matches_only_installed_models_with_fresh_declared_capabilities() {
        let value = inventory();
        let result =
            match_model_to_task(&value, "qwen2.5:7b", &requirements(), 1_100, 10_000).unwrap();
        assert_eq!(result.status, ModelFitStatus::Unknown);
        assert!(result
            .reasons
            .contains(&ModelFitReason::MemoryEstimateWithinAvailable));
        assert_eq!(result.evidence_confidence, EvidenceConfidence::Verified);

        let mut value = inventory();
        value.models[0].estimated_min_memory_mb = None;
        let result = match_model_to_task(&value, "qwen2.5:7b", &requirements(), 1_100, 10_000)
            .unwrap();
        assert!(result
            .reasons
            .contains(&ModelFitReason::MemoryEstimateUnknown));
        assert_eq!(result.status, ModelFitStatus::Unknown);
    }

    #[test]
    fn reports_known_capability_and_context_mismatches_as_incompatible() {
        let mut value = inventory();
        value.models[0].capabilities = vec![ModelCapability::Chat];
        value.models[0].context_length_tokens = Some(8_192);
        let result = match_model_to_task(&value, "qwen2.5:7b", &requirements(), 1_100, 10_000)
            .unwrap();
        assert_eq!(result.status, ModelFitStatus::Incompatible);
        assert!(result
            .reasons
            .contains(&ModelFitReason::CapabilityNotDeclared));
        assert!(result
            .reasons
            .contains(&ModelFitReason::ContextLengthTooShort));
    }

    #[test]
    fn unknown_capability_evidence_never_becomes_a_false_positive() {
        let mut value = inventory();
        value.models[0].evidence.confidence = EvidenceConfidence::Unknown;
        value.models[0].capabilities = vec![ModelCapability::Chat];
        let result = match_model_to_task(
            &value,
            "qwen2.5:7b",
            &ModelTaskRequirements {
                required_capabilities: vec![ModelCapability::Vision],
                minimum_context_length_tokens: None,
                minimum_memory_mb: None,
            },
            1_100,
            10_000,
        )
        .unwrap();
        assert_eq!(result.status, ModelFitStatus::Unknown);
        assert!(result
            .reasons
            .contains(&ModelFitReason::CapabilityEvidenceUnknown));
    }

    #[test]
    fn capability_only_match_can_be_compatible_without_claiming_memory_fit() {
        let value = inventory();
        let mut task = requirements();
        task.minimum_memory_mb = None;
        let result = match_model_to_task(&value, "qwen2.5:7b", &task, 1_100, 10_000).unwrap();
        assert_eq!(result.status, ModelFitStatus::Compatible);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn downloadable_models_are_not_eligible_for_installed_model_matching() {
        let mut value = inventory();
        value.models[0].availability = ModelAvailability::Downloadable;
        let result = match_model_to_task(&value, "qwen2.5:7b", &requirements(), 1_100, 10_000)
            .unwrap();
        assert_eq!(result.status, ModelFitStatus::Incompatible);
        assert!(result.reasons.contains(&ModelFitReason::ModelNotInstalled));
    }

    #[test]
    fn rejects_duplicate_capabilities_and_unknown_task_requirements() {
        let mut value = inventory();
        value.models[0].capabilities.push(ModelCapability::Chat);
        assert_eq!(
            validate_model_runtime_inventory(&value, 1_100, 10_000),
            Err(ModelInventoryValidationError::DuplicateCapability)
        );

        let value = inventory();
        let invalid = ModelTaskRequirements {
            required_capabilities: vec![ModelCapability::Unknown],
            minimum_context_length_tokens: None,
            minimum_memory_mb: None,
        };
        assert_eq!(
            match_model_to_task(&value, "qwen2.5:7b", &invalid, 1_100, 10_000),
            Err(ModelInventoryValidationError::InvalidRequirements)
        );
    }
}
