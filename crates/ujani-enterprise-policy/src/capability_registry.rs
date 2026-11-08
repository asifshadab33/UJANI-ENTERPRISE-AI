//! In-memory, tenant-scoped capability metadata registry.
//!
//! This is a local policy/metadata primitive only. It does not discover external
//! providers, authenticate connectors, invoke tools, persist records, or execute
//! state-changing operations. Provider health must be supplied by a trusted host.

use std::collections::BTreeMap;

/// Version of the capability descriptor schema accepted by this registry.
pub const CAPABILITY_SCHEMA_VERSION: u16 = 1;
const MAX_IDENTIFIER_LEN: usize = 96;
const MAX_PERMISSIONS: usize = 32;
const MAX_CPU_MILLIS: u32 = 1_000_000;
const MAX_MEMORY_MB: u64 = 4 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

/// Declares whether a capability is read-only, preview-only, or state-changing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    ReadOnly,
    Preview,
    StateChanging,
}

pub use crate::DataClassification;

/// Last host-supplied health state for a provider; unknown is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHealth {
    Unknown,
    Healthy,
    Degraded,
    Unavailable,
}

/// Hard upper bounds a host must enforce when invoking a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudget {
    pub max_cpu_millis: u32,
    pub max_memory_mb: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub timeout_ms: u64,
}

/// Tenant-bound metadata describing one capability and its execution constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    pub tenant_id: String,
    pub capability_id: String,
    pub schema_version: u16,
    pub provider_id: String,
    pub provider_version: String,
    pub adapter_version: String,
    pub operation: OperationClass,
    pub required_permissions: Vec<String>,
    pub data_classification: DataClassification,
    pub requires_network: bool,
    pub requires_external_service: bool,
    pub external_data_egress: bool,
    pub supports_offline: bool,
    pub resource_budget: ResourceBudget,
}

/// Fail-closed validation and registration errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    InvalidTenantId,
    InvalidIdentifier,
    InvalidVersion,
    UnsupportedSchemaVersion,
    TenantMismatch,
    DuplicateCapability,
    UnknownProvider,
    TooManyPermissions,
    InvalidPermission,
    InvalidResourceBudget,
    OfflineRequiresExternalService,
    StateChangingDisabled,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
}

impl ResourceBudget {
    /// Returns whether every requested resource ceiling is within the registry limits.
    fn is_valid(self) -> bool {
        self.max_cpu_millis > 0
            && self.max_cpu_millis <= MAX_CPU_MILLIS
            && self.max_memory_mb > 0
            && self.max_memory_mb <= MAX_MEMORY_MB
            && self.max_request_bytes > 0
            && self.max_request_bytes <= MAX_PAYLOAD_BYTES
            && self.max_response_bytes > 0
            && self.max_response_bytes <= MAX_PAYLOAD_BYTES
            && self.timeout_ms > 0
            && self.timeout_ms <= MAX_TIMEOUT_MS
    }
}

impl CapabilityDescriptor {
    /// Validates descriptor metadata against the selected tenant and safe-operation policy.
    fn validate_for_tenant(&self, tenant_id: &str) -> Result<(), RegistryError> {
        if self.tenant_id != tenant_id {
            return Err(RegistryError::TenantMismatch);
        }
        if !valid_identifier(&self.tenant_id)
            || !valid_identifier(&self.capability_id)
            || !valid_identifier(&self.provider_id)
        {
            return Err(RegistryError::InvalidIdentifier);
        }
        if !valid_version(&self.provider_version) || !valid_version(&self.adapter_version) {
            return Err(RegistryError::InvalidVersion);
        }
        if self.schema_version != CAPABILITY_SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedSchemaVersion);
        }
        if self.required_permissions.len() > MAX_PERMISSIONS {
            return Err(RegistryError::TooManyPermissions);
        }
        if self
            .required_permissions
            .iter()
            .any(|permission| !valid_identifier(permission))
        {
            return Err(RegistryError::InvalidPermission);
        }
        if !self.resource_budget.is_valid() {
            return Err(RegistryError::InvalidResourceBudget);
        }
        if self.supports_offline
            && (self.requires_external_service || self.requires_network || self.external_data_egress)
        {
            return Err(RegistryError::OfflineRequiresExternalService);
        }
        if self.operation == OperationClass::StateChanging {
            return Err(RegistryError::StateChangingDisabled);
        }
        Ok(())
    }
}

/// A per-tenant registry. The host must authenticate the caller and choose the
/// tenant boundary before constructing or exposing this registry.
#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    tenant_id: String,
    capabilities: BTreeMap<String, CapabilityDescriptor>,
    provider_health: BTreeMap<String, ProviderHealth>,
}

impl CapabilityRegistry {
    /// Creates an empty registry for one validated tenant identifier.
    pub fn new(tenant_id: impl Into<String>) -> Result<Self, RegistryError> {
        let tenant_id = tenant_id.into();
        if !valid_identifier(&tenant_id) {
            return Err(RegistryError::InvalidTenantId);
        }
        Ok(Self {
            tenant_id,
            capabilities: BTreeMap::new(),
            provider_health: BTreeMap::new(),
        })
    }

    /// Registers metadata only; this does not authenticate or connect to a provider.
    pub fn register(&mut self, descriptor: CapabilityDescriptor) -> Result<(), RegistryError> {
        descriptor.validate_for_tenant(&self.tenant_id)?;
        let capability_id = descriptor.capability_id.clone();
        if self.capabilities.contains_key(&capability_id) {
            return Err(RegistryError::DuplicateCapability);
        }
        self.provider_health
            .entry(descriptor.provider_id.clone())
            .or_insert(ProviderHealth::Unknown);
        self.capabilities.insert(capability_id, descriptor);
        Ok(())
    }

    /// Returns a registered descriptor by capability ID without invoking its provider.
    pub fn get(&self, capability_id: &str) -> Option<&CapabilityDescriptor> {
        self.capabilities.get(capability_id)
    }

    /// Returns descriptors in stable ID order. This is inventory, not an
    /// authorization decision or proof that a provider is reachable.
    /// Returns descriptors in stable capability-ID order.
    pub fn list(&self) -> Vec<&CapabilityDescriptor> {
        self.capabilities.values().collect()
    }

    /// Health is supplied by the trusted host after its own connector checks.
    /// Updates host-supplied provider health; this does not probe or authenticate the provider.
    pub fn set_provider_health(
        &mut self,
        provider_id: &str,
        health: ProviderHealth,
    ) -> Result<(), RegistryError> {
        let status = self
            .provider_health
            .get_mut(provider_id)
            .ok_or(RegistryError::UnknownProvider)?;
        *status = health;
        Ok(())
    }

    /// Returns the last supplied health state, or Unknown when none has been recorded.
    pub fn provider_health(&self, provider_id: &str) -> ProviderHealth {
        self.provider_health
            .get(provider_id)
            .copied()
            .unwrap_or(ProviderHealth::Unknown)
    }

    /// Only healthy read-only/preview capabilities are discoverable for routing.
    /// Degraded, unknown and unavailable providers fail closed.
    /// Returns only read-only or preview capabilities whose providers are marked Healthy.
    pub fn routable(&self) -> Vec<&CapabilityDescriptor> {
        self.capabilities
            .values()
            .filter(|descriptor| {
                self.provider_health(&descriptor.provider_id) == ProviderHealth::Healthy
                    && matches!(
                        descriptor.operation,
                        OperationClass::ReadOnly | OperationClass::Preview
                    )
            })
            .collect()
    }

    /// Reports whether one registered capability currently passes the local routing policy.
    pub fn is_routable(&self, capability_id: &str) -> bool {
        self.get(capability_id).is_some_and(|descriptor| {
            self.provider_health(&descriptor.provider_id) == ProviderHealth::Healthy
                && matches!(
                    descriptor.operation,
                    OperationClass::ReadOnly | OperationClass::Preview
                )
        })
    }

    /// Returns the tenant boundary chosen when this registry was constructed.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityDescriptor, CapabilityRegistry, DataClassification, OperationClass,
        ProviderHealth, RegistryError, ResourceBudget, CAPABILITY_SCHEMA_VERSION,
    };

    fn descriptor(capability_id: &str, operation: OperationClass) -> CapabilityDescriptor {
        CapabilityDescriptor {
            tenant_id: "tenant-a".into(),
            capability_id: capability_id.into(),
            schema_version: CAPABILITY_SCHEMA_VERSION,
            provider_id: "provider-zeek".into(),
            provider_version: "6.2.0".into(),
            adapter_version: "1.0.0".into(),
            operation,
            required_permissions: vec!["network.read".into()],
            data_classification: DataClassification::Internal,
            requires_network: true,
            requires_external_service: false,
            external_data_egress: false,
            supports_offline: false,
            resource_budget: ResourceBudget {
                max_cpu_millis: 500,
                max_memory_mb: 256,
                max_request_bytes: 1024 * 1024,
                max_response_bytes: 4 * 1024 * 1024,
                timeout_ms: 5_000,
            },
        }
    }

    #[test]
    fn registry_is_tenant_scoped_and_rejects_cross_tenant_descriptors() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        let mut item = descriptor("network.connections.read", OperationClass::ReadOnly);
        item.tenant_id = "tenant-b".into();
        assert_eq!(registry.register(item), Err(RegistryError::TenantMismatch));
        assert!(registry.list().is_empty());
    }

    #[test]
    fn registration_is_metadata_only_and_provider_starts_unknown() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        registry
            .register(descriptor(
                "network.connections.read",
                OperationClass::ReadOnly,
            ))
            .unwrap();
        assert_eq!(
            registry.provider_health("provider-zeek"),
            ProviderHealth::Unknown
        );
        assert!(!registry.is_routable("network.connections.read"));
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn only_healthy_read_only_or_preview_capabilities_are_routable() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        registry
            .register(descriptor(
                "network.connections.read",
                OperationClass::ReadOnly,
            ))
            .unwrap();
        registry
            .register(descriptor(
                "firewall.policy.preview",
                OperationClass::Preview,
            ))
            .unwrap();
        registry
            .set_provider_health("provider-zeek", ProviderHealth::Healthy)
            .unwrap();
        assert_eq!(registry.routable().len(), 2);
        registry
            .set_provider_health("provider-zeek", ProviderHealth::Degraded)
            .unwrap();
        assert!(registry.routable().is_empty());
    }

    #[test]
    fn state_changing_capabilities_are_rejected_by_default() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        assert_eq!(
            registry.register(descriptor(
                "firewall.rule.apply",
                OperationClass::StateChanging
            )),
            Err(RegistryError::StateChangingDisabled)
        );
    }

    #[test]
    fn duplicate_capability_ids_are_rejected() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        let item = descriptor("network.connections.read", OperationClass::ReadOnly);
        registry.register(item.clone()).unwrap();
        assert_eq!(
            registry.register(item),
            Err(RegistryError::DuplicateCapability)
        );
    }

    #[test]
    fn invalid_resource_budgets_are_rejected() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        let mut item = descriptor("network.connections.read", OperationClass::ReadOnly);
        item.resource_budget.timeout_ms = 0;
        assert_eq!(
            registry.register(item),
            Err(RegistryError::InvalidResourceBudget)
        );
    }

    #[test]
    fn external_dependencies_cannot_claim_offline_support() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        let mut item = descriptor("cloud.lookup", OperationClass::ReadOnly);
        item.requires_external_service = true;
        item.supports_offline = true;
        assert_eq!(
            registry.register(item),
            Err(RegistryError::OfflineRequiresExternalService)
        );
    }

    #[test]
    fn offline_capabilities_cannot_require_network_or_egress() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        let mut network = descriptor("offline.network", OperationClass::ReadOnly);
        network.requires_network = true;
        network.supports_offline = true;
        assert_eq!(
            registry.register(network),
            Err(RegistryError::OfflineRequiresExternalService)
        );

        let mut egress = descriptor("offline.egress", OperationClass::ReadOnly);
        egress.external_data_egress = true;
        egress.supports_offline = true;
        assert_eq!(
            registry.register(egress),
            Err(RegistryError::OfflineRequiresExternalService)
        );
    }

    #[test]
    fn unsupported_schema_versions_are_rejected() {
        let mut registry = CapabilityRegistry::new("tenant-a").unwrap();
        let mut item = descriptor("network.connections.read", OperationClass::ReadOnly);
        item.schema_version = 2;
        assert_eq!(
            registry.register(item),
            Err(RegistryError::UnsupportedSchemaVersion)
        );
    }
}
