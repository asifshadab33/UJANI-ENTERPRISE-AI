//! Authenticated, bounded Enterprise model/runtime inventory v2 intake boundary.
//!
//! This module verifies the enrolled-device signature over the exact raw body,
//! checks current device trust and owner opt-in, and applies the Enterprise-only
//! privacy/consent preflight. It deliberately does not consume replay state or
//! persist inventory. The hosting service MUST perform full JSON Schema v2
//! validation and atomically re-check tenant, key generation, owner-consent
//! generation, administrator authorisation and replay state while persisting
//! the inventory and its audit receipt. No workload or execution rights result.

use crate::device_trust::durable::{DurableDeviceRegistry, DurableDeviceTrustError};
use crate::device_trust::{
    AuthenticatedDeviceRequest, SignedDeviceRequest, MAX_DEVICE_REQUEST_BODY_BYTES,
};
use crate::model_inventory_v2_preflight::{
    validate_enterprise_inventory_v2_preflight, InventoryV2PreflightError,
};
use crate::operator_http_contract::{resolve_route, HttpMethod, OperatorHttpRoute};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MODEL_INVENTORY_REQUEST_METHOD: &str = "POST";
pub const MODEL_INVENTORY_REQUEST_RESOURCE: &str = "model-inventory:ingest";
pub const MODEL_INVENTORY_REQUEST_WORKLOAD: &str = "model-inventory";
const MODEL_INVENTORY_BINDING_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-MODEL-INVENTORY-V2-REQUEST\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelInventoryV2IntakeError {
    InvalidRoute,
    BodyTooLarge,
    InvalidJson,
    Preflight(InventoryV2PreflightError),
    RequestBindingMismatch,
    DeviceAuthenticationFailed,
    OwnerConsentMissing,
    TrustStoreUnavailable,
}

impl ModelInventoryV2IntakeError {
    /// Generic status mapping; never disclose tenant, key or trust-store details.
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRoute => 404,
            Self::RequestBindingMismatch | Self::DeviceAuthenticationFailed => 401,
            Self::OwnerConsentMissing | Self::Preflight(_) => 403,
            Self::TrustStoreUnavailable => 503,
            Self::BodyTooLarge => 413,
            Self::InvalidJson => 400,
        }
    }
}

/// Domain-separated manifest digest selected by the server-side route.
pub fn model_inventory_v2_request_manifest_digest() -> [u8; 32] {
    Sha256::digest(MODEL_INVENTORY_BINDING_DOMAIN).into()
}

/// Authenticate and preflight exact raw inventory bytes without consuming the
/// durable replay claim. The database acceptance transaction owns replay state.
pub fn authenticate_model_inventory_v2_request(
    registry: &DurableDeviceRegistry,
    method: HttpMethod,
    path: &str,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    now_unix_ms: u64,
) -> Result<(AuthenticatedDeviceRequest, Value), ModelInventoryV2IntakeError> {
    let route = resolve_route(method, path).ok_or(ModelInventoryV2IntakeError::InvalidRoute)?;
    if route.route != OperatorHttpRoute::DeviceModelInventory
        || raw_body.is_empty()
        || raw_body.len() > MAX_DEVICE_REQUEST_BODY_BYTES
        || !route.permits_body_size(raw_body.len())
    {
        return Err(
            if raw_body.len() > MAX_DEVICE_REQUEST_BODY_BYTES
                || raw_body.len() > route.max_body_bytes
            {
                ModelInventoryV2IntakeError::BodyTooLarge
            } else {
                ModelInventoryV2IntakeError::InvalidRoute
            },
        );
    }

    let payload: Value =
        serde_json::from_slice(raw_body).map_err(|_| ModelInventoryV2IntakeError::InvalidJson)?;
    let path_device_id = path.split('/').nth(3).unwrap_or_default();
    if path_device_id != signed_request.claims.device_id
        || signed_request.claims.method != MODEL_INVENTORY_REQUEST_METHOD
        || signed_request.claims.resource_id != MODEL_INVENTORY_REQUEST_RESOURCE
        || signed_request.claims.workload_id != MODEL_INVENTORY_REQUEST_WORKLOAD
        || signed_request.claims.manifest_sha256 != model_inventory_v2_request_manifest_digest()
    {
        return Err(ModelInventoryV2IntakeError::RequestBindingMismatch);
    }

    let authenticated = registry
        .verify_request_for(
            signed_request,
            MODEL_INVENTORY_REQUEST_METHOD,
            MODEL_INVENTORY_REQUEST_RESOURCE,
            raw_body,
            now_unix_ms,
        )
        .map_err(map_device_trust_error)?;
    if authenticated.device_id() != path_device_id {
        return Err(ModelInventoryV2IntakeError::RequestBindingMismatch);
    }
    let (_, owner_opted_in) = registry
        .authenticated_device_status_for_request(&authenticated)
        .map_err(map_device_trust_error)?;
    if !owner_opted_in {
        return Err(ModelInventoryV2IntakeError::OwnerConsentMissing);
    }
    validate_enterprise_inventory_v2_preflight(&payload, authenticated.device_id())
        .map_err(ModelInventoryV2IntakeError::Preflight)?;
    Ok((authenticated, payload))
}

/// Convert trust failures to non-leaky authentication or service errors.
pub fn map_device_trust_error(error: DurableDeviceTrustError) -> ModelInventoryV2IntakeError {
    match error {
        DurableDeviceTrustError::Trust(_) => {
            ModelInventoryV2IntakeError::DeviceAuthenticationFailed
        }
        DurableDeviceTrustError::Io(_)
        | DurableDeviceTrustError::CorruptState
        | DurableDeviceTrustError::CapacityExceeded
        | DurableDeviceTrustError::KeyProvider(_)
        | DurableDeviceTrustError::LockPoisoned
        | DurableDeviceTrustError::AnchorUnavailable(_)
        | DurableDeviceTrustError::AnchorMismatch
        | DurableDeviceTrustError::AnchorConflict
        | DurableDeviceTrustError::AnchorGenerationExhausted => {
            ModelInventoryV2IntakeError::TrustStoreUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_http_contract::MAX_MODEL_INVENTORY_BODY_BYTES;

    #[test]
    fn intake_errors_have_generic_non_leaky_statuses() {
        assert_eq!(ModelInventoryV2IntakeError::InvalidRoute.http_status(), 404);
        assert_eq!(
            ModelInventoryV2IntakeError::DeviceAuthenticationFailed.http_status(),
            401
        );
        assert_eq!(
            ModelInventoryV2IntakeError::OwnerConsentMissing.http_status(),
            403
        );
        assert_eq!(
            ModelInventoryV2IntakeError::TrustStoreUnavailable.http_status(),
            503
        );
        assert_eq!(ModelInventoryV2IntakeError::BodyTooLarge.http_status(), 413);
    }

    #[test]
    fn request_binding_digest_is_stable_and_domain_separated() {
        let expected: [u8; 32] = Sha256::digest(MODEL_INVENTORY_BINDING_DOMAIN).into();
        let telemetry: [u8; 32] =
            Sha256::digest(b"UJANI-ENTERPRISE-DEVICE-TELEMETRY-REQUEST-V1\\0").into();
        assert_eq!(model_inventory_v2_request_manifest_digest(), expected);
        assert_ne!(model_inventory_v2_request_manifest_digest(), telemetry);
    }

    #[test]
    fn inventory_route_body_limit_matches_the_shared_device_request_ceiling() {
        assert_eq!(
            MAX_MODEL_INVENTORY_BODY_BYTES,
            MAX_DEVICE_REQUEST_BODY_BYTES
        );
    }
}
