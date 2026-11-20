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
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MODEL_INVENTORY_REQUEST_METHOD: &str = "POST";
pub const MODEL_INVENTORY_REQUEST_RESOURCE: &str = "model-inventory:ingest";
pub const MODEL_INVENTORY_REQUEST_WORKLOAD: &str = "model-inventory";
const MODEL_INVENTORY_BINDING_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-MODEL-INVENTORY-V2-REQUEST\0";

/// JSON value decoder that rejects duplicate object keys recursively.
/// The default Value decoder otherwise silently keeps the last value.
struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde::Deserializer::deserialize_any(deserializer, StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(StrictJsonValue(Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON object key: {key}")));
            }
            values.insert(key, object.next_value::<StrictJsonValue>()?.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

fn parse_strict_json(raw: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}


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

/// Extract the device identifier only from the canonical API-v1 model-inventory route.
fn model_inventory_device_id(path: &str) -> Option<&str> {
    let route = resolve_route(HttpMethod::Post, path)?;
    if route.route != OperatorHttpRoute::DeviceModelInventory {
        return None;
    }
    path.split('/').nth(4)
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

    let payload =
        parse_strict_json(raw_body).map_err(|_| ModelInventoryV2IntakeError::InvalidJson)?;
    // resolve_route above validates the canonical prefix and endpoint.
    let path_device_id =
        model_inventory_device_id(path).ok_or(ModelInventoryV2IntakeError::InvalidRoute)?;
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
    fn strict_json_decoder_rejects_duplicate_keys_at_all_nesting_levels() {
        for raw in [
            br#"{"schema_version":2,"schema_version":2}"# as &[u8],
            br#"{"collection_context":{"scope":"organisation_enrolled","scope":"personal_local_only"}}"#,
            br#"{"models":[{"model_id":"one","model_id":"two"}]}"#,
        ] {
            let error = parse_strict_json(raw).unwrap_err();
            assert!(error.to_string().contains("duplicate JSON object key"));
        }
    }

    #[test]
    fn strict_json_decoder_accepts_valid_nested_payload_and_rejects_trailing_data() {
        let value = parse_strict_json(br#"{"schema_version":2,"models":[{"name":"local"}]}"#).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["models"][0]["name"], "local");
        assert!(parse_strict_json(br#"{"schema_version":2} trailing"#).is_err());
    }

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
    fn model_inventory_path_extracts_only_the_canonical_api_v1_device_segment() {
        assert_eq!(
            model_inventory_device_id("/api/v1/devices/device-01/model-inventory"),
            Some("device-01")
        );
        assert_eq!(
            model_inventory_device_id("/v1/devices/device-01/model-inventory"),
            None
        );
        assert_eq!(
            model_inventory_device_id("/api/v1/devices/../model-inventory"),
            None
        );
        assert_eq!(
            model_inventory_device_id("/api/v1/devices/device-01/telemetry"),
            None
        );
    }

    #[test]
    fn inventory_route_body_limit_matches_the_shared_device_request_ceiling() {
        assert_eq!(
            MAX_MODEL_INVENTORY_BODY_BYTES,
            MAX_DEVICE_REQUEST_BODY_BYTES
        );
    }
}
