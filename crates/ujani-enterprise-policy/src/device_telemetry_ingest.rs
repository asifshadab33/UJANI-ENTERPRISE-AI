//! Authenticated, bounded device telemetry intake boundary.
//!
//! This module validates the privacy-minimised telemetry body before consuming
//! the signed request nonce, then authenticates the exact raw bytes against the
//! enrolled device key and rechecks current owner consent. The caller must pass
//! the returned tenant/device identity and sample fields to the tenant-scoped
//! database transaction (migration 0003); this module does not persist samples.
//! The database transaction remains authoritative for monotonic generation /
//! sequence, replay, trust and dual-consent checks under concurrent requests.

use crate::device_trust::durable::{DurableDeviceRegistry, DurableDeviceTrustError};
use crate::device_trust::{
    AuthenticatedDeviceRequest, SignedDeviceRequest, MAX_DEVICE_REQUEST_BODY_BYTES,
};
use crate::operator_http_contract::{resolve_route, HttpMethod, OperatorHttpRoute};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const DEVICE_TELEMETRY_REQUEST_METHOD: &str = "POST";
pub const DEVICE_TELEMETRY_REQUEST_RESOURCE: &str = "device-telemetry:ingest";
pub const DEVICE_TELEMETRY_REQUEST_WORKLOAD: &str = "device-telemetry";
pub const MAX_DEVICE_TELEMETRY_AGE_MS: u64 = 5 * 60 * 1000;
pub const MAX_DEVICE_TELEMETRY_FUTURE_SKEW_MS: u64 = 60 * 1000;
const TELEMETRY_BINDING_DOMAIN: &[u8] = b"UJANI-ENTERPRISE-DEVICE-TELEMETRY-REQUEST-V1\0";

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceThermalState {
    Cool,
    Warm,
    Hot,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DevicePowerState {
    Ac,
    Battery,
    LowBattery,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceParticipationState {
    Idle,
    Interactive,
    Paused,
    Disabled,
    Unknown,
}

/// Only resource and participation facts required by the existing telemetry
/// migration are accepted. Prompts, paths, process lists and arbitrary fields
/// are rejected by deny_unknown_fields.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeviceTelemetryBody {
    schema_version: u16,
    device_id: String,
    generation: u64,
    sequence: u64,
    observed_at_unix_ms: u64,
    cpu_available_millis: Option<u32>,
    memory_available_mb: Option<u64>,
    thermal_state: DeviceThermalState,
    power_state: DevicePowerState,
    participation_state: DeviceParticipationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTelemetrySample {
    pub device_id: String,
    pub generation: u64,
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub cpu_available_millis: Option<u32>,
    pub memory_available_mb: Option<u64>,
    pub thermal_state: DeviceThermalState,
    pub power_state: DevicePowerState,
    pub participation_state: DeviceParticipationState,
    pub payload_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTelemetryIntakeError {
    UnsupportedVersion,
    InvalidDeviceId,
    InvalidGenerationOrSequence,
    InvalidResourceMeasurement,
    StaleOrFutureSample,
    InvalidRoute,
    RequestBindingMismatch,
    DeviceAuthenticationFailed,
    OwnerConsentMissing,
    TrustStoreUnavailable,
}

impl DeviceTelemetryIntakeError {
    /// Generic HTTP status mapping; callers must not disclose trust-store details.
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRoute => 404,
            Self::DeviceAuthenticationFailed | Self::RequestBindingMismatch => 401,
            Self::OwnerConsentMissing => 403,
            Self::TrustStoreUnavailable => 503,
            _ => 400,
        }
    }
}

fn valid_device_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

/// Stable digest binding the device request to the telemetry-ingest operation.
pub fn device_telemetry_request_manifest_digest() -> [u8; 32] {
    Sha256::digest(TELEMETRY_BINDING_DOMAIN).into()
}

/// Parse and validate exact raw telemetry bytes without consuming a replay nonce.
pub fn validate_device_telemetry_body(
    raw_body: &[u8],
    now_unix_ms: u64,
) -> Result<DeviceTelemetrySample, DeviceTelemetryIntakeError> {
    if raw_body.is_empty() || raw_body.len() > MAX_DEVICE_REQUEST_BODY_BYTES {
        return Err(DeviceTelemetryIntakeError::InvalidResourceMeasurement);
    }
    let body: DeviceTelemetryBody = serde_json::from_slice(raw_body)
        .map_err(|_| DeviceTelemetryIntakeError::InvalidResourceMeasurement)?;
    if body.schema_version != 1 {
        return Err(DeviceTelemetryIntakeError::UnsupportedVersion);
    }
    if !valid_device_id(&body.device_id) {
        return Err(DeviceTelemetryIntakeError::InvalidDeviceId);
    }
    if body.generation == 0 || body.sequence == 0 {
        return Err(DeviceTelemetryIntakeError::InvalidGenerationOrSequence);
    }
    if body
        .cpu_available_millis
        .is_some_and(|value| value > 65_535_000)
        || body
            .memory_available_mb
            .is_some_and(|value| value > 16_777_216)
    {
        return Err(DeviceTelemetryIntakeError::InvalidResourceMeasurement);
    }
    if body.observed_at_unix_ms > now_unix_ms.saturating_add(MAX_DEVICE_TELEMETRY_FUTURE_SKEW_MS)
        || now_unix_ms.saturating_sub(body.observed_at_unix_ms) > MAX_DEVICE_TELEMETRY_AGE_MS
    {
        return Err(DeviceTelemetryIntakeError::StaleOrFutureSample);
    }
    Ok(DeviceTelemetrySample {
        device_id: body.device_id,
        generation: body.generation,
        sequence: body.sequence,
        observed_at_unix_ms: body.observed_at_unix_ms,
        cpu_available_millis: body.cpu_available_millis,
        memory_available_mb: body.memory_available_mb,
        thermal_state: body.thermal_state,
        power_state: body.power_state,
        participation_state: body.participation_state,
        payload_digest: Sha256::digest(raw_body).into(),
    })
}

/// Authenticate a telemetry request at the service boundary.
///
/// The route selects method/resource; tenant identity comes only from the
/// enrolled device key. Administrator approval is represented by the durable
/// enrollment state. Owner opt-in is re-read from the current key generation.
/// The SQL acceptance function must repeat both consent/trust checks and enforce
/// monotonic generation/sequence in the same transaction that inserts the sample.
pub fn authenticate_device_telemetry_request(
    registry: &DurableDeviceRegistry,
    method: HttpMethod,
    path: &str,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    now_unix_ms: u64,
) -> Result<(AuthenticatedDeviceRequest, DeviceTelemetrySample), DeviceTelemetryIntakeError> {
    let route = resolve_route(method, path).ok_or(DeviceTelemetryIntakeError::InvalidRoute)?;
    if route.route != OperatorHttpRoute::DeviceTelemetry
        || route.max_body_bytes < raw_body.len()
        || !route.permits_body_size(raw_body.len())
    {
        return Err(DeviceTelemetryIntakeError::InvalidRoute);
    }

    let sample = validate_device_telemetry_body(raw_body, now_unix_ms)?;
    let path_device_id = path.split('/').nth(3).unwrap_or_default();
    if path_device_id != sample.device_id
        || signed_request.claims.device_id != sample.device_id
        || signed_request.claims.method != DEVICE_TELEMETRY_REQUEST_METHOD
        || signed_request.claims.resource_id != DEVICE_TELEMETRY_REQUEST_RESOURCE
        || signed_request.claims.workload_id != DEVICE_TELEMETRY_REQUEST_WORKLOAD
        || signed_request.claims.manifest_sha256 != device_telemetry_request_manifest_digest()
    {
        return Err(DeviceTelemetryIntakeError::RequestBindingMismatch);
    }

    let authenticated = registry
        .authenticate_request_for(
            signed_request,
            DEVICE_TELEMETRY_REQUEST_METHOD,
            DEVICE_TELEMETRY_REQUEST_RESOURCE,
            raw_body,
            now_unix_ms,
        )
        .map_err(|_| DeviceTelemetryIntakeError::DeviceAuthenticationFailed)?;

    if authenticated.device_id() != sample.device_id {
        return Err(DeviceTelemetryIntakeError::RequestBindingMismatch);
    }
    let owner_opted_in = registry
        .authenticated_device_status_for_request(&authenticated)
        .map(|(_, opted_in)| opted_in)
        .map_err(|_| DeviceTelemetryIntakeError::TrustStoreUnavailable)?;
    if !owner_opted_in {
        return Err(DeviceTelemetryIntakeError::OwnerConsentMissing);
    }
    Ok((authenticated, sample))
}

/// Convert trust-store errors to a generic intake failure without leaking
/// whether a device, tenant, key or replay record exists.
pub fn map_device_trust_error(_: DurableDeviceTrustError) -> DeviceTelemetryIntakeError {
    DeviceTelemetryIntakeError::DeviceAuthenticationFailed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(observed_at: u64) -> Vec<u8> {
        format!(
            r#"{{"schema_version":1,"device_id":"device-1","generation":2,"sequence":7,"observed_at_unix_ms":{observed_at},"cpu_available_millis":1200,"memory_available_mb":4096,"thermal_state":"cool","power_state":"ac","participation_state":"idle"}}"#
        )
        .into_bytes()
    }

    #[test]
    fn accepts_bounded_privacy_minimised_telemetry() {
        let raw = body(1_000);
        let sample = validate_device_telemetry_body(&raw, 1_100).unwrap();
        assert_eq!(sample.device_id, "device-1");
        assert_eq!(sample.generation, 2);
        assert_eq!(sample.sequence, 7);
        assert_eq!(sample.cpu_available_millis, Some(1_200));
        assert_eq!(sample.memory_available_mb, Some(4_096));
        let expected_digest: [u8; 32] = Sha256::digest(&raw).into();
        assert_eq!(sample.payload_digest, expected_digest);
    }

    #[test]
    fn rejects_unknown_fields_including_private_content() {
        let raw = br#"{"schema_version":1,"device_id":"device-1","generation":1,"sequence":1,"observed_at_unix_ms":1000,"cpu_available_millis":1,"memory_available_mb":1,"thermal_state":"cool","power_state":"ac","participation_state":"idle","prompt":"must-not-be-collected"}"#;
        assert_eq!(
            validate_device_telemetry_body(raw, 1_000),
            Err(DeviceTelemetryIntakeError::InvalidResourceMeasurement)
        );
    }

    #[test]
    fn rejects_stale_future_and_zero_watermarks() {
        assert_eq!(
            validate_device_telemetry_body(&body(1), 400_000),
            Err(DeviceTelemetryIntakeError::StaleOrFutureSample)
        );
        assert_eq!(
            validate_device_telemetry_body(&body(200_000), 1_000),
            Err(DeviceTelemetryIntakeError::StaleOrFutureSample)
        );
        let zero = body(1_000).iter().copied().collect::<Vec<_>>();
        let zero = String::from_utf8(zero)
            .unwrap()
            .replace("\"sequence\":7", "\"sequence\":0");
        assert_eq!(
            validate_device_telemetry_body(zero.as_bytes(), 1_000),
            Err(DeviceTelemetryIntakeError::InvalidGenerationOrSequence)
        );
    }

    #[test]
    fn rejects_oversized_resources_and_bad_device_ids() {
        let huge = String::from_utf8(body(1_000)).unwrap().replace(
            "\"cpu_available_millis\":1200",
            "\"cpu_available_millis\":70000000",
        );
        assert_eq!(
            validate_device_telemetry_body(huge.as_bytes(), 1_000),
            Err(DeviceTelemetryIntakeError::InvalidResourceMeasurement)
        );
        let bad_id = String::from_utf8(body(1_000))
            .unwrap()
            .replace("device-1", "../other");
        assert_eq!(
            validate_device_telemetry_body(bad_id.as_bytes(), 1_000),
            Err(DeviceTelemetryIntakeError::InvalidDeviceId)
        );
    }
}
