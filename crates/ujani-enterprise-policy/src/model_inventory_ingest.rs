//! Authenticated, privacy-minimised model/runtime inventory intake.
//!
//! This boundary validates the shared v1 inventory contract, binds it to the
//! enrolled device signature and current owner opt-in, and returns the
//! authenticated principal for a tenant-scoped persistence transaction.
//! It does not consume replay state or persist data: the host must atomically
//! claim the request ID, recheck key/trust/dual-consent state, increment the
//! server-side inventory revision and store the snapshot. No model is installed,
//! selected, downloaded, started or dispatched by this module.

use crate::device_trust::durable::{DurableDeviceRegistry, DurableDeviceTrustError};
use crate::device_trust::{
    AuthenticatedDeviceRequest, SignedDeviceRequest, MAX_DEVICE_REQUEST_BODY_BYTES,
};
use crate::model_inventory::{
    validate_model_runtime_inventory, ModelInventoryValidationError, ModelRuntimeInventory,
};
use crate::operator_http_contract::{
    resolve_route, HttpMethod, OperatorHttpRoute, RoutePrincipal,
    MAX_DEVICE_MODEL_RUNTIME_INVENTORY_BODY_BYTES,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_METHOD: &str = "POST";
pub const DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_RESOURCE: &str =
    "device-model-runtime-inventory:ingest";
/// Fixed operation binding, not a user workload or permission to execute a model.
pub const DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_WORKLOAD: &str =
    "device-model-runtime-inventory";
pub const MAX_DEVICE_MODEL_RUNTIME_INVENTORY_AGE_MS: u64 = 15 * 60 * 1000;
const INVENTORY_BINDING_DOMAIN: &[u8] =
    b"UJANI-ENTERPRISE-DEVICE-MODEL-RUNTIME-INVENTORY-REQUEST-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceModelRuntimeInventoryIntakeError {
    InvalidRoute,
    BodyTooLarge,
    InvalidJson,
    InvalidSchemaShape,
    InvalidInventory(ModelInventoryValidationError),
    RequestBindingMismatch,
    DeviceAuthenticationFailed,
    OwnerConsentMissing,
    TrustStoreUnavailable,
}

impl DeviceModelRuntimeInventoryIntakeError {
    /// Generic HTTP status mapping; never disclose tenant, key or trust-store details.
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRoute => 404,
            Self::DeviceAuthenticationFailed | Self::RequestBindingMismatch => 401,
            Self::OwnerConsentMissing => 403,
            Self::TrustStoreUnavailable => 503,
            Self::BodyTooLarge => 413,
            Self::InvalidJson | Self::InvalidSchemaShape | Self::InvalidInventory(_) => 400,
        }
    }
}

fn required_fields(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| fields.iter().all(|field| object.contains_key(*field)))
}

fn evidence_has_required_fields(value: &Value) -> bool {
    required_fields(
        value,
        &["source", "confidence", "observed_at_unix_ms"],
    )
}

/// Serde's Option fields intentionally accept omission. The JSON Schema requires
/// several nullable properties to be present, so enforce those requirements here
/// before converting into the typed representation.
fn schema_required_fields_present(value: &Value) -> bool {
    if !required_fields(
        value,
        &[
            "schema_version",
            "generated_at_unix_ms",
            "platform",
            "hardware",
            "runtimes",
            "models",
        ],
    ) {
        return false;
    }

    let Some(platform) = value.get("platform") else {
        return false;
    };
    if !required_fields(platform, &["os", "architecture"]) {
        return false;
    }

    let Some(hardware) = value.get("hardware") else {
        return false;
    };
    if !required_fields(
        hardware,
        &[
            "cpu_logical_cores",
            "memory_total_mb",
            "memory_available_mb",
            "accelerators",
        ],
    ) {
        return false;
    }
    let Some(accelerators) = hardware.get("accelerators").and_then(Value::as_array) else {
        return false;
    };
    if accelerators.iter().any(|accelerator| {
        !required_fields(accelerator, &["kind", "vendor", "evidence"])
            || accelerator
                .get("evidence")
                .is_none_or(|evidence| !evidence_has_required_fields(evidence))
    }) {
        return false;
    }

    let Some(runtimes) = value.get("runtimes").and_then(Value::as_array) else {
        return false;
    };
    if runtimes.iter().any(|runtime| {
        !required_fields(
            runtime,
            &[
                "runtime_id",
                "provider",
                "version",
                "availability",
                "network_scope",
                "evidence",
            ],
        ) || runtime
            .get("evidence")
            .is_none_or(|evidence| !evidence_has_required_fields(evidence))
    }) {
        return false;
    }

    let Some(models) = value.get("models").and_then(Value::as_array) else {
        return false;
    };
    if models.iter().any(|model| {
        !required_fields(
            model,
            &[
                "model_ref",
                "runtime_id",
                "display_name",
                "availability",
                "size_bytes",
                "capabilities",
                "evidence",
            ],
        ) || model
            .get("evidence")
            .is_none_or(|evidence| !evidence_has_required_fields(evidence))
    }) {
        return false;
    }

    if let Some(privacy) = value.get("privacy") {
        let Some(privacy_fields) = privacy.as_object() else {
            return false;
        };
        if privacy_fields.iter().any(|(name, declaration)| {
            !matches!(
                name.as_str(),
                "contains_prompts"
                    | "contains_user_files"
                    | "contains_local_paths"
                    | "contains_credentials"
            ) || declaration != &Value::Bool(false)
        }) {
            return false;
        }
    }

    true
}

/// Stable digest binding a device signature to this exact inventory operation.
pub fn device_model_runtime_inventory_request_manifest_digest() -> [u8; 32] {
    Sha256::digest(INVENTORY_BINDING_DOMAIN).into()
}

/// Parse the shared v1 contract and validate freshness, bounds and privacy.
pub fn validate_device_model_runtime_inventory_body(
    raw_body: &[u8],
    authenticated_device_id: &str,
    now_unix_ms: u64,
) -> Result<ModelRuntimeInventory, DeviceModelRuntimeInventoryIntakeError> {
    if raw_body.is_empty()
        || raw_body.len() > MAX_DEVICE_MODEL_RUNTIME_INVENTORY_BODY_BYTES
        || raw_body.len() > MAX_DEVICE_REQUEST_BODY_BYTES
    {
        return Err(DeviceModelRuntimeInventoryIntakeError::BodyTooLarge);
    }

    let value: Value = serde_json::from_slice(raw_body)
        .map_err(|_| DeviceModelRuntimeInventoryIntakeError::InvalidJson)?;
    if !schema_required_fields_present(&value) {
        return Err(DeviceModelRuntimeInventoryIntakeError::InvalidSchemaShape);
    }

    let inventory: ModelRuntimeInventory = serde_json::from_value(value)
        .map_err(|_| DeviceModelRuntimeInventoryIntakeError::InvalidSchemaShape)?;
    if inventory
        .device_ref
        .as_deref()
        .is_some_and(|device_ref| device_ref != authenticated_device_id)
    {
        return Err(DeviceModelRuntimeInventoryIntakeError::RequestBindingMismatch);
    }
    validate_model_runtime_inventory(
        &inventory,
        now_unix_ms,
        MAX_DEVICE_MODEL_RUNTIME_INVENTORY_AGE_MS,
    )
    .map_err(DeviceModelRuntimeInventoryIntakeError::InvalidInventory)?;

    Ok(inventory)
}

/// Authenticate a model/runtime inventory report without consuming its replay ID.
///
/// The route supplies the device identifier and fixed operation scope. Tenant
/// identity is derived only from the enrolled device key. Owner opt-in is
/// re-read from the exact current key generation. The persistence adapter must
/// repeat the trust, active-key, owner-binding, administrator-approval and
/// owner-consent checks under the same database transaction that claims
/// request_id and writes the latest inventory revision.
pub fn authenticate_device_model_runtime_inventory_request(
    registry: &DurableDeviceRegistry,
    method: HttpMethod,
    path: &str,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    now_unix_ms: u64,
) -> Result<
    (AuthenticatedDeviceRequest, ModelRuntimeInventory),
    DeviceModelRuntimeInventoryIntakeError,
> {
    let route = resolve_route(method, path)
        .ok_or(DeviceModelRuntimeInventoryIntakeError::InvalidRoute)?;
    if route.route != OperatorHttpRoute::DeviceModelRuntimeInventory
        || route.principal != RoutePrincipal::EnrolledDeviceSignature
    {
        return Err(DeviceModelRuntimeInventoryIntakeError::InvalidRoute);
    }
    if raw_body.len() > route.max_body_bytes
        || !route.permits_body_size(raw_body.len())
        || raw_body.len() > MAX_DEVICE_MODEL_RUNTIME_INVENTORY_BODY_BYTES
    {
        return Err(DeviceModelRuntimeInventoryIntakeError::BodyTooLarge);
    }

    let path_device_id = path.split('/').nth(3).unwrap_or_default();
    let inventory =
        validate_device_model_runtime_inventory_body(raw_body, path_device_id, now_unix_ms)?;
    if signed_request.claims.device_id != path_device_id
        || signed_request.claims.method != DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_METHOD
        || signed_request.claims.resource_id != DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_RESOURCE
        || signed_request.claims.workload_id != DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_WORKLOAD
        || signed_request.claims.manifest_sha256
            != device_model_runtime_inventory_request_manifest_digest()
    {
        return Err(DeviceModelRuntimeInventoryIntakeError::RequestBindingMismatch);
    }

    let authenticated = registry
        .verify_request_for(
            signed_request,
            DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_METHOD,
            DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_RESOURCE,
            raw_body,
            now_unix_ms,
        )
        .map_err(map_device_model_runtime_inventory_trust_error)?;

    if authenticated.device_id() != path_device_id {
        return Err(DeviceModelRuntimeInventoryIntakeError::RequestBindingMismatch);
    }
    let owner_opted_in = registry
        .authenticated_device_status_for_request(&authenticated)
        .map(|(_, opted_in)| opted_in)
        .map_err(map_device_model_runtime_inventory_trust_error)?;
    if !owner_opted_in {
        return Err(DeviceModelRuntimeInventoryIntakeError::OwnerConsentMissing);
    }

    Ok((authenticated, inventory))
}

/// Convert trust-store errors to generic outcomes without disclosing whether a
/// device, tenant, key, replay record or protected provider exists.
pub fn map_device_model_runtime_inventory_trust_error(
    error: DurableDeviceTrustError,
) -> DeviceModelRuntimeInventoryIntakeError {
    match error {
        DurableDeviceTrustError::Trust(_) => {
            DeviceModelRuntimeInventoryIntakeError::DeviceAuthenticationFailed
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
            DeviceModelRuntimeInventoryIntakeError::TrustStoreUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_trust::durable::DeviceTrustIntegrityKey;
    use crate::device_trust::{
        admin_command_bytes, canonical_device_request_bytes, enrollment_proof_bytes,
        owner_consent_bytes, DeviceCommandAction, DeviceRequestClaims, SignedDeviceAdminCommand,
        SignedOwnerConsentCommand,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn body(generated_at: u64) -> Vec<u8> {
        format!(
            r#"{{"schema_version":1,"generated_at_unix_ms":{generated_at},"device_ref":"device-1","platform":{{"os":"linux","architecture":"x86_64"}},"hardware":{{"cpu_logical_cores":8,"memory_total_mb":16384,"memory_available_mb":8192,"accelerators":[]}},"runtimes":[{{"runtime_id":"ollama-local","provider":"ollama","version":"0.5.0","availability":"available","network_scope":"loopback_only","evidence":{{"source":"runtime_api","confidence":"reported","observed_at_unix_ms":{generated_at}}}}}}],"models":[{{"model_ref":"qwen2.5:3b","runtime_id":"ollama-local","display_name":"Qwen 2.5 3B","availability":"installed","size_bytes":1500000000,"capabilities":["chat","coding"],"evidence":{{"source":"runtime_metadata","confidence":"reported","observed_at_unix_ms":{generated_at}}}}}}],"privacy":{{"contains_prompts":false,"contains_user_files":false,"contains_local_paths":false,"contains_credentials":false}}}}"#
        )
        .into_bytes()
    }

    fn nonce(label: &[u8], unique_id: u64) -> [u8; 16] {
        let mut digest = Sha256::new();
        digest.update(label);
        digest.update(std::process::id().to_be_bytes());
        digest.update(unique_id.to_be_bytes());
        digest.finalize()[..16]
            .try_into()
            .expect("SHA-256 prefix is 16 bytes")
    }

    fn signed_registry(
        owner_opted_in: bool,
    ) -> (DurableDeviceRegistry, SigningKey, PathBuf, u64) {
        let unique_id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let admin = SigningKey::from_bytes(&[31; 32]);
        let device = SigningKey::from_bytes(&[41; 32]);
        let directory = std::env::temp_dir().join(format!(
            "ujani-model-inventory-ingest-{}-{unique_id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("registry.db");
        let registry = DurableDeviceRegistry::open(
            &path,
            vec![("admin-v1".into(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new(
                "integrity-v1",
                Sha256::digest(b"model-inventory-ingest-test-integrity-key").into(),
            ),
        )
        .unwrap();

        let mut enrollment = SignedDeviceAdminCommand {
            action: DeviceCommandAction::Enroll,
            tenant_id: "tenant-a".into(),
            device_id: "device-1".into(),
            admin_key_id: "admin-v1".into(),
            target_key_id: "device-key-v1".into(),
            target_public_key: Some(device.verifying_key().to_bytes()),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1_000,
            nonce: nonce(b"admin-enrollment", unique_id),
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        enrollment.new_device_signature =
            Some(device.sign(&enrollment_proof_bytes(&enrollment)).to_bytes());
        enrollment.signature = admin.sign(&admin_command_bytes(&enrollment)).to_bytes();
        registry.apply_admin_command(&enrollment, 200).unwrap();

        if owner_opted_in {
            let mut consent = SignedOwnerConsentCommand {
                tenant_id: "tenant-a".into(),
                device_id: "device-1".into(),
                key_id: "device-key-v1".into(),
                key_generation: 1,
                revision: 1,
                opted_in: true,
                issued_at_unix_ms: 210,
                expires_at_unix_ms: 1_000,
                nonce: nonce(b"owner-consent", unique_id),
                signature: [0; 64],
            };
            consent.signature = device.sign(&owner_consent_bytes(&consent)).to_bytes();
            registry.apply_owner_consent(&consent, 220).unwrap();
        }

        (registry, device, directory, unique_id)
    }

    fn signed_inventory_request(
        device: &SigningKey,
        raw_body: &[u8],
        request_device_id: &str,
        unique_id: u64,
    ) -> SignedDeviceRequest {
        let claims = DeviceRequestClaims {
            tenant_id: "tenant-a".into(),
            device_id: request_device_id.into(),
            key_id: "device-key-v1".into(),
            key_generation: 1,
            request_id: nonce(b"model-inventory-request", unique_id),
            issued_at_unix_ms: 230,
            expires_at_unix_ms: 1_000,
            method: DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_METHOD.into(),
            resource_id: DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_RESOURCE.into(),
            workload_id: DEVICE_MODEL_RUNTIME_INVENTORY_REQUEST_WORKLOAD.into(),
            manifest_sha256: device_model_runtime_inventory_request_manifest_digest(),
            body_sha256: Sha256::digest(raw_body).into(),
        };
        SignedDeviceRequest {
            signature: device.sign(&canonical_device_request_bytes(&claims)).to_bytes(),
            claims,
        }
    }

    #[test]
    fn accepts_only_schema_valid_fresh_privacy_minimised_inventory() {
        let raw = body(250);
        let inventory =
            validate_device_model_runtime_inventory_body(&raw, "device-1", 250).unwrap();
        assert_eq!(inventory.schema_version, 1);
        assert_eq!(inventory.runtimes.len(), 1);
        assert_eq!(inventory.models.len(), 1);
        assert_eq!(
            validate_device_model_runtime_inventory_body(&raw, "device-2", 250),
            Err(DeviceModelRuntimeInventoryIntakeError::RequestBindingMismatch)
        );
    }

    #[test]
    fn rejects_unknown_fields_and_missing_nullable_schema_required_fields() {
        let raw = body(250);
        let with_prompt = String::from_utf8(raw.clone())
            .unwrap()
            .replace(r#""privacy":{"#, r#""prompt":"private text","privacy":{"#);
        assert_eq!(
            validate_device_model_runtime_inventory_body(
                with_prompt.as_bytes(),
                "device-1",
                250
            ),
            Err(DeviceModelRuntimeInventoryIntakeError::InvalidSchemaShape)
        );

        let missing_required_nullable = String::from_utf8(raw)
            .unwrap()
            .replace(r#","memory_available_mb":8192"#, "");
        assert_eq!(
            validate_device_model_runtime_inventory_body(
                missing_required_nullable.as_bytes(),
                "device-1",
                250
            ),
            Err(DeviceModelRuntimeInventoryIntakeError::InvalidSchemaShape)
        );
    }

    #[test]
    fn rejects_stale_future_private_and_oversized_inventory() {
        let stale = body(1_000_000);
        assert!(matches!(
            validate_device_model_runtime_inventory_body(&stale, "device-1", 2_000_000),
            Err(DeviceModelRuntimeInventoryIntakeError::InvalidInventory(
                ModelInventoryValidationError::StaleInventory
            ))
        ));

        let future = body(2_100_000);
        assert!(matches!(
            validate_device_model_runtime_inventory_body(&future, "device-1", 2_000_000),
            Err(DeviceModelRuntimeInventoryIntakeError::InvalidInventory(
                ModelInventoryValidationError::FutureTimestamp
            ))
        ));

        let private = String::from_utf8(body(250))
            .unwrap()
            .replace(r#""contains_prompts":false"#, r#""contains_prompts":true"#);
        assert!(matches!(
            validate_device_model_runtime_inventory_body(
                private.as_bytes(),
                "device-1",
                250
            ),
            Err(DeviceModelRuntimeInventoryIntakeError::InvalidSchemaShape)
        ));

        let oversized = vec![b' '; MAX_DEVICE_MODEL_RUNTIME_INVENTORY_BODY_BYTES + 1];
        assert_eq!(
            validate_device_model_runtime_inventory_body(&oversized, "device-1", 250),
            Err(DeviceModelRuntimeInventoryIntakeError::BodyTooLarge)
        );
    }

    #[test]
    fn authenticated_intake_requires_device_signature_and_current_owner_opt_in() {
        let (registry, device, directory, unique_id) = signed_registry(true);
        let raw = body(250);
        let signed = signed_inventory_request(&device, &raw, "device-1", unique_id);
        let path = "/v1/devices/device-1/model-runtime-inventory";
        let first = authenticate_device_model_runtime_inventory_request(
            &registry,
            HttpMethod::Post,
            path,
            &signed,
            &raw,
            250,
        );
        assert!(first.is_ok());
        let second = authenticate_device_model_runtime_inventory_request(
            &registry,
            HttpMethod::Post,
            path,
            &signed,
            &raw,
            250,
        );
        assert!(
            second.is_ok(),
            "the SQL persistence transaction owns the replay claim"
        );
        drop(registry);
        let _ = std::fs::remove_dir_all(directory);

        let (registry, device, directory, unique_id) = signed_registry(false);
        let raw = body(250);
        let signed = signed_inventory_request(&device, &raw, "device-1", unique_id);
        assert_eq!(
            authenticate_device_model_runtime_inventory_request(
                &registry,
                HttpMethod::Post,
                path,
                &signed,
                &raw,
                250
            ),
            Err(DeviceModelRuntimeInventoryIntakeError::OwnerConsentMissing)
        );
        drop(registry);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn authenticated_intake_rejects_route_and_request_binding_mismatches() {
        let (registry, device, directory, unique_id) = signed_registry(true);
        let raw = body(250);
        let signed = signed_inventory_request(&device, &raw, "device-2", unique_id);
        assert_eq!(
            authenticate_device_model_runtime_inventory_request(
                &registry,
                HttpMethod::Post,
                "/v1/devices/device-1/model-runtime-inventory",
                &signed,
                &raw,
                250
            ),
            Err(DeviceModelRuntimeInventoryIntakeError::RequestBindingMismatch)
        );
        assert_eq!(
            authenticate_device_model_runtime_inventory_request(
                &registry,
                HttpMethod::Get,
                "/v1/devices/device-1/model-runtime-inventory",
                &signed,
                &raw,
                250
            ),
            Err(DeviceModelRuntimeInventoryIntakeError::InvalidRoute)
        );
        drop(registry);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn trust_store_failures_are_service_unavailable_not_bad_credentials() {
        assert_eq!(
            map_device_model_runtime_inventory_trust_error(DurableDeviceTrustError::Io(
                "disk unavailable".into()
            )),
            DeviceModelRuntimeInventoryIntakeError::TrustStoreUnavailable
        );
        assert_eq!(
            DeviceModelRuntimeInventoryIntakeError::TrustStoreUnavailable.http_status(),
            503
        );
        assert_eq!(
            DeviceModelRuntimeInventoryIntakeError::OwnerConsentMissing.http_status(),
            403
        );
    }
}
