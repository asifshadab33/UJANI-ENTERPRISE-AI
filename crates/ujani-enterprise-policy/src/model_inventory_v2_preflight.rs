//! Fail-closed preflight for Enterprise model/runtime inventory v2.
//!
//! This is deliberately a narrow admission guard, not a replacement for the
//! shared JSON Schema validator or the authenticated persistence transaction.
//! The hosting service must authenticate the enrolled device first, validate
//! the complete payload against schemas/model-runtime-inventory-v2.schema.json,
//! then re-check key generation, owner-consent generation, administrator
//! authorisation and replay state in the same tenant-scoped transaction that
//! stores the inventory. This module never grants workload or execution rights.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryV2PreflightError {
    InvalidDeviceBinding,
    InvalidTopLevelShape,
    UnsupportedSchemaVersion,
    InvalidTimestamp,
    InvalidCollectionContext,
    ConsentNotGranted,
    OrganisationNotAuthorised,
    InvalidPolicyVersion,
    InvalidPrivacyDeclaration,
    InvalidInventoryCollections,
}

fn has_exact_keys(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

/// Check the Enterprise-only v2 trust and privacy envelope after device
/// authentication. Full nested schema validation remains mandatory separately.
pub fn validate_enterprise_inventory_v2_preflight(
    payload: &Value,
    authenticated_device_id: &str,
) -> Result<(), InventoryV2PreflightError> {
    if !valid_identifier(authenticated_device_id) {
        return Err(InventoryV2PreflightError::InvalidDeviceBinding);
    }

    if !has_exact_keys(
        payload,
        &[
            "schema_version",
            "generated_at_unix_ms",
            "device_ref",
            "collection_context",
            "platform",
            "hardware",
            "runtimes",
            "models",
            "privacy",
        ],
    ) {
        return Err(InventoryV2PreflightError::InvalidTopLevelShape);
    }

    if payload.get("schema_version").and_then(Value::as_u64) != Some(2) {
        return Err(InventoryV2PreflightError::UnsupportedSchemaVersion);
    }
    if payload
        .get("generated_at_unix_ms")
        .and_then(Value::as_u64)
        .filter(|timestamp| *timestamp > 0)
        .is_none()
    {
        return Err(InventoryV2PreflightError::InvalidTimestamp);
    }
    if payload.get("device_ref").and_then(Value::as_str) != Some(authenticated_device_id) {
        return Err(InventoryV2PreflightError::InvalidDeviceBinding);
    }

    let context = payload
        .get("collection_context")
        .ok_or(InventoryV2PreflightError::InvalidCollectionContext)?;
    if !has_exact_keys(
        context,
        &[
            "scope",
            "owner_consent",
            "organisation_authorisation",
            "policy_version",
        ],
    ) || context.get("scope").and_then(Value::as_str) != Some("organisation_enrolled")
    {
        return Err(InventoryV2PreflightError::InvalidCollectionContext);
    }
    if context.get("owner_consent").and_then(Value::as_str) != Some("granted") {
        return Err(InventoryV2PreflightError::ConsentNotGranted);
    }
    if context
        .get("organisation_authorisation")
        .and_then(Value::as_str)
        != Some("authorised")
    {
        return Err(InventoryV2PreflightError::OrganisationNotAuthorised);
    }
    if !context
        .get("policy_version")
        .and_then(Value::as_str)
        .is_some_and(valid_identifier)
    {
        return Err(InventoryV2PreflightError::InvalidPolicyVersion);
    }

    let privacy = payload
        .get("privacy")
        .ok_or(InventoryV2PreflightError::InvalidPrivacyDeclaration)?;
    if !has_exact_keys(
        privacy,
        &[
            "contains_prompts",
            "contains_user_files",
            "contains_local_paths",
            "contains_credentials",
        ],
    ) || [
        "contains_prompts",
        "contains_user_files",
        "contains_local_paths",
        "contains_credentials",
    ]
    .iter()
    .any(|key| privacy.get(*key) != Some(&Value::Bool(false)))
    {
        return Err(InventoryV2PreflightError::InvalidPrivacyDeclaration);
    }

    if !payload.get("platform").is_some_and(Value::is_object)
        || !payload.get("hardware").is_some_and(Value::is_object)
        || !payload.get("runtimes").is_some_and(Value::is_array)
        || !payload.get("models").is_some_and(Value::is_array)
        || payload["runtimes"]
            .as_array()
            .is_some_and(|items| items.len() > 16)
        || payload["models"]
            .as_array()
            .is_some_and(|items| items.len() > 512)
    {
        return Err(InventoryV2PreflightError::InvalidInventoryCollections);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_payload() -> Value {
        json!({
            "schema_version": 2,
            "generated_at_unix_ms": 1_800_000_000_000u64,
            "device_ref": "device-1",
            "collection_context": {
                "scope": "organisation_enrolled",
                "owner_consent": "granted",
                "organisation_authorisation": "authorised",
                "policy_version": "policy-v2"
            },
            "platform": {},
            "hardware": {},
            "runtimes": [],
            "models": [],
            "privacy": {
                "contains_prompts": false,
                "contains_user_files": false,
                "contains_local_paths": false,
                "contains_credentials": false
            }
        })
    }

    #[test]
    fn accepts_only_enterprise_scoped_dual_authorised_inventory() {
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&valid_payload(), "device-1"),
            Ok(())
        );
    }

    #[test]
    fn rejects_personal_local_scope_at_enterprise_boundary() {
        let mut payload = valid_payload();
        payload["collection_context"]["scope"] = json!("personal_local_only");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::InvalidCollectionContext)
        );
    }

    #[test]
    fn rejects_missing_or_revoked_owner_consent() {
        let mut payload = valid_payload();
        payload["collection_context"]["owner_consent"] = json!("revoked");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::ConsentNotGranted)
        );
    }

    #[test]
    fn rejects_missing_or_revoked_organisation_authorisation() {
        let mut payload = valid_payload();
        payload["collection_context"]["organisation_authorisation"] = json!("unknown");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::OrganisationNotAuthorised)
        );
    }

    #[test]
    fn rejects_device_spoofing_and_missing_device_reference() {
        let mut payload = valid_payload();
        payload["device_ref"] = json!("device-2");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::InvalidDeviceBinding)
        );
        let mut missing = valid_payload();
        missing.as_object_mut().unwrap().remove("device_ref");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&missing, "device-1"),
            Err(InventoryV2PreflightError::InvalidTopLevelShape)
        );
    }

    #[test]
    fn rejects_any_payload_claiming_user_content_or_paths() {
        let mut payload = valid_payload();
        payload["privacy"]["contains_local_paths"] = json!(true);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::InvalidPrivacyDeclaration)
        );
    }

    #[test]
    fn rejects_unknown_fields_and_wrong_schema_version() {
        let mut unknown = valid_payload();
        unknown["prompt"] = json!("must never be present");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&unknown, "device-1"),
            Err(InventoryV2PreflightError::InvalidTopLevelShape)
        );
        let mut version = valid_payload();
        version["schema_version"] = json!(1);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&version, "device-1"),
            Err(InventoryV2PreflightError::UnsupportedSchemaVersion)
        );
    }

    #[test]
    fn rejects_oversized_inventory_collections() {
        let mut payload = valid_payload();
        payload["runtimes"] = json!(vec![json!({}); 17]);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::InvalidInventoryCollections)
        );
    }
}
