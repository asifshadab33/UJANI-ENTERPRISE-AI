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
    StaleInventory,
    StaleEvidence,
    FutureEvidence,
    InvalidEvidenceTimestamp,
}

/// Default freshness window for resource-planning observations. Callers may use
/// a stricter policy, but must never silently widen this value at a trust boundary.
pub const MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS: u64 = 15 * 60 * 1000;
const MODEL_INVENTORY_CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

fn validate_nested_observation_timestamps(
    value: &Value,
    generated_at_unix_ms: u64,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<(), InventoryV2PreflightError> {
    match value {
        Value::Object(object) => {
            if let Some(observed) = object.get("observed_at_unix_ms") {
                if !observed.is_null() {
                    let timestamp = observed
                        .as_u64()
                        .filter(|timestamp| *timestamp > 0 && *timestamp <= MAX_SAFE_JSON_INTEGER)
                        .ok_or(InventoryV2PreflightError::InvalidEvidenceTimestamp)?;
                    if timestamp
                        > now_unix_ms.saturating_add(MODEL_INVENTORY_CLOCK_SKEW_TOLERANCE_MS)
                        || timestamp
                            > generated_at_unix_ms
                                .saturating_add(MODEL_INVENTORY_CLOCK_SKEW_TOLERANCE_MS)
                    {
                        return Err(InventoryV2PreflightError::FutureEvidence);
                    }
                    if now_unix_ms.saturating_sub(timestamp) > max_age_ms {
                        return Err(InventoryV2PreflightError::StaleEvidence);
                    }
                }
            }
            for child in object.values() {
                validate_nested_observation_timestamps(
                    child,
                    generated_at_unix_ms,
                    now_unix_ms,
                    max_age_ms,
                )?;
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_nested_observation_timestamps(child, generated_at_unix_ms, now_unix_ms, max_age_ms)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Time-aware Enterprise admission preflight. Schema validation and atomic replay,
/// consent-generation, key-generation and persistence checks remain service duties.
pub fn validate_enterprise_inventory_v2_preflight_at(
    payload: &Value,
    authenticated_device_id: &str,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<(), InventoryV2PreflightError> {
    validate_enterprise_inventory_v2_preflight(payload, authenticated_device_id)?;
    let generated_at = payload
        .get("generated_at_unix_ms")
        .and_then(Value::as_u64)
        .ok_or(InventoryV2PreflightError::InvalidTimestamp)?;
    if generated_at > now_unix_ms.saturating_add(MODEL_INVENTORY_CLOCK_SKEW_TOLERANCE_MS) {
        return Err(InventoryV2PreflightError::InvalidTimestamp);
    }
    if now_unix_ms.saturating_sub(generated_at) > max_age_ms {
        return Err(InventoryV2PreflightError::StaleInventory);
    }
    validate_nested_observation_timestamps(payload, generated_at, now_unix_ms, max_age_ms)
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
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
    // Match the shared JSON Schema's interoperable integer ceiling.
    // Full freshness/future-skew validation remains a separate service check.
    if payload
        .get("generated_at_unix_ms")
        .and_then(Value::as_u64)
        .filter(|timestamp| *timestamp > 0 && *timestamp <= 9_007_199_254_740_991)
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
    fn rejects_timestamps_above_the_shared_schema_safe_integer_limit() {
        let mut payload = valid_payload();
        payload["generated_at_unix_ms"] = json!(9_007_199_254_740_992u64);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device-1"),
            Err(InventoryV2PreflightError::InvalidTimestamp)
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

#[cfg(test)]
mod inventory_v2_preflight_boundary_regression_tests {
    use super::*;
    use serde_json::{json, Value};

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
    fn rejects_invalid_authenticated_device_and_policy_identifiers() {
        let mut payload = valid_payload();
        payload["device_ref"] = json!("device/1");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&payload, "device/1"),
            Err(InventoryV2PreflightError::InvalidDeviceBinding)
        );
        let mut invalid_policy = valid_payload();
        invalid_policy["collection_context"]["policy_version"] = json!("policy/v2");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&invalid_policy, "device-1"),
            Err(InventoryV2PreflightError::InvalidPolicyVersion)
        );
    }

    #[test]
    fn rejects_runtime_and_model_collections_over_their_independent_limits() {
        let mut too_many_runtimes = valid_payload();
        too_many_runtimes["runtimes"] = Value::Array(vec![json!({}); 17]);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&too_many_runtimes, "device-1"),
            Err(InventoryV2PreflightError::InvalidInventoryCollections)
        );

        let mut too_many_models = valid_payload();
        too_many_models["models"] = Value::Array(vec![json!({}); 513]);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&too_many_models, "device-1"),
            Err(InventoryV2PreflightError::InvalidInventoryCollections)
        );
    }

    #[test]
    fn rejects_unknown_nested_authority_fields_and_incomplete_privacy_flags() {
        let mut extra_context = valid_payload();
        extra_context["collection_context"]["admin_override"] = json!(true);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&extra_context, "device-1"),
            Err(InventoryV2PreflightError::InvalidCollectionContext)
        );

        let mut incomplete_privacy = valid_payload();
        incomplete_privacy["privacy"]
            .as_object_mut()
            .unwrap()
            .remove("contains_credentials");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&incomplete_privacy, "device-1"),
            Err(InventoryV2PreflightError::InvalidPrivacyDeclaration)
        );
    }
}

#[cfg(test)]
mod inventory_v2_consent_timestamp_regression_tests {
    use super::*;
    use serde_json::json;

    fn payload() -> Value {
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
    fn accepts_payload_at_the_safe_integer_timestamp_ceiling() {
        let mut value = payload();
        value["generated_at_unix_ms"] = json!(9_007_199_254_740_991u64);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&value, "device-1"),
            Ok(())
        );
    }

    #[test]
    fn rejects_zero_timestamp_and_non_boolean_privacy_flags() {
        let mut zero = payload();
        zero["generated_at_unix_ms"] = json!(0);
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&zero, "device-1"),
            Err(InventoryV2PreflightError::InvalidTimestamp)
        );

        let mut invalid_privacy = payload();
        invalid_privacy["privacy"]["contains_prompts"] = json!("false");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&invalid_privacy, "device-1"),
            Err(InventoryV2PreflightError::InvalidPrivacyDeclaration)
        );
    }

    #[test]
    fn rejects_missing_or_non_granted_organisation_consent_context() {
        let mut owner = payload();
        owner["collection_context"]["owner_consent"] = json!("revoked");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&owner, "device-1"),
            Err(InventoryV2PreflightError::ConsentNotGranted)
        );

        let mut organisation = payload();
        organisation["collection_context"]["organisation_authorisation"] = json!("pending");
        assert_eq!(
            validate_enterprise_inventory_v2_preflight(&organisation, "device-1"),
            Err(InventoryV2PreflightError::OrganisationNotAuthorised)
        );
    }
}


#[cfg(test)]
mod inventory_v2_observation_freshness_tests {
    use super::*;
    use serde_json::json;

    fn payload(now: u64) -> Value {
        json!({
            "schema_version": 2,
            "generated_at_unix_ms": now,
            "device_ref": "device-1",
            "collection_context": {
                "scope": "organisation_enrolled",
                "owner_consent": "granted",
                "organisation_authorisation": "authorised",
                "policy_version": "policy-v2"
            },
            "platform": {"evidence": {
                "source": "os_api", "confidence": "verified",
                "observed_at_unix_ms": now
            }},
            "hardware": {}, "runtimes": [], "models": [],
            "privacy": {
                "contains_prompts": false, "contains_user_files": false,
                "contains_local_paths": false, "contains_credentials": false
            }
        })
    }

    #[test]
    fn accepts_fresh_nested_observation_and_unknown_null_observation() {
        let now = 1_800_000_000_000u64;
        let mut value = payload(now);
        value["hardware"]["evidence"] = json!({
            "source": "os_api", "confidence": "unknown", "observed_at_unix_ms": null
        });
        assert_eq!(validate_enterprise_inventory_v2_preflight_at(
            &value, "device-1", now, MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS
        ), Ok(()));
    }

    #[test]
    fn rejects_stale_nested_capability_or_hardware_evidence() {
        let now = 1_800_000_000_000u64;
        let mut value = payload(now);
        value["models"] = json!([{"capabilities":[{"evidence":{
            "source":"runtime_metadata", "confidence":"reported",
            "observed_at_unix_ms": now - MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS - 1
        }}]}]);
        assert_eq!(validate_enterprise_inventory_v2_preflight_at(
            &value, "device-1", now, MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS
        ), Err(InventoryV2PreflightError::StaleEvidence));
    }

    #[test]
    fn rejects_future_nested_evidence_even_when_snapshot_timestamp_is_current() {
        let now = 1_800_000_000_000u64;
        let mut value = payload(now);
        value["runtimes"] = json!([{"evidence":{
            "source":"runtime_api", "confidence":"verified",
            "observed_at_unix_ms": now + MODEL_INVENTORY_CLOCK_SKEW_TOLERANCE_MS + 1
        }}]);
        assert_eq!(validate_enterprise_inventory_v2_preflight_at(
            &value, "device-1", now, MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS
        ), Err(InventoryV2PreflightError::FutureEvidence));
    }

    #[test]
    fn rejects_stale_snapshot_before_any_model_is_considered() {
        let now = 1_800_000_000_000u64;
        let value = payload(now - MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS - 1);
        assert_eq!(validate_enterprise_inventory_v2_preflight_at(
            &value, "device-1", now, MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS
        ), Err(InventoryV2PreflightError::StaleInventory));
    }

    #[test]
    fn rejects_invalid_nested_observation_timestamp_types_and_zero() {
        let now = 1_800_000_000_000u64;
        for timestamp in [json!(0), json!("yesterday"), json!(9_007_199_254_740_992u64)] {
            let mut value = payload(now);
            value["platform"]["evidence"]["observed_at_unix_ms"] = timestamp;
            assert_eq!(validate_enterprise_inventory_v2_preflight_at(
                &value, "device-1", now, MAX_MODEL_INVENTORY_OBSERVATION_AGE_MS
            ), Err(InventoryV2PreflightError::InvalidEvidenceTimestamp));
        }
    }
}
