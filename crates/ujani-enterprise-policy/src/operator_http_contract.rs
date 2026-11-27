//! Fail-closed HTTP route contract for the future Enterprise hosting adapter.
//!
//! This module is deliberately transport-neutral: it does not open a socket,
//! terminate TLS, validate OIDC tokens, persist leases, or execute workloads.
//! The HTTP adapter MUST resolve routes through this contract before dispatch,
//! enforce the declared body limit, authenticate the declared principal, and
//! fail closed for every unknown method/path. The host adapter must authenticate
//! `DeviceOwnerConsent` with the enrolled device signature and dispatch the verified
//! command to `DurableDeviceRegistry::apply_owner_consent`. No remote-execution route exists.
use super::operator_control_plane::{
    OperatorModelTaskMatchRequest, OperatorRole, OperatorServiceError,
};

pub const MAX_OPERATOR_ACTION_BODY_BYTES: usize = 16 * 1024;
pub const MAX_DEVICE_ENROLLMENT_BODY_BYTES: usize = 64 * 1024;
pub const MAX_DEVICE_INGEST_BODY_BYTES: usize = 1024 * 1024;
/// Model inventory contains bounded metadata only; keep the same 1 MiB transport ceiling.
pub const MAX_MODEL_INVENTORY_BODY_BYTES: usize = MAX_DEVICE_INGEST_BODY_BYTES;
pub const MAX_OWNER_CONSENT_BODY_BYTES: usize = 16 * 1024;
/// A task-match request contains only bounded task requirements and identifiers.
pub const MAX_MODEL_TASK_MATCH_BODY_BYTES: usize = 8 * 1024;

/// Errors returned before an HTTP adapter authenticates and dispatches a task-match request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTaskMatchBodyError {
    EmptyBody,
    BodyTooLarge,
    InvalidJson,
    InvalidRequest,
}

/// Decode a bounded task-match request before tenant-bound service dispatch.
/// The HTTP host should authenticate the route and enforce its body limit before
/// calling this parser; duplicate keys are rejected recursively and unknown fields
/// are rejected by the typed request DTO. The host must enforce role and audit outcome.
pub fn decode_model_task_match_request(
    raw_body: &[u8],
) -> Result<OperatorModelTaskMatchRequest, ModelTaskMatchBodyError> {
    if raw_body.is_empty() {
        return Err(ModelTaskMatchBodyError::EmptyBody);
    }
    if raw_body.len() > MAX_MODEL_TASK_MATCH_BODY_BYTES {
        return Err(ModelTaskMatchBodyError::BodyTooLarge);
    }

    let strict_value = crate::strict_json::parse_strict_json(raw_body)
        .map_err(|_| ModelTaskMatchBodyError::InvalidJson)?;
    serde_json::from_value(strict_value).map_err(|_| ModelTaskMatchBodyError::InvalidRequest)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePrincipal {
    PublicHealth,
    Operator { minimum_role: OperatorRole },
    EnrolledDeviceSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorHttpRoute {
    Health,
    OperatorOverview,
    OperatorModelTaskMatch,
    DeviceEnrollment,
    DeviceTelemetry,
    DeviceModelInventory,
    DeviceOwnerConsent,
    LeaseAcquire,
    LeaseRenew,
    LeaseRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteContract {
    pub route: OperatorHttpRoute,
    pub principal: RoutePrincipal,
    /// Maximum raw request-body size. Zero means the route accepts no body.
    pub max_body_bytes: usize,
}

impl RouteContract {
    pub fn permits_operator_role(&self, role: OperatorRole) -> bool {
        let RoutePrincipal::Operator { minimum_role } = self.principal else {
            return false;
        };
        role_rank(role) >= role_rank(minimum_role)
    }

    pub fn permits_body_size(&self, actual_bytes: usize) -> bool {
        actual_bytes <= self.max_body_bytes
    }
}

fn role_rank(role: OperatorRole) -> u8 {
    match role {
        OperatorRole::Viewer => 1,
        OperatorRole::Operator => 2,
        OperatorRole::Administrator => 3,
    }
}

/// Resolve only the explicitly supported method/path pairs. Dynamic path
/// segments are restricted to simple identifiers; encoded separators,
/// dot-segments and empty identifiers are rejected by returning None.
pub fn resolve_route(method: HttpMethod, path: &str) -> Option<RouteContract> {
    // The adapter must pass the raw origin-form path, not a URL, decoded path,
    // or a path that another proxy/router may normalize differently. Reject
    // ambiguous syntax here so authorization and dispatch see one spelling.
    if path.len() > 2048
        || !path.starts_with('/')
        || path.starts_with("//")
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'?' | b'#' | b'\\' | b'%'))
    {
        return None;
    }
    if path == "/healthz" && method == HttpMethod::Get {
        return Some(RouteContract {
            route: OperatorHttpRoute::Health,
            principal: RoutePrincipal::PublicHealth,
            max_body_bytes: 0,
        });
    }
    if path == "/api/v1/operator/overview" && method == HttpMethod::Get {
        return Some(RouteContract {
            route: OperatorHttpRoute::OperatorOverview,
            principal: RoutePrincipal::Operator {
                minimum_role: OperatorRole::Viewer,
            },
            max_body_bytes: 0,
        });
    }
    if path == "/api/v1/operator/model-task-match" && method == HttpMethod::Post {
        return Some(RouteContract {
            route: OperatorHttpRoute::OperatorModelTaskMatch,
            principal: RoutePrincipal::Operator {
                minimum_role: OperatorRole::Viewer,
            },
            max_body_bytes: MAX_MODEL_TASK_MATCH_BODY_BYTES,
        });
    }
    if path == "/api/v1/devices/enroll" && method == HttpMethod::Post {
        return Some(RouteContract {
            route: OperatorHttpRoute::DeviceEnrollment,
            principal: RoutePrincipal::Operator {
                minimum_role: OperatorRole::Administrator,
            },
            max_body_bytes: MAX_DEVICE_ENROLLMENT_BODY_BYTES,
        });
    }
    if path == "/api/v1/leases/acquire" && method == HttpMethod::Post {
        return Some(RouteContract {
            route: OperatorHttpRoute::LeaseAcquire,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_OPERATOR_ACTION_BODY_BYTES,
        });
    }

    // Bound allocation even if a hostile request target contains many segments.
    let parts: Vec<&str> = path.splitn(7, '/').collect();
    if parts.len() == 6
        && parts[1] == "api"
        && parts[2] == "v1"
        && parts[3] == "devices"
        && valid_path_segment(parts[4])
        && parts[5] == "telemetry"
        && method == HttpMethod::Post
    {
        return Some(RouteContract {
            route: OperatorHttpRoute::DeviceTelemetry,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_DEVICE_INGEST_BODY_BYTES,
        });
    }
    if parts.len() == 6
        && parts[1] == "api"
        && parts[2] == "v1"
        && parts[3] == "devices"
        && valid_path_segment(parts[4])
        && parts[5] == "model-inventory"
        && method == HttpMethod::Post
    {
        return Some(RouteContract {
            route: OperatorHttpRoute::DeviceModelInventory,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_MODEL_INVENTORY_BODY_BYTES,
        });
    }
    if parts.len() == 6
        && parts[1] == "api"
        && parts[2] == "v1"
        && parts[3] == "devices"
        && valid_path_segment(parts[4])
        && parts[5] == "owner-consent"
        && method == HttpMethod::Post
    {
        return Some(RouteContract {
            route: OperatorHttpRoute::DeviceOwnerConsent,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_OWNER_CONSENT_BODY_BYTES,
        });
    }
    if parts.len() == 6
        && parts[1] == "api"
        && parts[2] == "v1"
        && parts[3] == "leases"
        && valid_path_segment(parts[4])
        && method == HttpMethod::Post
    {
        let route = match parts[5] {
            "renew" => OperatorHttpRoute::LeaseRenew,
            "release" => OperatorHttpRoute::LeaseRelease,
            _ => return None,
        };
        return Some(RouteContract {
            route,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_OPERATOR_ACTION_BODY_BYTES,
        });
    }
    None
}

/// Dispatch a parsed owner-consent command only for its device-authenticated route.
///
/// The hosting adapter must enforce `RouteContract::max_body_bytes` against the
/// raw request body before parsing. Signature, expiry, generation, tenant and
/// replay checks are performed by the durable registry.
fn owner_consent_device_id(path: &str) -> Option<&str> {
    let contract = resolve_route(HttpMethod::Post, path)?;
    if contract.route != OperatorHttpRoute::DeviceOwnerConsent
        || contract.principal != RoutePrincipal::EnrolledDeviceSignature
    {
        return None;
    }
    path.split('/')
        .nth(4)
        .filter(|device_id| valid_path_segment(device_id))
}

/// Dispatch a parsed owner-consent command only for its device-authenticated route.
pub fn dispatch_owner_consent_command(
    method: HttpMethod,
    path: &str,
    registry: &super::device_trust::durable::DurableDeviceRegistry,
    command: &super::device_trust::SignedOwnerConsentCommand,
    now_unix_ms: u64,
) -> Result<Option<u64>, super::device_trust::durable::DurableDeviceTrustError> {
    if method != HttpMethod::Post {
        return Ok(None);
    }
    let Some(device_id) = owner_consent_device_id(path) else {
        return Ok(None);
    };
    if device_id != command.device_id {
        return Ok(None);
    }
    registry.apply_owner_consent(command, now_unix_ms).map(Some)
}

fn valid_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

/// Stable HTTP status mapping for the hosting adapter. Response bodies should
/// remain generic and must not expose tenant, key, database or audit details.
pub fn service_error_status(error: OperatorServiceError) -> u16 {
    match error {
        OperatorServiceError::Unauthorized => 401,
        // A repository returning another tenant's data is an internal boundary
        // violation, not an authorization denial attributable to the caller.
        OperatorServiceError::InvalidTenantBoundary => 500,
        OperatorServiceError::RepositoryUnavailable | OperatorServiceError::AuditUnavailable => 503,
        OperatorServiceError::InvalidOverview => 502,
        OperatorServiceError::InvalidModelMatchRequest => 400,
        OperatorServiceError::ModelInventoryUnavailable => 404,
        OperatorServiceError::ModelMatchRejected => 422,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_is_the_only_public_route_and_accepts_no_body() {
        let route = resolve_route(HttpMethod::Get, "/healthz").unwrap();
        assert_eq!(route.route, OperatorHttpRoute::Health);
        assert_eq!(route.principal, RoutePrincipal::PublicHealth);
        assert!(route.permits_body_size(0));
        assert!(!route.permits_body_size(1));
    }

    #[test]
    fn overview_is_read_only_and_available_to_viewers() {
        let route = resolve_route(HttpMethod::Get, "/api/v1/operator/overview").unwrap();
        assert_eq!(route.route, OperatorHttpRoute::OperatorOverview);
        assert!(route.permits_operator_role(OperatorRole::Viewer));
        assert!(route.permits_operator_role(OperatorRole::Administrator));
        assert!(!route.permits_body_size(1));
    }

    #[test]
    fn model_task_match_is_read_only_operator_route_with_bounded_request() {
        let route = resolve_route(HttpMethod::Post, "/api/v1/operator/model-task-match").unwrap();
        assert_eq!(route.route, OperatorHttpRoute::OperatorModelTaskMatch);
        assert!(route.permits_operator_role(OperatorRole::Viewer));
        assert!(route.permits_operator_role(OperatorRole::Administrator));
        assert!(route.permits_body_size(MAX_MODEL_TASK_MATCH_BODY_BYTES));
        assert!(!route.permits_body_size(MAX_MODEL_TASK_MATCH_BODY_BYTES + 1));
        assert!(resolve_route(HttpMethod::Get, "/api/v1/operator/model-task-match").is_none());
    }

    #[test]
    fn enrollment_requires_administrator_and_is_bounded() {
        let route = resolve_route(HttpMethod::Post, "/api/v1/devices/enroll").unwrap();
        assert!(!route.permits_operator_role(OperatorRole::Viewer));
        assert!(!route.permits_operator_role(OperatorRole::Operator));
        assert!(route.permits_operator_role(OperatorRole::Administrator));
        assert!(route.permits_body_size(MAX_DEVICE_ENROLLMENT_BODY_BYTES));
        assert!(!route.permits_body_size(MAX_DEVICE_ENROLLMENT_BODY_BYTES + 1));
    }

    #[test]
    fn device_ingest_and_lease_routes_require_device_signatures() {
        for (path, expected) in [
            (
                "/api/v1/devices/device-1/telemetry",
                OperatorHttpRoute::DeviceTelemetry,
            ),
            (
                "/api/v1/devices/device-1/model-inventory",
                OperatorHttpRoute::DeviceModelInventory,
            ),
            ("/api/v1/leases/acquire", OperatorHttpRoute::LeaseAcquire),
            (
                "/api/v1/leases/lease-1/renew",
                OperatorHttpRoute::LeaseRenew,
            ),
            (
                "/api/v1/leases/lease-1/release",
                OperatorHttpRoute::LeaseRelease,
            ),
        ] {
            let route = resolve_route(HttpMethod::Post, path).unwrap();
            assert_eq!(route.route, expected);
            assert_eq!(route.principal, RoutePrincipal::EnrolledDeviceSignature);
        }
    }

    #[test]
    fn model_inventory_requires_device_signature_and_has_a_bounded_body() {
        let route =
            resolve_route(HttpMethod::Post, "/api/v1/devices/device-1/model-inventory").unwrap();
        assert_eq!(route.route, OperatorHttpRoute::DeviceModelInventory);
        assert_eq!(route.principal, RoutePrincipal::EnrolledDeviceSignature);
        assert!(route.permits_body_size(MAX_MODEL_INVENTORY_BODY_BYTES));
        assert!(!route.permits_body_size(MAX_MODEL_INVENTORY_BODY_BYTES + 1));
        assert!(
            resolve_route(HttpMethod::Get, "/api/v1/devices/device-1/model-inventory").is_none()
        );
    }

    #[test]
    fn owner_consent_requires_device_signature_and_has_a_bounded_body() {
        let route =
            resolve_route(HttpMethod::Post, "/api/v1/devices/device-1/owner-consent").unwrap();
        assert_eq!(route.route, OperatorHttpRoute::DeviceOwnerConsent);
        assert_eq!(route.principal, RoutePrincipal::EnrolledDeviceSignature);
        assert!(route.permits_body_size(MAX_OWNER_CONSENT_BODY_BYTES));
        assert!(!route.permits_body_size(MAX_OWNER_CONSENT_BODY_BYTES + 1));
        assert!(resolve_route(HttpMethod::Get, "/api/v1/devices/device-1/owner-consent").is_none());
    }

    #[test]
    fn unknown_methods_paths_and_unsafe_segments_fail_closed() {
        assert!(resolve_route(HttpMethod::Post, "/api/v1/operator/overview").is_none());
        assert!(resolve_route(HttpMethod::Get, "/api/v1/leases/acquire").is_none());
        assert!(resolve_route(HttpMethod::Post, "/api/v1/devices/../telemetry").is_none());
        assert!(resolve_route(HttpMethod::Post, "/api/v1/devices/%2fetc/telemetry").is_none());
        assert!(resolve_route(
            HttpMethod::Post,
            "/api/v1/devices/device-1/owner-consent/extra/segments"
        )
        .is_none());
        assert!(resolve_route(HttpMethod::Post, "/api/v1/leases/lease-1/execute").is_none());
        assert!(resolve_route(HttpMethod::Post, "/api/v1/workloads/execute").is_none());
        assert!(resolve_route(HttpMethod::Post, "prefix/v1/devices/device-1/telemetry").is_none());
        assert!(resolve_route(HttpMethod::Post, "prefix/v1/leases/lease-1/renew").is_none());
        assert!(resolve_route(HttpMethod::Post, "//v1/devices/device-1/telemetry").is_none());
    }

    #[test]
    fn rejects_non_canonical_or_ambiguous_request_targets() {
        for path in [
            "/api/v1/devices/device-1/telemetry?override=1",
            "/api/v1/devices/device-1/telemetry#fragment",
            "/api/v1/devices/device-1%2Fother/telemetry",
            "/api/v1/devices/device-1\\telemetry",
            "/api/v1/devices/device-1/telemetry\r\nX-Injected: yes",
            "/api/v1/devices/device-1/telemetry\tX-Injected: yes",
            "/api/v1/devices/device-1/telemetry\0X-Injected: yes",
            "/api/v1/devices/device-1//telemetry",
        ] {
            assert!(
                resolve_route(HttpMethod::Post, path).is_none(),
                "ambiguous path must be rejected: {path:?}"
            );
        }
        let oversized = format!("/{}", "a".repeat(2048));
        assert!(resolve_route(HttpMethod::Post, &oversized).is_none());
    }

    #[test]
    fn service_errors_map_to_non_leaky_http_statuses() {
        assert_eq!(
            service_error_status(OperatorServiceError::Unauthorized),
            401
        );
        assert_eq!(
            service_error_status(OperatorServiceError::InvalidTenantBoundary),
            500
        );
        assert_eq!(
            service_error_status(OperatorServiceError::RepositoryUnavailable),
            503
        );
        assert_eq!(
            service_error_status(OperatorServiceError::AuditUnavailable),
            503
        );
        assert_eq!(
            service_error_status(OperatorServiceError::InvalidOverview),
            502
        );
    }
}

#[cfg(test)]
mod strict_path_canonicalization_regressions {
    use super::*;

    #[test]
    fn rejects_non_origin_form_and_ambiguous_path_spellings() {
        for path in [
            "",
            "healthz",
            "https://ujani.example/healthz",
            "//v1/operator/overview",
            "/api/v1/operator/overview?tenant=other",
            "/api/v1/operator/overview#fragment",
            "/api/v1/operator/%6fverview",
            "/api/v1/operator\\\\overview",
            "/api/v1/devices/device-1/telemetry/",
            "/api/v1/devices/device-1/telemetry/extra",
            "/api/v1/devices//telemetry",
            "/api/v1/devices/../telemetry",
            "/api/v1/devices/device-1/owner-consent?confirm=true",
        ] {
            assert!(
                resolve_route(HttpMethod::Get, path).is_none()
                    && resolve_route(HttpMethod::Post, path).is_none(),
                "ambiguous or non-canonical path must fail closed: {path:?}"
            );
        }
    }

    #[test]
    fn route_resolution_is_method_specific_and_does_not_accept_body_on_get_routes() {
        let overview = resolve_route(HttpMethod::Get, "/api/v1/operator/overview").unwrap();
        assert_eq!(overview.route, OperatorHttpRoute::OperatorOverview);
        assert_eq!(overview.max_body_bytes, 0);
        assert!(overview.permits_body_size(0));
        assert!(!overview.permits_body_size(1));

        assert!(resolve_route(HttpMethod::Post, "/api/v1/operator/overview").is_none());
        assert!(resolve_route(HttpMethod::Get, "/api/v1/devices/device-1/telemetry").is_none());
    }

    #[test]
    fn rejects_overlong_targets_before_route_matching() {
        assert!(resolve_route(HttpMethod::Get, "/v1/operator/overview").is_none());
        assert!(resolve_route(HttpMethod::Post, "/v1/devices/device-1/telemetry").is_none());
        let path = format!("/{}", "a".repeat(2048));
        assert!(resolve_route(HttpMethod::Get, &path).is_none());
        assert!(resolve_route(HttpMethod::Post, &path).is_none());
    }
}

#[cfg(test)]
mod path_segment_boundary_regressions {
    use super::{owner_consent_device_id, valid_path_segment};

    #[test]
    fn owner_consent_path_extracts_only_the_canonical_api_v1_device_segment() {
        assert_eq!(
            owner_consent_device_id("/api/v1/devices/device-01/owner-consent"),
            Some("device-01")
        );
        assert_eq!(
            owner_consent_device_id("/v1/devices/device-01/owner-consent"),
            None
        );
        assert_eq!(
            owner_consent_device_id("/api/v1/devices/../owner-consent"),
            None
        );
    }

    #[test]
    fn accepts_only_bounded_ascii_device_and_lease_identifiers() {
        assert!(valid_path_segment("device-01"));
        assert!(valid_path_segment("tenant:device_01.v2"));
        assert!(valid_path_segment(&"a".repeat(128)));

        for invalid in [
            "",
            ".",
            "..",
            "device/other",
            "device\\other",
            "device%2Fother",
            "device name",
            "device?tenant=other",
            "device#fragment",
            "device\nheader",
            "dévïce",
        ] {
            assert!(
                !valid_path_segment(invalid),
                "unsafe path segment must be rejected: {invalid:?}"
            );
        }

        assert!(!valid_path_segment(&"a".repeat(129)));
    }
}

#[cfg(test)]
mod strict_request_body_boundary_regressions {
    use super::*;

    #[test]
    fn device_ingest_and_lease_routes_enforce_exact_body_limits() {
        let cases = [
            (
                "/api/v1/devices/device-1/telemetry",
                MAX_DEVICE_INGEST_BODY_BYTES,
            ),
            (
                "/api/v1/devices/device-1/model-inventory",
                MAX_MODEL_INVENTORY_BODY_BYTES,
            ),
            (
                "/api/v1/leases/lease-1/renew",
                MAX_OPERATOR_ACTION_BODY_BYTES,
            ),
            (
                "/api/v1/leases/lease-1/release",
                MAX_OPERATOR_ACTION_BODY_BYTES,
            ),
        ];
        for (path, maximum) in cases {
            let route = resolve_route(HttpMethod::Post, path)
                .unwrap_or_else(|| panic!("expected exact supported route: {path}"));
            assert_eq!(route.principal, RoutePrincipal::EnrolledDeviceSignature);
            assert!(
                route.permits_body_size(maximum),
                "exact limit must be accepted: {path}"
            );
            assert!(
                !route.permits_body_size(maximum + 1),
                "one byte over limit must be rejected: {path}"
            );
        }
    }

    #[test]
    fn device_path_identity_is_not_loosened_by_extra_or_ambiguous_segments() {
        for path in [
            "/api/v1/devices/device-1/telemetry/extra",
            "/api/v1/devices/device-1//telemetry",
            "/api/v1/devices/device-1%2Fother/telemetry",
            "/api/v1/devices/device-1/telemetry?device=device-2",
            "/api/v1/devices/device-1/telemetry#device-2",
        ] {
            assert!(
                resolve_route(HttpMethod::Post, path).is_none(),
                "must reject: {path}"
            );
        }
        assert!(resolve_route(HttpMethod::Post, "/api/v1/devices/device-1/telemetry").is_some());
    }
}

#[cfg(test)]
mod model_task_match_route_compatibility_regressions {
    use super::*;

    #[test]
    fn only_the_documented_api_v1_model_match_path_is_routable() {
        let route = resolve_route(HttpMethod::Post, "/api/v1/operator/model-task-match")
            .expect("canonical documented route must resolve");
        assert_eq!(route.route, OperatorHttpRoute::OperatorModelTaskMatch);
        assert_eq!(
            route.principal,
            RoutePrincipal::Operator {
                minimum_role: OperatorRole::Viewer
            }
        );
        assert_eq!(route.max_body_bytes, MAX_MODEL_TASK_MATCH_BODY_BYTES);
        assert!(route.permits_body_size(MAX_MODEL_TASK_MATCH_BODY_BYTES));
        assert!(!route.permits_body_size(MAX_MODEL_TASK_MATCH_BODY_BYTES + 1));

        for unsupported in [
            "/v1/operator/model-task-match",
            "/api/v1/operator/model-task-match/",
            "/api/v1/operator/model-task-match?device=device-1",
            "/api/v1/operator/model-task-match#fragment",
        ] {
            assert!(
                resolve_route(HttpMethod::Post, unsupported).is_none(),
                "unsupported spelling must fail closed: {unsupported}"
            );
        }
        assert!(resolve_route(HttpMethod::Get, "/api/v1/operator/model-task-match").is_none());
    }
}

#[cfg(test)]
mod dynamic_route_identifier_boundary_regressions {
    use super::*;

    #[test]
    fn dynamic_device_and_lease_routes_reject_invalid_identifiers() {
        for path in [
            "/api/v1/devices//telemetry",
            "/api/v1/devices/../telemetry",
            "/api/v1/devices/device/other/telemetry",
            "/api/v1/devices/device%2Fother/telemetry",
            "/api/v1/leases//renew",
            "/api/v1/leases/../release",
            "/api/v1/leases/lease/other/renew",
            "/api/v1/leases/lease%2Fother/release",
            &format!("/api/v1/devices/{}/telemetry", "d".repeat(129)),
            &format!("/api/v1/leases/{}/renew", "l".repeat(129)),
        ] {
            assert!(
                resolve_route(HttpMethod::Post, path).is_none(),
                "dynamic route must reject invalid identifier: {path:?}"
            );
        }
    }

    #[test]
    fn dynamic_device_and_lease_routes_accept_bounded_canonical_identifiers() {
        for path in [
            "/api/v1/devices/device-01/telemetry",
            "/api/v1/devices/tenant:device_01.v2/model-inventory",
            "/api/v1/devices/device-01/owner-consent",
            "/api/v1/leases/lease-01/renew",
            "/api/v1/leases/tenant:lease_01.v2/release",
        ] {
            assert!(
                resolve_route(HttpMethod::Post, path).is_some(),
                "canonical bounded identifier should route: {path:?}"
            );
        }
    }
}

#[cfg(test)]
mod model_task_match_body_decoder_tests {
    use super::*;

    const VALID: &str = r#"{
        "device_id": "device-01",
        "model_ref": "llama3.2:latest",
        "requirements": {
            "required_capabilities": ["chat"],
            "minimum_context_length_tokens": 4096,
            "minimum_memory_mb": 2048
        }
    }"#;

    #[test]
    fn bounded_valid_request_decodes_to_typed_requirements() {
        let request = decode_model_task_match_request(VALID.as_bytes()).unwrap();
        assert_eq!(request.device_id, "device-01");
        assert_eq!(request.model_ref, "llama3.2:latest");
        assert_eq!(
            request.requirements.minimum_context_length_tokens,
            Some(4096)
        );
        assert_eq!(request.requirements.minimum_memory_mb, Some(2048));
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_nesting_level() {
        let duplicate_top_level = br#"{
            "device_id": "device-01",
            "device_id": "device-02",
            "model_ref": "llama3.2:latest",
            "requirements": {"required_capabilities": ["chat"]}
        }"#;
        assert_eq!(
            decode_model_task_match_request(duplicate_top_level),
            Err(ModelTaskMatchBodyError::InvalidJson)
        );

        let duplicate_nested = br#"{
            "device_id": "device-01",
            "model_ref": "llama3.2:latest",
            "requirements": {
                "required_capabilities": ["chat"],
                "minimum_memory_mb": 1024,
                "minimum_memory_mb": 2048
            }
        }"#;
        assert_eq!(
            decode_model_task_match_request(duplicate_nested),
            Err(ModelTaskMatchBodyError::InvalidJson)
        );
    }

    #[test]
    fn unknown_fields_and_wrong_shapes_are_rejected_by_typed_contract() {
        let unknown_top_level = VALID.replace(
            "\"model_ref\": \"llama3.2:latest\",",
            "\"model_ref\": \"llama3.2:latest\", \"tenant_id\": \"tenant-from-browser\",",
        );
        assert_eq!(
            decode_model_task_match_request(unknown_top_level.as_bytes()),
            Err(ModelTaskMatchBodyError::InvalidRequest)
        );

        let unknown_nested = VALID.replace(
            "\"minimum_memory_mb\": 2048",
            "\"minimum_memory_mb\": 2048, \"role\": \"administrator\"",
        );
        assert_eq!(
            decode_model_task_match_request(unknown_nested.as_bytes()),
            Err(ModelTaskMatchBodyError::InvalidRequest)
        );
    }

    #[test]
    fn empty_oversized_malformed_and_trailing_bodies_fail_before_dispatch() {
        assert_eq!(
            decode_model_task_match_request(b""),
            Err(ModelTaskMatchBodyError::EmptyBody)
        );
        assert_eq!(
            decode_model_task_match_request(&vec![b' '; MAX_MODEL_TASK_MATCH_BODY_BYTES + 1]),
            Err(ModelTaskMatchBodyError::BodyTooLarge)
        );
        assert_eq!(
            decode_model_task_match_request(b"{not-json}"),
            Err(ModelTaskMatchBodyError::InvalidJson)
        );
        assert_eq!(
            decode_model_task_match_request(format!("{VALID} {{}}").as_bytes()),
            Err(ModelTaskMatchBodyError::InvalidJson)
        );
    }
}
