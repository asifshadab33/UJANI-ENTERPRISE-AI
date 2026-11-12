//! Fail-closed HTTP route contract for the future Enterprise hosting adapter.
//!
//! This module is deliberately transport-neutral: it does not open a socket,
//! terminate TLS, validate OIDC tokens, persist leases, or execute workloads.
//! The HTTP adapter MUST resolve routes through this contract before dispatch,
//! enforce the declared body limit, authenticate the declared principal, and
//! fail closed for every unknown method/path. No remote-execution route exists.
use super::operator_control_plane::{OperatorRole, OperatorServiceError};

pub const MAX_OPERATOR_ACTION_BODY_BYTES: usize = 16 * 1024;
pub const MAX_DEVICE_ENROLLMENT_BODY_BYTES: usize = 64 * 1024;
pub const MAX_DEVICE_INGEST_BODY_BYTES: usize = 1024 * 1024;

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
    DeviceEnrollment,
    DeviceTelemetry,
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
    if !path.starts_with('/') || path.starts_with("//") {
        return None;
    }
    if path == "/healthz" && method == HttpMethod::Get {
        return Some(RouteContract {
            route: OperatorHttpRoute::Health,
            principal: RoutePrincipal::PublicHealth,
            max_body_bytes: 0,
        });
    }
    if path == "/v1/operator/overview" && method == HttpMethod::Get {
        return Some(RouteContract {
            route: OperatorHttpRoute::OperatorOverview,
            principal: RoutePrincipal::Operator {
                minimum_role: OperatorRole::Viewer,
            },
            max_body_bytes: 0,
        });
    }
    if path == "/v1/devices/enroll" && method == HttpMethod::Post {
        return Some(RouteContract {
            route: OperatorHttpRoute::DeviceEnrollment,
            principal: RoutePrincipal::Operator {
                minimum_role: OperatorRole::Administrator,
            },
            max_body_bytes: MAX_DEVICE_ENROLLMENT_BODY_BYTES,
        });
    }
    if path == "/v1/leases/acquire" && method == HttpMethod::Post {
        return Some(RouteContract {
            route: OperatorHttpRoute::LeaseAcquire,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_OPERATOR_ACTION_BODY_BYTES,
        });
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() == 5
        && parts[1] == "v1"
        && parts[2] == "devices"
        && valid_path_segment(parts[3])
        && parts[4] == "telemetry"
        && method == HttpMethod::Post
    {
        return Some(RouteContract {
            route: OperatorHttpRoute::DeviceTelemetry,
            principal: RoutePrincipal::EnrolledDeviceSignature,
            max_body_bytes: MAX_DEVICE_INGEST_BODY_BYTES,
        });
    }
    if parts.len() == 5
        && parts[1] == "v1"
        && parts[2] == "leases"
        && valid_path_segment(parts[3])
        && method == HttpMethod::Post
    {
        let route = match parts[4] {
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
        let route = resolve_route(HttpMethod::Get, "/v1/operator/overview").unwrap();
        assert_eq!(route.route, OperatorHttpRoute::OperatorOverview);
        assert!(route.permits_operator_role(OperatorRole::Viewer));
        assert!(route.permits_operator_role(OperatorRole::Administrator));
        assert!(!route.permits_body_size(1));
    }

    #[test]
    fn enrollment_requires_administrator_and_is_bounded() {
        let route = resolve_route(HttpMethod::Post, "/v1/devices/enroll").unwrap();
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
                "/v1/devices/device-1/telemetry",
                OperatorHttpRoute::DeviceTelemetry,
            ),
            ("/v1/leases/acquire", OperatorHttpRoute::LeaseAcquire),
            ("/v1/leases/lease-1/renew", OperatorHttpRoute::LeaseRenew),
            (
                "/v1/leases/lease-1/release",
                OperatorHttpRoute::LeaseRelease,
            ),
        ] {
            let route = resolve_route(HttpMethod::Post, path).unwrap();
            assert_eq!(route.route, expected);
            assert_eq!(route.principal, RoutePrincipal::EnrolledDeviceSignature);
        }
    }

    #[test]
    fn unknown_methods_paths_and_unsafe_segments_fail_closed() {
        assert!(resolve_route(HttpMethod::Post, "/v1/operator/overview").is_none());
        assert!(resolve_route(HttpMethod::Get, "/v1/leases/acquire").is_none());
        assert!(resolve_route(HttpMethod::Post, "/v1/devices/../telemetry").is_none());
        assert!(resolve_route(HttpMethod::Post, "/v1/devices/%2fetc/telemetry").is_none());
        assert!(resolve_route(HttpMethod::Post, "/v1/leases/lease-1/execute").is_none());
        assert!(resolve_route(HttpMethod::Post, "/v1/workloads/execute").is_none());
        assert!(resolve_route(HttpMethod::Post, "prefix/v1/devices/device-1/telemetry").is_none());
        assert!(resolve_route(HttpMethod::Post, "prefix/v1/leases/lease-1/renew").is_none());
        assert!(resolve_route(HttpMethod::Post, "//v1/devices/device-1/telemetry").is_none());
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
