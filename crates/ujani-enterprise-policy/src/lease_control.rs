//! Authenticated device-bound lease renewal and release application service.
//!
//! The HTTP adapter must select the route, expected tenant and workload manifest
//! from trusted server-side state. This module authenticates the signed device
//! request, checks current enrollment/key generation, and binds lease mutation
//! to the exact device that owns the durable reservation. It does not open a
//! network listener or dispatch/execute workloads.

use crate::device_trust::durable::DurableDeviceRegistry;
use crate::device_trust::{
    AuthenticatedDeviceRequest, SignedDeviceRequest, MAX_DEVICE_REQUEST_BODY_BYTES,
};
use crate::durable_ledger::{DurableLedger, DurableLedgerError};

const LEASE_REQUEST_METHOD: &str = "POST";
const LEASE_RENEW_RESOURCE: &str = "lease.renew";
const LEASE_RELEASE_RESOURCE: &str = "lease.release";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseControlError {
    RequestBodyTooLarge,
    RequestBindingMismatch,
    DeviceAuthenticationFailed,
    OwnerOptInMissing,
    LeaseRejected,
    LedgerUnavailable,
    ReservationOutcomeUnknown,
}

#[allow(clippy::too_many_arguments)]
fn authenticate_lease_request(
    registry: &DurableDeviceRegistry,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    expected_resource: &str,
    expected_tenant_id: &str,
    expected_workload_id: &str,
    expected_manifest_sha256: &[u8; 32],
    now_unix_ms: u64,
) -> Result<AuthenticatedDeviceRequest, LeaseControlError> {
    if raw_body.len() > MAX_DEVICE_REQUEST_BODY_BYTES {
        return Err(LeaseControlError::RequestBodyTooLarge);
    }
    let claims = &signed_request.claims;
    if claims.tenant_id != expected_tenant_id
        || claims.workload_id != expected_workload_id
        || &claims.manifest_sha256 != expected_manifest_sha256
    {
        return Err(LeaseControlError::RequestBindingMismatch);
    }

    let authenticated = registry
        .authenticate_request_for(
            signed_request,
            LEASE_REQUEST_METHOD,
            expected_resource,
            raw_body,
            now_unix_ms,
        )
        .map_err(|_| LeaseControlError::DeviceAuthenticationFailed)?;

    if authenticated.tenant_id() != expected_tenant_id
        || authenticated.workload_id() != expected_workload_id
        || authenticated.manifest_sha256() != expected_manifest_sha256
    {
        return Err(LeaseControlError::RequestBindingMismatch);
    }

    Ok(authenticated)
}

/// Renew an existing lease from its currently enrolled device. The expected
/// manifest digest must come from the trusted workload record, not the request.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_and_renew_device_lease(
    registry: &DurableDeviceRegistry,
    ledger: &DurableLedger,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    expected_tenant_id: &str,
    expected_workload_id: &str,
    expected_manifest_sha256: &[u8; 32],
    lease_token: &[u8; 32],
    now_unix_ms: u64,
) -> Result<(), LeaseControlError> {
    let authenticated = authenticate_lease_request(
        registry,
        signed_request,
        raw_body,
        LEASE_RENEW_RESOURCE,
        expected_tenant_id,
        expected_workload_id,
        expected_manifest_sha256,
        now_unix_ms,
    )?;
    registry
        .with_authenticated_device_status_for_request(&authenticated, |_key, owner_opted_in| {
            if !owner_opted_in {
                return Err(LeaseControlError::OwnerOptInMissing);
            }
            let renewed = ledger
                .renew_lease_for_device(
                    authenticated.workload_id(),
                    authenticated.device_id(),
                    lease_token,
                    now_unix_ms,
                )
                .map_err(map_ledger_error)?;
            if !renewed {
                return Err(LeaseControlError::LeaseRejected);
            }
            Ok(())
        })
        .map_err(|_| LeaseControlError::DeviceAuthenticationFailed)??;
    Ok(())
}

/// Release is permitted for the owning authenticated device even after owner
/// opt-out, so an opt-out can relinquish an active reservation. It never renews
/// or creates work.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_and_release_device_lease(
    registry: &DurableDeviceRegistry,
    ledger: &DurableLedger,
    signed_request: &SignedDeviceRequest,
    raw_body: &[u8],
    expected_tenant_id: &str,
    expected_workload_id: &str,
    expected_manifest_sha256: &[u8; 32],
    lease_token: &[u8; 32],
    now_unix_ms: u64,
) -> Result<(), LeaseControlError> {
    let authenticated = authenticate_lease_request(
        registry,
        signed_request,
        raw_body,
        LEASE_RELEASE_RESOURCE,
        expected_tenant_id,
        expected_workload_id,
        expected_manifest_sha256,
        now_unix_ms,
    )?;
    registry
        .with_authenticated_device_status_for_request(&authenticated, |_key, _owner_opted_in| {
            let released = ledger
                .release_lease_for_device(
                    authenticated.workload_id(),
                    authenticated.device_id(),
                    lease_token,
                )
                .map_err(map_ledger_error)?;
            if !released {
                return Err(LeaseControlError::LeaseRejected);
            }
            Ok(())
        })
        .map_err(|_| LeaseControlError::DeviceAuthenticationFailed)??;
    Ok(())
}

fn map_ledger_error(error: DurableLedgerError) -> LeaseControlError {
    match error {
        DurableLedgerError::AnchorUnavailable(_) => LeaseControlError::ReservationOutcomeUnknown,
        _ => LeaseControlError::LedgerUnavailable,
    }
}
