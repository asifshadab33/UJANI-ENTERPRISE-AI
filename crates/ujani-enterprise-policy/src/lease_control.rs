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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_trust::durable::{DeviceTrustIntegrityKey, DurableDeviceRegistry};
    use crate::device_trust::{
        admin_command_bytes, device_request_bytes, enrollment_proof_bytes, owner_consent_bytes,
        DeviceCommandAction, DeviceRequestClaims, SignedDeviceAdminCommand,
        SignedOwnerConsentCommand, MAX_OWNER_CONSENT_TTL_MS,
    };
    use crate::durable_ledger::LedgerIntegrityKey;
    use crate::{
        workload_from_manifest, Admission, ClassPolicy, DataClassification, Device,
        SchedulingContext, WorkloadManifest, LEASE_MS,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TENANT_ID: &str = "tenant-a";
    const DEVICE_ID: &str = "device-1";
    const WORKLOAD_ID: &str = "job-lease-test";

    struct Fixture {
        directory: PathBuf,
        registry_path: PathBuf,
        ledger_path: PathBuf,
        device: SigningKey,
        registry: DurableDeviceRegistry,
        ledger: DurableLedger,
        manifest_sha256: [u8; 32],
        lease_token: [u8; 32],
    }

    fn test_directory() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ujani-lease-control-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("restrict test directory permissions");
        }
        path
    }

    fn test_key_bytes(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn open_registry(path: &Path, admin: &SigningKey) -> DurableDeviceRegistry {
        DurableDeviceRegistry::open(
            path,
            vec![("admin-v1".to_owned(), admin.verifying_key())],
            DeviceTrustIntegrityKey::new(
                "trust-test-v1",
                test_key_bytes("ujani-lease-control-trust-integrity-test-v1"),
            ),
        )
        .expect("open durable device registry")
    }

    fn open_ledger(path: &Path) -> DurableLedger {
        DurableLedger::open_with_integrity_keys(
            path,
            "ledger-test-v1",
            vec![LedgerIntegrityKey::new(
                "ledger-test-v1",
                test_key_bytes("ujani-lease-control-ledger-integrity-test-v1"),
            )],
        )
        .expect("open durable reservation ledger")
    }

    fn signed_enrollment(admin: &SigningKey, device: &SigningKey) -> SignedDeviceAdminCommand {
        let mut command = SignedDeviceAdminCommand {
            action: DeviceCommandAction::Enroll,
            tenant_id: TENANT_ID.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            admin_key_id: "admin-v1".to_owned(),
            target_key_id: "device-key-v1".to_owned(),
            target_public_key: Some(device.verifying_key().to_bytes()),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1_000,
            nonce: [1; 16],
            signature: [0; 64],
            old_device_signature: None,
            new_device_signature: None,
        };
        command.new_device_signature =
            Some(device.sign(&enrollment_proof_bytes(&command)).to_bytes());
        command.signature = admin.sign(&admin_command_bytes(&command)).to_bytes();
        command
    }

    fn signed_owner_consent(
        device: &SigningKey,
        opted_in: bool,
        revision: u64,
        issued_at_unix_ms: u64,
        nonce: [u8; 16],
    ) -> SignedOwnerConsentCommand {
        let mut command = SignedOwnerConsentCommand {
            tenant_id: TENANT_ID.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            key_id: "device-key-v1".to_owned(),
            key_generation: 1,
            revision,
            opted_in,
            issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms + MAX_OWNER_CONSENT_TTL_MS,
            nonce,
            signature: [0; 64],
        };
        command.signature = device.sign(&owner_consent_bytes(&command)).to_bytes();
        command
    }

    fn manifest() -> WorkloadManifest {
        WorkloadManifest {
            schema_version: 1,
            workload_id: WORKLOAD_ID.to_owned(),
            class: "inference".to_owned(),
            model: "qwen2.5:3b".to_owned(),
            requested_cpu_millis: 500,
            requested_memory_mb: 512,
            max_runtime_ms: 60_000,
            data_classification: DataClassification::Internal,
            network_access: false,
        }
    }

    fn signed_request(
        device: &SigningKey,
        manifest_sha256: [u8; 32],
        resource_id: &str,
        request_id: u8,
        now_unix_ms: u64,
        body: &[u8],
    ) -> SignedDeviceRequest {
        let claims = DeviceRequestClaims {
            tenant_id: TENANT_ID.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            key_id: "device-key-v1".to_owned(),
            key_generation: 1,
            request_id: [request_id; 16],
            issued_at_unix_ms: now_unix_ms.saturating_sub(100),
            expires_at_unix_ms: now_unix_ms.saturating_add(5_000),
            method: "POST".to_owned(),
            resource_id: resource_id.to_owned(),
            workload_id: WORKLOAD_ID.to_owned(),
            manifest_sha256,
            body_sha256: Sha256::digest(body).into(),
        };
        let signature = device.sign(&device_request_bytes(&claims)).to_bytes();
        SignedDeviceRequest { claims, signature }
    }

    fn setup() -> Fixture {
        let directory = test_directory();
        let registry_path = directory.join("device-trust.db");
        let ledger_path = directory.join("reservations.db");
        let admin = SigningKey::from_bytes(&test_key_bytes("ujani-lease-control-admin-test-v1"));
        let device = SigningKey::from_bytes(&test_key_bytes("ujani-lease-control-device-test-v1"));
        let registry = open_registry(&registry_path, &admin);
        registry
            .apply_admin_command(&signed_enrollment(&admin, &device), 200)
            .expect("enrol test device");
        registry
            .apply_owner_consent(&signed_owner_consent(&device, true, 1, 300, [2; 16]), 400)
            .expect("persist explicit device-owner opt-in");

        let manifest = manifest();
        let manifest_sha256 =
            crate::workload_manifest_sha256(&manifest).expect("valid workload manifest");
        let workload = workload_from_manifest(&manifest).expect("construct workload");
        let ledger = open_ledger(&ledger_path);
        let admission_device = Device {
            device_id: DEVICE_ID.to_owned(),
            enrolled: true,
            admin_approved: true,
            available: true,
            allowed_workload_classes: vec!["inference".to_owned()],
            remaining_cpu_millis: 2_000,
            remaining_memory_mb: 4_096,
        };
        let context = SchedulingContext {
            owner_opted_in: true,
            within_admin_schedule: true,
            interactive_user_present: false,
            on_ac_power: true,
            device_already_running: true,
            thermal_state_safe: true,
            network_policy_allows: true,
            data_classification_allows: true,
            telemetry_fresh: true,
        };
        let policies = vec![ClassPolicy {
            class: "inference".to_owned(),
            requires_admin_approval: false,
            max_cpu_millis: 2_000,
            max_memory_mb: 4_096,
        }];
        let lease_token = [0x55; 32];
        assert_eq!(
            ledger
                .admit_and_reserve_with_lease(
                    &admission_device,
                    &workload,
                    &context,
                    &policies,
                    &[],
                    1_000,
                    &lease_token,
                )
                .expect("commit initial durable lease"),
            Admission::Accept
        );

        Fixture {
            directory,
            registry_path,
            ledger_path,
            device,
            registry,
            ledger,
            manifest_sha256,
            lease_token,
        }
    }

    fn cleanup(fixture: Fixture) {
        let Fixture {
            directory,
            registry,
            ledger,
            ..
        } = fixture;
        drop(registry);
        drop(ledger);
        fs::remove_dir_all(directory).expect("remove isolated test directory");
    }

    #[test]
    fn durable_renew_requires_owner_opt_in_and_owner_can_release_after_opt_out() {
        let fixture = setup();
        let renew_body = b"renew lease";
        let renew = signed_request(
            &fixture.device,
            fixture.manifest_sha256,
            "lease.renew",
            3,
            1_500,
            renew_body,
        );
        assert_eq!(
            authenticate_and_renew_device_lease(
                &fixture.registry,
                &fixture.ledger,
                &renew,
                renew_body,
                TENANT_ID,
                WORKLOAD_ID,
                &fixture.manifest_sha256,
                &fixture.lease_token,
                1_500,
            ),
            Ok(())
        );
        assert_eq!(fixture.ledger.snapshot().unwrap().active_jobs, 1);

        fixture
            .registry
            .apply_owner_consent(
                &signed_owner_consent(&fixture.device, false, 2, 1_600, [4; 16]),
                1_700,
            )
            .expect("persist owner opt-out");
        let denied_renew_body = b"renew after opt-out";
        let denied_renew = signed_request(
            &fixture.device,
            fixture.manifest_sha256,
            "lease.renew",
            5,
            1_800,
            denied_renew_body,
        );
        assert_eq!(
            authenticate_and_renew_device_lease(
                &fixture.registry,
                &fixture.ledger,
                &denied_renew,
                denied_renew_body,
                TENANT_ID,
                WORKLOAD_ID,
                &fixture.manifest_sha256,
                &fixture.lease_token,
                1_800,
            ),
            Err(LeaseControlError::OwnerOptInMissing)
        );

        let release_body = b"release after opt-out";
        let release = signed_request(
            &fixture.device,
            fixture.manifest_sha256,
            "lease.release",
            6,
            1_900,
            release_body,
        );
        assert_eq!(
            authenticate_and_release_device_lease(
                &fixture.registry,
                &fixture.ledger,
                &release,
                release_body,
                TENANT_ID,
                WORKLOAD_ID,
                &fixture.manifest_sha256,
                &fixture.lease_token,
                1_900,
            ),
            Ok(())
        );
        let snapshot = fixture.ledger.snapshot().unwrap();
        assert_eq!(snapshot.active_jobs, 0);
        assert_eq!(snapshot.reserved_cpu_millis, 0);
        assert_eq!(snapshot.reserved_memory_mb, 0);
        assert_eq!(
            fixture
                .ledger
                .reservation_revision(DEVICE_ID, 2_000)
                .unwrap(),
            3
        );
        cleanup(fixture);
    }

    #[test]
    fn authenticated_renewal_cannot_resurrect_an_expired_lease() {
        let fixture = setup();
        let now = 1_000 + LEASE_MS + 1;
        let body = b"renew expired lease";
        let request = signed_request(
            &fixture.device,
            fixture.manifest_sha256,
            "lease.renew",
            7,
            now,
            body,
        );
        assert_eq!(
            authenticate_and_renew_device_lease(
                &fixture.registry,
                &fixture.ledger,
                &request,
                body,
                TENANT_ID,
                WORKLOAD_ID,
                &fixture.manifest_sha256,
                &fixture.lease_token,
                now,
            ),
            Err(LeaseControlError::LeaseRejected)
        );
        let snapshot = fixture.ledger.snapshot().unwrap();
        assert_eq!(snapshot.active_jobs, 0);
        assert_eq!(snapshot.reserved_cpu_millis, 0);
        assert_eq!(snapshot.reserved_memory_mb, 0);
        assert_eq!(
            fixture.ledger.reservation_revision(DEVICE_ID, now).unwrap(),
            2
        );
        cleanup(fixture);
    }

    #[test]
    fn concurrent_authenticated_releases_are_serialized_across_store_handles() {
        let fixture = setup();
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();

        for request_id in [8u8, 9u8] {
            let registry_path = fixture.registry_path.clone();
            let ledger_path = fixture.ledger_path.clone();
            let manifest_sha256 = fixture.manifest_sha256;
            let lease_token = fixture.lease_token;
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let admin =
                    SigningKey::from_bytes(&test_key_bytes("ujani-lease-control-admin-test-v1"));
                let device =
                    SigningKey::from_bytes(&test_key_bytes("ujani-lease-control-device-test-v1"));
                let registry = open_registry(&registry_path, &admin);
                let ledger = open_ledger(&ledger_path);
                let body = b"concurrent release";
                let request = signed_request(
                    &device,
                    manifest_sha256,
                    "lease.release",
                    request_id,
                    2_000,
                    body,
                );
                barrier.wait();
                authenticate_and_release_device_lease(
                    &registry,
                    &ledger,
                    &request,
                    body,
                    TENANT_ID,
                    WORKLOAD_ID,
                    &manifest_sha256,
                    &lease_token,
                    2_000,
                )
            }));
        }

        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("release worker must not panic"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(LeaseControlError::LeaseRejected))
                .count(),
            1
        );
        let snapshot = fixture.ledger.snapshot().unwrap();
        assert_eq!(snapshot.active_jobs, 0);
        assert_eq!(snapshot.reserved_cpu_millis, 0);
        assert_eq!(snapshot.reserved_memory_mb, 0);
        assert_eq!(
            fixture
                .ledger
                .reservation_revision(DEVICE_ID, 2_001)
                .unwrap(),
            2
        );
        cleanup(fixture);
    }
}
