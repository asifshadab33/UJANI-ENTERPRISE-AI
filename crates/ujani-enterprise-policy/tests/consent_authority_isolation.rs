use std::sync::Arc;
use std::thread;

use ujani_enterprise_policy::collective_defence_authority::{
    AuthorityError, ConsentAuthorityBackend, IndividualConsentRecord, MemoryConsentAuthority,
    TenantConsentRecord,
};

fn tenant(tenant_id: &str, enabled: bool, generation: u64, now: u64) -> TenantConsentRecord {
    TenantConsentRecord {
        tenant_id: tenant_id.into(),
        enabled,
        generation,
        purpose: "collective-defence.read-only.v1".into(),
        schema_version: "1.0".into(),
        retention_seconds: if enabled { 86_400 } else { 0 },
        notice_version: "notice-v1".into(),
        notice_sha256: [1; 32],
        actor_key_id: "admin-key".into(),
        updated_at_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
    }
}

fn individual(
    tenant_id: &str,
    principal_id: &str,
    device_id: &str,
    tenant_generation: u64,
    generation: u64,
    now: u64,
) -> IndividualConsentRecord {
    IndividualConsentRecord {
        tenant_id: tenant_id.into(),
        principal_id: principal_id.into(),
        device_id: device_id.into(),
        enabled: true,
        tenant_generation,
        generation,
        purpose: "collective-defence.read-only.v1".into(),
        notice_version: "notice-v1".into(),
        notice_sha256: [2; 32],
        actor_key_id: "user-key".into(),
        updated_at_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
    }
}

#[test]
fn individual_consent_is_scoped_to_the_exact_device() {
    let authority = MemoryConsentAuthority::default();
    authority
        .put_tenant(tenant("tenant-a", true, 1, 100), None, "tenant-a-enable")
        .unwrap();
    authority
        .put_individual(
            individual("tenant-a", "user-a", "device-a", 1, 1, 101),
            None,
            "device-a-enable",
        )
        .unwrap();

    assert!(authority
        .authorization_snapshot("tenant-a", "user-a", "device-a", 102)
        .is_ok());
    assert_eq!(
        authority.authorization_snapshot("tenant-a", "user-a", "device-b", 102),
        Err(AuthorityError::IndividualNotEnabled)
    );
}

#[test]
fn tenant_reenable_does_not_restore_old_individual_consent() {
    let authority = MemoryConsentAuthority::default();
    authority
        .put_tenant(tenant("tenant-a", true, 1, 100), None, "enable-1")
        .unwrap();
    authority
        .put_individual(
            individual("tenant-a", "user-a", "device-a", 1, 1, 101),
            None,
            "individual-enable",
        )
        .unwrap();
    authority
        .put_tenant(tenant("tenant-a", false, 2, 102), Some(1), "disable-2")
        .unwrap();
    authority
        .put_tenant(tenant("tenant-a", true, 3, 103), Some(2), "reenable-3")
        .unwrap();

    assert_eq!(
        authority.authorization_snapshot("tenant-a", "user-a", "device-a", 104),
        Err(AuthorityError::ConsentNotCurrent)
    );
}

#[test]
fn concurrent_tenant_updates_cannot_both_win_the_same_generation() {
    let authority = Arc::new(MemoryConsentAuthority::default());
    let first_authority = Arc::clone(&authority);
    let second_authority = Arc::clone(&authority);

    let first = thread::spawn(move || {
        first_authority.put_tenant(
            tenant("tenant-race", true, 1, 100),
            None,
            "concurrent-request-a",
        )
    });
    let second = thread::spawn(move || {
        second_authority.put_tenant(
            tenant("tenant-race", true, 1, 101),
            None,
            "concurrent-request-b",
        )
    });

    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| **result == Err(AuthorityError::GenerationConflict))
            .count(),
        1
    );
    assert_eq!(
        authority.tenant_record("tenant-race").unwrap().unwrap().generation,
        1
    );
}
