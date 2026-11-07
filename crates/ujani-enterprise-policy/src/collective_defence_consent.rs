//! Two-party opt-in policy primitives for read-only Collective Defence telemetry.
//!
//! This module is deliberately side-effect-free. It is not a consent database,
//! identity provider, sensor, transport, ingestion service, or execution agent.
//! Production callers must load trusted keys and current generations from a
//! separately protected, durable authority; persist revocation before reporting
//! success; audit consent changes; and call the gate at both collection and
//! transmission boundaries. Missing state must be treated as denial.
//!
//! The individual signing key must be provisioned by a trusted identity system
//! and bound to the named user and device. A device key alone does not prove
//! that a human reviewed and accepted the consent notice.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey};

const TENANT_DOMAIN: &[u8] = b"UJANI-COLLECTIVE-DEFENCE-TENANT-CONSENT-V1\0";
const INDIVIDUAL_DOMAIN: &[u8] = b"UJANI-COLLECTIVE-DEFENCE-INDIVIDUAL-CONSENT-V1\0";
pub const COLLECTIVE_DEFENCE_PURPOSE: &str = "collective-defence.read-only.v1";
pub const SECURITY_EVENT_SCHEMA_VERSION: &str = "1.0";
pub const MAX_CONSENT_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_CONSENT_CLOCK_SKEW_MS: u64 = 30_000;
pub const MAX_EVENT_RETENTION_SECONDS: u32 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentError {
    InvalidIdentifier,
    InvalidPurpose,
    UnsupportedSchema,
    InvalidRetention,
    InvalidTimeWindow,
    Expired,
    UnknownSigningKey,
    InvalidSignature,
    TenantOptInRequired,
    IndividualOptInRequired,
    TenantMismatch,
    DeviceMismatch,
    PrincipalMismatch,
    PolicyGenerationMismatch,
    RevokedOrStaleGeneration,
}

/// Tenant administrator's signed, versioned feature decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantConsentClaims {
    pub tenant_id: String,
    pub enabled: bool,
    pub generation: u64,
    pub purpose: String,
    pub event_schema_version: String,
    pub retention_seconds: u32,
    pub admin_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Individual user's separate signed participation decision for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndividualConsentClaims {
    pub tenant_id: String,
    pub device_id: String,
    pub principal_id: String,
    pub enabled: bool,
    pub tenant_generation: u64,
    pub generation: u64,
    pub purpose: String,
    pub notice_version: String,
    /// SHA-256 of the exact consent notice text and data-category disclosure shown to the user.
    pub notice_sha256: [u8; 32],
    pub user_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTenantConsent {
    pub claims: TenantConsentClaims,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIndividualConsent {
    pub claims: IndividualConsentClaims,
    pub signature: [u8; 64],
}

/// Constructed only after verifying the tenant administrator's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantConsent(TenantConsentClaims);

/// Constructed only after verifying the individual user's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIndividualConsent(IndividualConsentClaims);

/// Short-lived proof that both independent opt-in gates were satisfied.
/// Fields are private so callers cannot manufacture a permit from booleans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPermit {
    tenant_id: String,
    device_id: String,
    principal_id: String,
    tenant_generation: u64,
    individual_generation: u64,
    event_schema_version: String,
    retention_seconds: u32,
    expires_at_unix_ms: u64,
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'@')
        })
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    let len = u32::try_from(value.len()).expect("bounded consent field length");
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn tenant_consent_bytes(claims: &TenantConsentClaims) -> Vec<u8> {
    let mut bytes = TENANT_DOMAIN.to_vec();
    push_string(&mut bytes, &claims.tenant_id);
    bytes.push(u8::from(claims.enabled));
    bytes.extend_from_slice(&claims.generation.to_be_bytes());
    push_string(&mut bytes, &claims.purpose);
    push_string(&mut bytes, &claims.event_schema_version);
    bytes.extend_from_slice(&claims.retention_seconds.to_be_bytes());
    push_string(&mut bytes, &claims.admin_key_id);
    bytes.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.expires_at_unix_ms.to_be_bytes());
    bytes
}

fn individual_consent_bytes(claims: &IndividualConsentClaims) -> Vec<u8> {
    let mut bytes = INDIVIDUAL_DOMAIN.to_vec();
    push_string(&mut bytes, &claims.tenant_id);
    push_string(&mut bytes, &claims.device_id);
    push_string(&mut bytes, &claims.principal_id);
    bytes.push(u8::from(claims.enabled));
    bytes.extend_from_slice(&claims.tenant_generation.to_be_bytes());
    bytes.extend_from_slice(&claims.generation.to_be_bytes());
    push_string(&mut bytes, &claims.purpose);
    push_string(&mut bytes, &claims.notice_version);
    bytes.extend_from_slice(&claims.notice_sha256);
    push_string(&mut bytes, &claims.user_key_id);
    bytes.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&claims.expires_at_unix_ms.to_be_bytes());
    bytes
}

fn validate_window(issued_at: u64, expires_at: u64, now: u64) -> Result<(), ConsentError> {
    if issued_at > now.saturating_add(MAX_CONSENT_CLOCK_SKEW_MS)
        || expires_at <= issued_at
        || expires_at.saturating_sub(issued_at) > MAX_CONSENT_TTL_MS
    {
        return Err(ConsentError::InvalidTimeWindow);
    }
    if expires_at <= now {
        return Err(ConsentError::Expired);
    }
    Ok(())
}

/// Verify a tenant administrator's opt-in using only pre-trusted admin keys.
pub fn verify_tenant_consent(
    signed: &SignedTenantConsent,
    trusted_admin_keys: &[(String, String, VerifyingKey)],
    now_unix_ms: u64,
) -> Result<VerifiedTenantConsent, ConsentError> {
    let claims = &signed.claims;
    if !valid_identifier(&claims.tenant_id, 128)
        || !valid_identifier(&claims.admin_key_id, 128)
        || claims.generation == 0
    {
        return Err(ConsentError::InvalidIdentifier);
    }
    if claims.purpose != COLLECTIVE_DEFENCE_PURPOSE {
        return Err(ConsentError::InvalidPurpose);
    }
    if claims.event_schema_version != SECURITY_EVENT_SCHEMA_VERSION {
        return Err(ConsentError::UnsupportedSchema);
    }
    if claims.retention_seconds > MAX_EVENT_RETENTION_SECONDS
        || (claims.enabled && claims.retention_seconds == 0)
    {
        return Err(ConsentError::InvalidRetention);
    }
    validate_window(
        claims.issued_at_unix_ms,
        claims.expires_at_unix_ms,
        now_unix_ms,
    )?;

    let key = trusted_admin_keys
        .iter()
        .find(|(key_id, tenant_id, _)| {
            key_id == &claims.admin_key_id && tenant_id == &claims.tenant_id
        })
        .map(|(_, _, key)| key)
        .ok_or(ConsentError::UnknownSigningKey)?;
    key.verify_strict(
        &tenant_consent_bytes(claims),
        &Signature::from_bytes(&signed.signature),
    )
    .map_err(|_| ConsentError::InvalidSignature)?;

    if !claims.enabled {
        return Err(ConsentError::TenantOptInRequired);
    }
    Ok(VerifiedTenantConsent(claims.clone()))
}

/// Verify a user's independent opt-in using an identity-provider-trusted key.
pub fn verify_individual_consent(
    signed: &SignedIndividualConsent,
    trusted_user_keys: &[(String, String, String, String, VerifyingKey)],
    now_unix_ms: u64,
) -> Result<VerifiedIndividualConsent, ConsentError> {
    let claims = &signed.claims;
    if !valid_identifier(&claims.tenant_id, 128)
        || !valid_identifier(&claims.device_id, 128)
        || !valid_identifier(&claims.principal_id, 128)
        || !valid_identifier(&claims.user_key_id, 128)
        || !valid_identifier(&claims.notice_version, 64)
        || claims.notice_sha256.iter().all(|byte| *byte == 0)
        || claims.tenant_generation == 0
        || claims.generation == 0
    {
        return Err(ConsentError::InvalidIdentifier);
    }
    if claims.purpose != COLLECTIVE_DEFENCE_PURPOSE {
        return Err(ConsentError::InvalidPurpose);
    }
    validate_window(
        claims.issued_at_unix_ms,
        claims.expires_at_unix_ms,
        now_unix_ms,
    )?;

    let key = trusted_user_keys
        .iter()
        .find(|(key_id, tenant_id, device_id, principal_id, _)| {
            key_id == &claims.user_key_id
                && tenant_id == &claims.tenant_id
                && device_id == &claims.device_id
                && principal_id == &claims.principal_id
        })
        .map(|(_, _, _, _, key)| key)
        .ok_or(ConsentError::UnknownSigningKey)?;
    key.verify_strict(
        &individual_consent_bytes(claims),
        &Signature::from_bytes(&signed.signature),
    )
    .map_err(|_| ConsentError::InvalidSignature)?;

    if !claims.enabled {
        return Err(ConsentError::IndividualOptInRequired);
    }
    Ok(VerifiedIndividualConsent(claims.clone()))
}

/// Require both verified opt-ins and the current authoritative revocation generations.
///
/// The current generations must come from a durable, rollback-resistant control-plane
/// store. A mismatch means consent was withdrawn, the tenant policy changed, or the
/// caller supplied stale state; every such case fails closed.
pub fn authorize_event_sharing(
    tenant: &VerifiedTenantConsent,
    individual: &VerifiedIndividualConsent,
    expected_tenant_id: &str,
    expected_device_id: &str,
    current_tenant_generation: u64,
    current_individual_generation: u64,
    now_unix_ms: u64,
) -> Result<ConsentPermit, ConsentError> {
    let tenant_claims = &tenant.0;
    let individual_claims = &individual.0;

    if tenant_claims.tenant_id != expected_tenant_id
        || individual_claims.tenant_id != expected_tenant_id
    {
        return Err(ConsentError::TenantMismatch);
    }
    if individual_claims.device_id != expected_device_id {
        return Err(ConsentError::DeviceMismatch);
    }
    if individual_claims.tenant_generation != tenant_claims.generation {
        return Err(ConsentError::PolicyGenerationMismatch);
    }
    if tenant_claims.generation != current_tenant_generation
        || individual_claims.generation != current_individual_generation
    {
        return Err(ConsentError::RevokedOrStaleGeneration);
    }
    if tenant_claims.expires_at_unix_ms <= now_unix_ms
        || individual_claims.expires_at_unix_ms <= now_unix_ms
    {
        return Err(ConsentError::Expired);
    }

    Ok(ConsentPermit {
        tenant_id: expected_tenant_id.to_owned(),
        device_id: expected_device_id.to_owned(),
        principal_id: individual_claims.principal_id.clone(),
        tenant_generation: current_tenant_generation,
        individual_generation: current_individual_generation,
        event_schema_version: tenant_claims.event_schema_version.clone(),
        retention_seconds: tenant_claims.retention_seconds,
        expires_at_unix_ms: tenant_claims
            .expires_at_unix_ms
            .min(individual_claims.expires_at_unix_ms),
    })
}

impl ConsentPermit {
    /// Re-check immediately before transmission using freshly loaded generations.
    pub fn is_current(
        &self,
        tenant_id: &str,
        device_id: &str,
        current_tenant_generation: u64,
        current_individual_generation: u64,
        now_unix_ms: u64,
    ) -> bool {
        self.tenant_id == tenant_id
            && self.device_id == device_id
            && self.tenant_generation == current_tenant_generation
            && self.individual_generation == current_individual_generation
            && now_unix_ms < self.expires_at_unix_ms
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn event_schema_version(&self) -> &str {
        &self.event_schema_version
    }

    pub fn retention_seconds(&self) -> u32 {
        self.retention_seconds
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_000_000;
    const EXPIRY: u64 = NOW + 60_000;

    fn signed_tenant(
        key: &SigningKey,
        enabled: bool,
        generation: u64,
        expires_at: u64,
    ) -> SignedTenantConsent {
        let claims = TenantConsentClaims {
            tenant_id: "tenant-a".into(),
            enabled,
            generation,
            purpose: COLLECTIVE_DEFENCE_PURPOSE.into(),
            event_schema_version: SECURITY_EVENT_SCHEMA_VERSION.into(),
            retention_seconds: if enabled { 86_400 } else { 0 },
            admin_key_id: "tenant-admin-key".into(),
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: expires_at,
        };
        SignedTenantConsent {
            signature: key.sign(&tenant_consent_bytes(&claims)).to_bytes(),
            claims,
        }
    }

    fn signed_individual(
        key: &SigningKey,
        enabled: bool,
        tenant_generation: u64,
        generation: u64,
        expires_at: u64,
    ) -> SignedIndividualConsent {
        let claims = IndividualConsentClaims {
            tenant_id: "tenant-a".into(),
            device_id: "device-01".into(),
            principal_id: "user-01".into(),
            enabled,
            tenant_generation,
            generation,
            purpose: COLLECTIVE_DEFENCE_PURPOSE.into(),
            notice_version: "notice-v1".into(),
            notice_sha256: [3u8; 32],
            user_key_id: "user-consent-key".into(),
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: expires_at,
        };
        SignedIndividualConsent {
            signature: key.sign(&individual_consent_bytes(&claims)).to_bytes(),
            claims,
        }
    }

    fn keys() -> (
        SigningKey,
        SigningKey,
        Vec<(String, String, VerifyingKey)>,
        Vec<(String, String, String, String, VerifyingKey)>,
    ) {
        let admin = SigningKey::from_bytes(&[7u8; 32]);
        let user = SigningKey::from_bytes(&[9u8; 32]);
        let admins = vec![(
            "tenant-admin-key".into(),
            "tenant-a".into(),
            admin.verifying_key(),
        )];
        let users = vec![(
            "user-consent-key".into(),
            "tenant-a".into(),
            "device-01".into(),
            "user-01".into(),
            user.verifying_key(),
        )];
        (admin, user, admins, users)
    }

    fn permit() -> ConsentPermit {
        let (admin, user, admins, users) = keys();
        let tenant =
            verify_tenant_consent(&signed_tenant(&admin, true, 4, EXPIRY), &admins, NOW).unwrap();
        let individual =
            verify_individual_consent(&signed_individual(&user, true, 4, 2, EXPIRY), &users, NOW)
                .unwrap();
        authorize_event_sharing(&tenant, &individual, "tenant-a", "device-01", 4, 2, NOW).unwrap()
    }

    #[test]
    fn tenant_opt_in_alone_never_enrols_an_individual() {
        let (admin, user, admins, users) = keys();
        let tenant = verify_tenant_consent(&signed_tenant(&admin, true, 4, EXPIRY), &admins, NOW).unwrap();
        let individual = signed_individual(&user, false, 4, 2, EXPIRY);
        assert_eq!(
            verify_individual_consent(&individual, &users, NOW),
            Err(ConsentError::IndividualOptInRequired)
        );
        assert!(authorize_event_sharing(
            &tenant,
            &verify_individual_consent(&signed_individual(&user, true, 4, 2, EXPIRY), &users, NOW)
                .unwrap(),
            "tenant-a",
            "device-01",
            4,
            2,
            NOW
        )
        .is_ok());
    }

    #[test]
    fn individual_opt_in_cannot_override_tenant_default_off() {
        let (admin, user, admins, users) = keys();
        assert_eq!(
            verify_tenant_consent(&signed_tenant(&admin, false, 4, EXPIRY), &admins, NOW),
            Err(ConsentError::TenantOptInRequired)
        );
        assert!(verify_individual_consent(
            &signed_individual(&user, true, 4, 2, EXPIRY),
            &users,
            NOW
        )
        .is_ok());
    }

    #[test]
    fn both_independent_signatures_are_required_and_bound_to_tenant_and_device() {
        let p = permit();
        assert_eq!(p.tenant_id(), "tenant-a");
        assert_eq!(p.device_id(), "device-01");
        assert_eq!(p.principal_id(), "user-01");
        assert_eq!(p.event_schema_version(), "1.0");
        assert_eq!(p.retention_seconds(), 86_400);
        let (admin, user, admins, users) = keys();
        let tenant = verify_tenant_consent(&signed_tenant(&admin, true, 4, EXPIRY), &admins, NOW).unwrap();
        let individual =
            verify_individual_consent(&signed_individual(&user, true, 4, 2, EXPIRY), &users, NOW)
                .unwrap();
        assert_eq!(
            authorize_event_sharing(&tenant, &individual, "tenant-b", "device-01", 4, 2, NOW),
            Err(ConsentError::TenantMismatch)
        );
        assert_eq!(
            authorize_event_sharing(&tenant, &individual, "tenant-a", "device-02", 4, 2, NOW),
            Err(ConsentError::DeviceMismatch)
        );
    }

    #[test]
    fn tenant_disable_or_individual_withdrawal_invalidates_existing_permit_generation() {
        let p = permit();
        assert!(!p.is_current("tenant-a", "device-01", 5, 2, NOW));
        assert!(!p.is_current("tenant-a", "device-01", 4, 3, NOW));
        assert!(!p.is_current("tenant-b", "device-01", 4, 2, NOW));
        assert!(!p.is_current("tenant-a", "device-02", 4, 2, NOW));
    }

    #[test]
    fn permit_expires_at_the_earlier_of_both_signed_consents() {
        let (admin, user, admins, users) = keys();
        let tenant = verify_tenant_consent(&signed_tenant(&admin, true, 4, EXPIRY), &admins, NOW).unwrap();
        let individual = verify_individual_consent(
            &signed_individual(&user, true, 4, 2, NOW + 30_000), &users, NOW
        ).unwrap();
        let p =
            authorize_event_sharing(&tenant, &individual, "tenant-a", "device-01", 4, 2, NOW)
                .unwrap();
        assert_eq!(p.expires_at_unix_ms(), NOW + 30_000);
        assert!(!p.is_current("tenant-a", "device-01", 4, 2, NOW + 30_000));
    }

    #[test]
    fn stale_generations_and_policy_generation_mismatch_fail_closed() {
        let (admin, user, admins, users) = keys();
        let tenant = verify_tenant_consent(&signed_tenant(&admin, true, 4, EXPIRY), &admins, NOW).unwrap();
        let individual = verify_individual_consent(
            &signed_individual(&user, true, 3, 2, EXPIRY), &users, NOW
        ).unwrap();
        assert_eq!(
            authorize_event_sharing(&tenant, &individual, "tenant-a", "device-01", 4, 2, NOW),
            Err(ConsentError::PolicyGenerationMismatch)
        );
        let individual =
            verify_individual_consent(&signed_individual(&user, true, 4, 2, EXPIRY), &users, NOW)
                .unwrap();
        assert_eq!(
            authorize_event_sharing(&tenant, &individual, "tenant-a", "device-01", 5, 2, NOW),
            Err(ConsentError::RevokedOrStaleGeneration)
        );
        assert_eq!(
            authorize_event_sharing(&tenant, &individual, "tenant-a", "device-01", 4, 3, NOW),
            Err(ConsentError::RevokedOrStaleGeneration)
        );
    }

    #[test]
    fn expired_or_excessively_long_consent_tokens_are_rejected() {
        let (admin, user, admins, users) = keys();
        assert_eq!(
            verify_tenant_consent(&signed_tenant(&admin, true, 4, NOW), &admins, NOW),
            Err(ConsentError::InvalidTimeWindow)
        );
        let long = signed_tenant(&admin, true, 4, NOW + MAX_CONSENT_TTL_MS + 1);
        assert_eq!(
            verify_tenant_consent(&long, &admins, NOW),
            Err(ConsentError::InvalidTimeWindow)
        );
        let individual = signed_individual(&user, true, 4, 2, NOW);
        assert_eq!(
            verify_individual_consent(&individual, &users, NOW),
            Err(ConsentError::InvalidTimeWindow)
        );
    }

    #[test]
    fn tampered_consent_and_untrusted_signing_keys_are_rejected() {
        let (admin, user, admins, users) = keys();
        let mut tenant = signed_tenant(&admin, true, 4, EXPIRY);
        tenant.claims.enabled = false;
        assert_eq!(
            verify_tenant_consent(&tenant, &admins, NOW),
            Err(ConsentError::InvalidSignature)
        );
        let individual = signed_individual(&user, true, 4, 2, EXPIRY);
        assert_eq!(
            verify_individual_consent(&individual, &[], NOW),
            Err(ConsentError::UnknownSigningKey)
        );
    }

    #[test]
    fn invalid_retention_and_schema_versions_are_rejected() {
        let (admin, _, admins, _) = keys();
        let mut tenant = signed_tenant(&admin, true, 4, EXPIRY);
        tenant.claims.retention_seconds = MAX_EVENT_RETENTION_SECONDS + 1;
        tenant.signature = admin.sign(&tenant_consent_bytes(&tenant.claims)).to_bytes();
        assert_eq!(
            verify_tenant_consent(&tenant, &admins, NOW),
            Err(ConsentError::InvalidRetention)
        );
        let mut tenant = signed_tenant(&admin, true, 4, EXPIRY);
        tenant.claims.event_schema_version = "2.0".into();
        tenant.signature = admin.sign(&tenant_consent_bytes(&tenant.claims)).to_bytes();
        assert_eq!(
            verify_tenant_consent(&tenant, &admins, NOW),
            Err(ConsentError::UnsupportedSchema)
        );
    }
    #[test]
    fn trusted_consent_keys_cannot_be_reused_across_tenants_or_principals() {
        let (admin, user, admins, users) = keys();
        let mut tenant = signed_tenant(&admin, true, 4, EXPIRY);
        tenant.claims.tenant_id = "tenant-b".into();
        tenant.signature = admin.sign(&tenant_consent_bytes(&tenant.claims)).to_bytes();
        assert_eq!(
            verify_tenant_consent(&tenant, &admins, NOW),
            Err(ConsentError::UnknownSigningKey)
        );

        let mut individual = signed_individual(&user, true, 4, 2, EXPIRY);
        individual.claims.principal_id = "user-02".into();
        individual.signature = user
            .sign(&individual_consent_bytes(&individual.claims))
            .to_bytes();
        assert_eq!(
            verify_individual_consent(&individual, &users, NOW),
            Err(ConsentError::UnknownSigningKey)
        );
    }

    #[test]
    fn consent_must_bind_the_exact_nonzero_notice_digest() {
        let (admin, user, admins, users) = keys();
        let mut individual = signed_individual(&user, true, 4, 2, EXPIRY);
        individual.claims.notice_sha256 = [0u8; 32];
        individual.signature = user.sign(&individual_consent_bytes(&individual.claims)).to_bytes();
        assert_eq!(
            verify_individual_consent(&individual, &users, NOW),
            Err(ConsentError::InvalidIdentifier)
        );
        let tenant =
            verify_tenant_consent(&signed_tenant(&admin, true, 4, EXPIRY), &admins, NOW).unwrap();
        assert_eq!(tenant.0.tenant_id, "tenant-a");
    }
}
