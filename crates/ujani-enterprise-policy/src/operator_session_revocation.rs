//! Durable revocation boundary for short-lived Enterprise operator sessions.
//!
//! Session signing-key rotation can revoke a whole key, but operators also need
//! targeted logout. This module adds a tenant/subject/nonce-scoped persistence
//! contract. The current verifier wrapper represents user logout; administrative
//! incident reasons require an actor-aware host extension. It does not implement a
//! database, identity provider, HTTP endpoint or browser session handling.

use crate::operator_control_plane::{
    OperatorAuthError, OperatorSessionClaims, OperatorSessionVerifier,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRevocationStoreError {
    Unavailable,
    IntegrityFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRevocationError {
    InvalidOrExpiredSession,
    StoreUnavailable,
}

/// Customer-hosted durable revocation store.
///
/// Implementations must key records by the complete tuple
/// (tenant_id, subject_id, nonce), persist the session expiry, and provide
/// durable, cross-process visibility. `revoke` must be idempotent. A failed
/// read or write must never be interpreted as "not revoked".
pub trait OperatorSessionRevocationStore: Send + Sync {
    fn is_revoked(
        &self,
        tenant_id: &str,
        subject_id: &str,
        nonce: &[u8; 16],
        now_unix_ms: u64,
    ) -> Result<bool, SessionRevocationStoreError>;

    fn revoke(
        &self,
        tenant_id: &str,
        subject_id: &str,
        nonce: &[u8; 16],
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), SessionRevocationStoreError>;
}

/// Decorates an existing trusted session verifier with fail-closed revocation.
///
/// Check this wrapper on every authenticated request. The underlying verifier
/// remains responsible for signature, issuer/identity-provider trust, expiry,
/// key rotation and claim validation.
pub struct RevocableOperatorSessionVerifier<V, R> {
    inner: V,
    revocations: R,
}

impl<V, R> RevocableOperatorSessionVerifier<V, R> {
    pub fn new(inner: V, revocations: R) -> Self {
        Self { inner, revocations }
    }

    /// Revoke a currently valid session token. The token is verified first so
    /// callers cannot insert arbitrary tenant, subject or nonce values.
    pub fn revoke_token(&self, token: &str, now_unix_ms: u64) -> Result<(), SessionRevocationError>
    where
        V: OperatorSessionVerifier,
        R: OperatorSessionRevocationStore,
    {
        let claims = self
            .inner
            .verify_session(token, now_unix_ms)
            .map_err(|_| SessionRevocationError::InvalidOrExpiredSession)?;
        validate_revocation_claims(&claims, now_unix_ms)?;
        self.revocations
            .revoke(
                &claims.tenant_id,
                &claims.subject_id,
                &claims.nonce,
                claims.expires_at_unix_ms,
                now_unix_ms,
            )
            .map_err(|_| SessionRevocationError::StoreUnavailable)
    }
}

fn validate_revocation_claims(
    claims: &OperatorSessionClaims,
    now_unix_ms: u64,
) -> Result<(), SessionRevocationError> {
    if claims.tenant_id.is_empty()
        || claims.subject_id.is_empty()
        || claims.nonce.iter().all(|byte| *byte == 0)
        || claims.expires_at_unix_ms <= now_unix_ms
    {
        return Err(SessionRevocationError::InvalidOrExpiredSession);
    }
    Ok(())
}

impl<V, R> OperatorSessionVerifier for RevocableOperatorSessionVerifier<V, R>
where
    V: OperatorSessionVerifier,
    R: OperatorSessionRevocationStore,
{
    fn verify_session(
        &self,
        token: &str,
        now_unix_ms: u64,
    ) -> Result<OperatorSessionClaims, OperatorAuthError> {
        let claims = self.inner.verify_session(token, now_unix_ms)?;
        if validate_revocation_claims(&claims, now_unix_ms).is_err() {
            return Err(OperatorAuthError::InvalidClaims);
        }
        match self.revocations.is_revoked(
            &claims.tenant_id,
            &claims.subject_id,
            &claims.nonce,
            now_unix_ms,
        ) {
            Ok(false) => Ok(claims),
            // A revoked session and an unavailable/integrity-failed store both
            // deny access. Do not reveal revocation state to an unauthenticated caller.
            Ok(true) | Err(_) => Err(OperatorAuthError::InvalidClaims),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct TestVerifier {
        claims: OperatorSessionClaims,
    }

    impl OperatorSessionVerifier for TestVerifier {
        fn verify_session(
            &self,
            token: &str,
            _now_unix_ms: u64,
        ) -> Result<OperatorSessionClaims, OperatorAuthError> {
            if token == "valid-test-token" {
                Ok(self.claims.clone())
            } else {
                Err(OperatorAuthError::InvalidSignature)
            }
        }
    }

    #[derive(Default)]
    struct MemoryRevocations {
        entries: Mutex<HashSet<(String, String, [u8; 16])>>,
        unavailable: bool,
    }

    impl OperatorSessionRevocationStore for MemoryRevocations {
        fn is_revoked(
            &self,
            tenant_id: &str,
            subject_id: &str,
            nonce: &[u8; 16],
            _now_unix_ms: u64,
        ) -> Result<bool, SessionRevocationStoreError> {
            if self.unavailable {
                return Err(SessionRevocationStoreError::Unavailable);
            }
            let entries = self
                .entries
                .lock()
                .map_err(|_| SessionRevocationStoreError::IntegrityFailure)?;
            Ok(entries.contains(&(tenant_id.into(), subject_id.into(), *nonce)))
        }

        fn revoke(
            &self,
            tenant_id: &str,
            subject_id: &str,
            nonce: &[u8; 16],
            expires_at_unix_ms: u64,
            now_unix_ms: u64,
        ) -> Result<(), SessionRevocationStoreError> {
            if self.unavailable {
                return Err(SessionRevocationStoreError::Unavailable);
            }
            if expires_at_unix_ms <= now_unix_ms {
                return Err(SessionRevocationStoreError::IntegrityFailure);
            }
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| SessionRevocationStoreError::IntegrityFailure)?;
            entries.insert((tenant_id.into(), subject_id.into(), *nonce));
            Ok(())
        }
    }

    fn test_nonce() -> [u8; 16] {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos()
            .to_le_bytes()
    }

    fn verifier() -> TestVerifier {
        TestVerifier {
            claims: OperatorSessionClaims {
                subject_id: "operator-1".into(),
                tenant_id: "tenant-1".into(),
                role: crate::operator_control_plane::OperatorRole::Administrator,
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 900_000,
                nonce: test_nonce(),
            },
        }
    }

    #[test]
    fn session_is_accepted_until_explicitly_revoked() {
        let wrapped =
            RevocableOperatorSessionVerifier::new(verifier(), MemoryRevocations::default());
        assert!(wrapped.verify_session("valid-test-token", 2_000).is_ok());
        assert_eq!(wrapped.revoke_token("valid-test-token", 2_001), Ok(()));
        assert_eq!(
            wrapped.verify_session("valid-test-token", 2_002),
            Err(OperatorAuthError::InvalidClaims)
        );
    }

    #[test]
    fn revocation_store_failure_denies_authentication() {
        let wrapped = RevocableOperatorSessionVerifier::new(
            verifier(),
            MemoryRevocations {
                unavailable: true,
                ..MemoryRevocations::default()
            },
        );
        assert_eq!(
            wrapped.verify_session("valid-test-token", 2_000),
            Err(OperatorAuthError::InvalidClaims)
        );
        assert_eq!(
            wrapped.revoke_token("valid-test-token", 2_001),
            Err(SessionRevocationError::StoreUnavailable)
        );
    }

    #[test]
    fn invalid_tokens_cannot_revoke_arbitrary_sessions() {
        let wrapped =
            RevocableOperatorSessionVerifier::new(verifier(), MemoryRevocations::default());
        assert_eq!(
            wrapped.revoke_token("attacker-controlled", 2_000),
            Err(SessionRevocationError::InvalidOrExpiredSession)
        );
    }

    #[test]
    fn revocation_is_scoped_to_tenant_subject_and_nonce() {
        let store = MemoryRevocations::default();
        let nonce = test_nonce();
        let mut other_nonce = nonce;
        other_nonce[0] = other_nonce[0].wrapping_add(1);
        store
            .revoke("tenant-1", "operator-1", &nonce, 900_000, 2_000)
            .unwrap();
        assert!(store
            .is_revoked("tenant-1", "operator-1", &nonce, 2_001)
            .unwrap());
        assert!(!store
            .is_revoked("tenant-2", "operator-1", &nonce, 2_001)
            .unwrap());
        assert!(!store
            .is_revoked("tenant-1", "operator-2", &nonce, 2_001)
            .unwrap());
        assert!(!store
            .is_revoked("tenant-1", "operator-1", &other_nonce, 2_001)
            .unwrap());
    }
}
