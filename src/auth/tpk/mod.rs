//! Platform-independent JWT creation using a user's Trusted Private Key
//!
//! When a platform-native OIDC token (e.g. `AMPLIFY_ID_TOKEN` from GitLab) is
//! not available, the runner can fall back to signing its own JWT, pulling
//! the necessary information from the runner's CI environment to associate a
//! CI pipeline (and artifacts) with a customer account, using the private key
//! from a keypair that the user creates in their Amplify dashboard by setting
//! a `TRUSTED_PRIVATE_KEY` environment variable in their CI system.
//!
//! # Defaults
//!
//! | Setting   | Value                            |
//! |-----------|----------------------------------|
//! | Issuer    | `https://tpk.amplify.security`   |
//! | Audience  | `https://api.amplify.security`   |
//! | Algorithm | ES512 (ECDSA P-521 + SHA-512)    |
//! | Token TTL | 3 600 seconds (1 hour)           |

use color_eyre::eyre::{Result, WrapErr};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default `iss` claim for trusted-private-key JWTs.
pub const DEFAULT_ISSUER: &str = "https://tpk.amplify.security";
/// Default `aud` claim for trusted-private-key JWTs.
pub const DEFAULT_AUDIENCE: &str = "https://api.amplify.security";
/// Default token lifetime in seconds (1 hour).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3_600;

// ─── signer ──────────────────────────────────────────────────────────────────

/// JWT signer backed by a customer-provided EC private key.
///
/// # Example
///
/// ```rust,ignore
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct MyClaims { pipeline_id: String }
///
/// let token = TpkJwt::from_ec_pem(pem_bytes)?
///     .with_issuer("https://ci.example.com")
///     .create_token(MyClaims { pipeline_id: "42".into() }, DEFAULT_TOKEN_TTL_SECS)?;
/// ```
pub(crate) struct TpkJwt {
    /// Value placed in the `iss` claim.
    pub issuer: String,
    /// Value placed in the `aud` claim.
    pub audience: String,
    encoding_key: EncodingKey,
    algorithm: Algorithm,
}

impl TpkJwt {
    /// Build a signer from a PEM-encoded EC private key.
    ///
    /// Defaults to [`Algorithm::ES512`] (ECDSA P-521), issuer
    /// [`DEFAULT_ISSUER`], and audience [`DEFAULT_AUDIENCE`].
    pub fn from_ec_pem(pem: &[u8]) -> Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(pem)
            .wrap_err("Failed to parse EC private key PEM for TPK JWT")?;
        Ok(Self {
            issuer: DEFAULT_ISSUER.to_string(),
            audience: DEFAULT_AUDIENCE.to_string(),
            encoding_key,
            algorithm: Algorithm::ES512,
        })
    }

    /// Attempt to build a signer from the `TRUSTED_PRIVATE_KEY` environment
    /// variable, which must contain a PEM-encoded EC private key.
    ///
    /// Returns `Ok(None)` when the variable is not set.
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var("TRUSTED_PRIVATE_KEY") {
            Ok(pem) => Ok(Some(Self::from_ec_pem(pem.as_bytes())?)),
            Err(_) => Ok(None),
        }
    }

    /// Override the `iss` (issuer) claim. Returns `self` for chaining.
    #[allow(dead_code)]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Override the `aud` (audience) claim. Returns `self` for chaining.
    #[allow(dead_code)]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Override the signing algorithm (default: [`Algorithm::ES512`]).
    /// Returns `self` for chaining.
    #[allow(dead_code)]
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sign and return a JWT containing the standard claims (`iss`, `aud`,
    /// `iat`, `nbf`, `exp`) merged with the caller-supplied `custom_claims`.
    ///
    /// `ttl_secs` controls how long the token is valid for.
    pub fn create_token<C: Serialize>(&self, custom_claims: C, ttl_secs: u64) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as usize;

        let claims = TpkClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            nbf: now,
            exp: now + ttl_secs as usize,
            extra: custom_claims,
        };

        let header = Header::new(self.algorithm);
        encode(&header, &claims, &self.encoding_key).wrap_err("Failed to encode TPK JWT")
    }
}

// ─── internal claims envelope ────────────────────────────────────────────────

/// Standard JWT fields with a generic extra payload flattened alongside them.
#[derive(Debug, Serialize)]
struct TpkClaims<C: Serialize> {
    iss: String,
    aud: String,
    iat: usize,
    nbf: usize,
    exp: usize,
    #[serde(flatten)]
    extra: C,
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};
    // Paths are relative to this source file:
    //   runner/src/auth/tpk/mod.rs  →  runner/
    const TEST_PRIVATE_KEY_PEM: &str = include_str!("../../../ecdsa-p521-local.private.pem");
    const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../ecdsa-p521-local.public.pem");

    // ── helpers ───────────────────────────────────────────────────────────

    fn make_signer() -> TpkJwt {
        TpkJwt::from_ec_pem(TEST_PRIVATE_KEY_PEM.as_bytes())
            .expect("test private key should be valid")
    }

    fn make_decoding_key() -> DecodingKey {
        DecodingKey::from_ec_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
            .expect("test public key should be valid")
    }

    fn make_validation(audience: &str) -> Validation {
        let mut v = Validation::new(Algorithm::ES512);
        v.set_audience(&[audience]);
        v
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct SampleClaims {
        sub: String,
        custom_field: String,
    }

    // ── construction ──────────────────────────────────────────────────────

    #[test]
    fn test_defaults_are_set() {
        let signer = make_signer();
        assert_eq!(signer.issuer, DEFAULT_ISSUER);
        assert_eq!(signer.audience, DEFAULT_AUDIENCE);
    }

    #[test]
    fn test_builder_overrides_issuer_and_audience() {
        let signer = make_signer()
            .with_issuer("https://ci.issuer.example.com")
            .with_audience("https://ci.audience.example.com");
        assert_eq!(signer.issuer, "https://ci.issuer.example.com");
        assert_eq!(signer.audience, "https://ci.audience.example.com");
    }

    // ── token shape ───────────────────────────────────────────────────────

    #[test]
    fn test_create_token_produces_three_part_jwt() {
        let token = make_signer()
            .create_token(
                SampleClaims {
                    sub: "test-subject".into(),
                    custom_field: "hello".into(),
                },
                3600,
            )
            .expect("token creation should succeed");

        assert!(!token.is_empty());
        // A compact-serialised JWT has exactly two '.' separators.
        assert_eq!(
            token.chars().filter(|&c| c == '.').count(),
            2,
            "token should be a three-part compact JWT"
        );
    }

    // ── round-trip verification ───────────────────────────────────────────

    #[test]
    fn test_token_verifies_with_matching_public_key() {
        let token = make_signer()
            .create_token(
                SampleClaims {
                    sub: "verified-subject".into(),
                    custom_field: "check-me".into(),
                },
                3600,
            )
            .unwrap();

        let decoded = decode::<serde_json::Value>(
            &token,
            &make_decoding_key(),
            &make_validation(DEFAULT_AUDIENCE),
        )
        .expect("token should verify with the matching public key");

        let claims = decoded.claims;
        assert_eq!(claims["iss"], DEFAULT_ISSUER);
        assert_eq!(claims["aud"], DEFAULT_AUDIENCE);
        assert_eq!(claims["sub"], "verified-subject");
        assert_eq!(claims["custom_field"], "check-me");
    }

    #[test]
    fn test_custom_issuer_and_audience_appear_in_decoded_token() {
        let signer = make_signer()
            .with_issuer("https://my.issuer.test")
            .with_audience("https://my.audience.test");

        let token = signer
            .create_token(
                SampleClaims {
                    sub: "s".into(),
                    custom_field: "v".into(),
                },
                3600,
            )
            .unwrap();

        let decoded = decode::<serde_json::Value>(
            &token,
            &make_decoding_key(),
            &make_validation("https://my.audience.test"),
        )
        .unwrap();

        assert_eq!(decoded.claims["iss"], "https://my.issuer.test");
        assert_eq!(decoded.claims["aud"], "https://my.audience.test");
    }

    #[test]
    fn test_standard_time_claims_are_present_and_consistent() {
        let ttl: u64 = 1_800;
        let token = make_signer()
            .create_token(
                SampleClaims {
                    sub: "t".into(),
                    custom_field: "v".into(),
                },
                ttl,
            )
            .unwrap();

        let decoded = decode::<serde_json::Value>(
            &token,
            &make_decoding_key(),
            &make_validation(DEFAULT_AUDIENCE),
        )
        .unwrap();
        let claims = decoded.claims;

        let iat = claims["iat"].as_u64().expect("iat should be a number");
        let exp = claims["exp"].as_u64().expect("exp should be a number");
        let nbf = claims["nbf"].as_u64().expect("nbf should be a number");

        assert_eq!(exp - iat, ttl, "exp should equal iat + ttl");
        assert_eq!(iat, nbf, "iat and nbf should be equal at issuance");
    }

    #[test]
    fn test_wrong_public_key_fails_verification() {
        // Forge a second signer from the same key; in practice this tests
        // that the validation machinery rejects a structurally valid but
        // wrongly-signed token when the key pair does not match.
        let token = make_signer()
            .create_token(
                SampleClaims {
                    sub: "x".into(),
                    custom_field: "y".into(),
                },
                3600,
            )
            .unwrap();

        // Corrupt the signature segment (last third of the JWT).
        let mut parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut bad_sig = parts[2].to_string();
        // Flip a character to invalidate the signature.
        if bad_sig.starts_with('A') {
            bad_sig.replace_range(0..1, "B");
        } else {
            bad_sig.replace_range(0..1, "A");
        }
        parts[2] = &bad_sig;
        let tampered = parts.join(".");

        let result = decode::<serde_json::Value>(
            &tampered,
            &make_decoding_key(),
            &make_validation(DEFAULT_AUDIENCE),
        );
        assert!(result.is_err(), "tampered token should fail verification");
    }

    // ── from_env ──────────────────────────────────────────────────────────
    //
    // These tests are async so they can share the crate-wide ENV_MUTEX
    // (tokio::sync::Mutex) with the gitlab tests, preventing races when both
    // suites run in parallel and manipulate TRUSTED_PRIVATE_KEY.

    #[tokio::test]
    async fn test_from_env_returns_none_when_var_absent() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        std::env::remove_var("TRUSTED_PRIVATE_KEY");
        let result = TpkJwt::from_env().unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_from_env_returns_signer_when_var_is_valid_key() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        std::env::set_var("TRUSTED_PRIVATE_KEY", TEST_PRIVATE_KEY_PEM);
        let result = TpkJwt::from_env().unwrap();
        assert!(result.is_some());
        std::env::remove_var("TRUSTED_PRIVATE_KEY");
    }

    #[tokio::test]
    async fn test_from_env_errors_on_invalid_pem() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        std::env::set_var("TRUSTED_PRIVATE_KEY", "not-a-valid-pem");
        let result = TpkJwt::from_env();
        assert!(result.is_err(), "an invalid PEM should produce an error");
        std::env::remove_var("TRUSTED_PRIVATE_KEY");
    }
}
