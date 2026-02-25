//! Authentication for GitLab CI pipelines.
//!
//! Token resolution order:
//!
//! 1. **`AMPLIFY_ID_TOKEN`** – an OIDC ID token issued by GitLab itself.
//!    This token is automatically configured in Amplify's runner component
//!    and should be preferred when in use.
//! 2. **`TRUSTED_PRIVATE_KEY`** – a PEM-encoded private key supplied by the
//!    user that is configured in Amplify. The runner signs its own JWT and
//!    includes a set of GitLab predefined CI/CD variables as claims so that
//!    the Amplify API can identify the pipeline and project.

use color_eyre::eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};

use crate::auth::tpk::{TpkJwt, DEFAULT_TOKEN_TTL_SECS};

// ─── auth provider ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct GitlabAuth {
    pub jwt: Option<String>,
}

impl GitlabAuth {
    pub fn new() -> Result<GitlabAuth> {
        Ok(GitlabAuth { jwt: None })
    }

    /// Return a bearer token that identifies this pipeline run to the Amplify API.
    pub async fn get_token(&mut self) -> Result<String> {
        if let Ok(token) = std::env::var("AMPLIFY_ID_TOKEN") {
            self.jwt = Some(token.clone());
            return Ok(token);
        }

        if let Some(signer) =
            TpkJwt::from_env().wrap_err("Failed to load TRUSTED_PRIVATE_KEY for GitLab TPK JWT")?
        {
            let claims = GitlabTpkClaims::from_env()
                .wrap_err("Failed to read required GitLab CI variables for TPK JWT")?;
            let token = signer
                .create_token(claims, DEFAULT_TOKEN_TTL_SECS)
                .wrap_err("Failed to sign GitLab TPK JWT")?;
            self.jwt = Some(token.clone());
            return Ok(token);
        }

        Err(color_eyre::eyre::eyre!(
            "No GitLab ID token found. \
             Either use the amplify-security/components/runner component in \
             your `.gitlab-ci.yml`, or create a keypair in Amplify and \
             configure `TRUSTED_PRIVATE_KEY` to the private key in your CI \
             environment variables."
        ))
    }
}

/// JWT payload for the Trusted Public Key fallback path.
///
/// The field names match the claim names used in real GitLab OIDC ID tokens so
/// that the Amplify API can handle both token kinds uniformly.
#[derive(Debug, Serialize, Deserialize)]
struct GitlabTpkClaims {
    /// URL of the GitLab instance (`CI_SERVER_URL`).
    /// e.g. `"https://gitlab.com"` or `"https://gitlab.example.com:8080"`.
    ci_server_url: String,

    /// Instance-level pipeline ID (`CI_PIPELINE_ID`).
    pipeline_id: String,

    /// Instance-level project ID (`CI_PROJECT_ID`).
    project_id: String,

    /// Namespace + project path (`CI_PROJECT_PATH`), e.g. `"my-group/my-project"`.
    project_path: String,

    /// The branch or tag name (`CI_COMMIT_REF_NAME`).
    /// Renamed to `ref` to match the GitLab OIDC token schema.
    #[serde(rename = "ref")]
    git_ref: String,

    /// Instance-level job ID (`CI_JOB_ID`).
    job_id: String,

    /// Full commit SHA (`CI_COMMIT_SHA`).
    sha: String,
}

impl GitlabTpkClaims {
    /// Populate claims from the current process environment.
    ///
    /// All fields are required. Every variable listed here is a predefined
    /// GitLab CI/CD variable that is always present in any GitLab CI job.
    fn from_env() -> Result<Self> {
        Ok(Self {
            ci_server_url: std::env::var("CI_SERVER_URL")
                .wrap_err("Expected CI_SERVER_URL to be set, but it wasn't!")?,
            pipeline_id: std::env::var("CI_PIPELINE_ID")
                .wrap_err("Expected CI_PIPELINE_ID to be set, but it wasn't!")?,
            project_id: std::env::var("CI_PROJECT_ID")
                .wrap_err("Expected CI_PROJECT_ID to be set, but it wasn't!")?,
            project_path: std::env::var("CI_PROJECT_PATH")
                .wrap_err("Expected CI_PROJECT_PATH to be set, but it wasn't!")?,
            git_ref: std::env::var("CI_COMMIT_REF_NAME")
                .wrap_err("Expected CI_COMMIT_REF_NAME to be set, but it wasn't!")?,
            job_id: std::env::var("CI_JOB_ID")
                .wrap_err("Expected CI_JOB_ID to be set, but it wasn't!")?,
            sha: std::env::var("CI_COMMIT_SHA")
                .wrap_err("Expected CI_COMMIT_SHA to be set, but it wasn't!")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    const TEST_PRIVATE_KEY_PEM: &str = include_str!("../../../ecdsa-p521-local.private.pem");
    const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../ecdsa-p521-local.public.pem");

    fn set_all_gitlab_vars() {
        std::env::set_var("CI_SERVER_URL", "https://gitlab.example.com");
        std::env::set_var("CI_PIPELINE_ID", "1001");
        std::env::set_var("CI_PROJECT_ID", "42");
        std::env::set_var("CI_PROJECT_PATH", "my-group/my-project");
        std::env::set_var("CI_COMMIT_REF_NAME", "main");
        std::env::set_var("CI_JOB_ID", "9999");
        std::env::set_var("CI_COMMIT_SHA", "abc123def456");
    }

    fn clear_all_vars() {
        std::env::remove_var("AMPLIFY_ID_TOKEN");
        std::env::remove_var("TRUSTED_PRIVATE_KEY");
        std::env::remove_var("CI_SERVER_URL");
        std::env::remove_var("CI_PIPELINE_ID");
        std::env::remove_var("CI_PROJECT_ID");
        std::env::remove_var("CI_PROJECT_PATH");
        std::env::remove_var("CI_COMMIT_REF_NAME");
        std::env::remove_var("CI_JOB_ID");
        std::env::remove_var("CI_COMMIT_SHA");
    }

    fn make_validation() -> Validation {
        let mut v = Validation::new(Algorithm::ES512);
        v.set_audience(&[crate::auth::tpk::DEFAULT_AUDIENCE]);
        v
    }

    // AMPLIFY_ID_TOKEN usage (from runner component)

    #[tokio::test]
    async fn test_amplify_id_token_is_returned_directly() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        clear_all_vars();
        std::env::set_var("AMPLIFY_ID_TOKEN", "gitlab.issued.token");

        let mut auth = GitlabAuth::new().unwrap();
        let token = auth.get_token().await.unwrap();

        assert_eq!(token, "gitlab.issued.token");
    }

    #[tokio::test]
    async fn test_amplify_id_token_is_cached_on_auth_struct() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        clear_all_vars();
        std::env::set_var("AMPLIFY_ID_TOKEN", "cached.token");

        let mut auth = GitlabAuth::new().unwrap();
        auth.get_token().await.unwrap();

        assert_eq!(auth.jwt.as_deref(), Some("cached.token"));
    }

    // TPK Fallback

    #[tokio::test]
    async fn test_tpk_fallback_produces_valid_jwt() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        clear_all_vars();
        set_all_gitlab_vars();
        std::env::set_var("TRUSTED_PRIVATE_KEY", TEST_PRIVATE_KEY_PEM);

        let mut auth = GitlabAuth::new().unwrap();
        let token = auth.get_token().await.unwrap();

        let decoding_key = DecodingKey::from_ec_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let decoded =
            decode::<serde_json::Value>(&token, &decoding_key, &make_validation()).unwrap();
        let claims = decoded.claims;

        assert_eq!(claims["ci_server_url"], "https://gitlab.example.com");
        assert_eq!(claims["pipeline_id"], "1001");
        assert_eq!(claims["project_id"], "42");
        assert_eq!(claims["project_path"], "my-group/my-project");
        assert_eq!(claims["ref"], "main");
        assert_eq!(claims["job_id"], "9999");
        assert_eq!(claims["sha"], "abc123def456");
    }

    #[tokio::test]
    async fn test_tpk_fallback_uses_correct_issuer_and_audience() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        clear_all_vars();
        set_all_gitlab_vars();
        std::env::set_var("TRUSTED_PRIVATE_KEY", TEST_PRIVATE_KEY_PEM);

        let mut auth = GitlabAuth::new().unwrap();
        let token = auth.get_token().await.unwrap();

        let decoding_key = DecodingKey::from_ec_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let decoded =
            decode::<serde_json::Value>(&token, &decoding_key, &make_validation()).unwrap();
        let claims = decoded.claims;

        assert_eq!(claims["iss"], crate::auth::tpk::DEFAULT_ISSUER);
        assert_eq!(claims["aud"], crate::auth::tpk::DEFAULT_AUDIENCE);
    }

    #[tokio::test]
    async fn test_tpk_fallback_token_is_cached_on_auth_struct() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        clear_all_vars();
        set_all_gitlab_vars();
        std::env::set_var("TRUSTED_PRIVATE_KEY", TEST_PRIVATE_KEY_PEM);

        let mut auth = GitlabAuth::new().unwrap();
        let token = auth.get_token().await.unwrap();

        assert_eq!(auth.jwt.as_deref(), Some(token.as_str()));
    }

    // Error Cases

    #[tokio::test]
    async fn test_error_when_neither_token_source_is_available() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;
        clear_all_vars();

        let mut auth = GitlabAuth::new().unwrap();
        let result = auth.get_token().await;

        assert!(
            result.is_err(),
            "should fail when no token source is configured"
        );
    }

    #[tokio::test]
    async fn test_error_when_tpk_present_but_ci_var_missing() {
        let _lock = crate::common::test_support::ENV_MUTEX.lock().await;

        // Each predefined GitLab CI variable is required; verify that omitting
        // any one of them produces an error.
        let all_vars = [
            "CI_SERVER_URL",
            "CI_PIPELINE_ID",
            "CI_PROJECT_ID",
            "CI_PROJECT_PATH",
            "CI_COMMIT_REF_NAME",
            "CI_JOB_ID",
            "CI_COMMIT_SHA",
        ];

        for omit in all_vars {
            clear_all_vars();
            set_all_gitlab_vars();
            std::env::remove_var(omit);
            std::env::set_var("TRUSTED_PRIVATE_KEY", TEST_PRIVATE_KEY_PEM);

            let mut auth = GitlabAuth::new().unwrap();
            let result = auth.get_token().await;

            assert!(result.is_err(), "should fail when {omit} is missing");
        }
    }
}
