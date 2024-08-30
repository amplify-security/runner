//! Authentication/JWT stuff for Github Actions
//!
//! Is there anything else I need to write?

use color_eyre::eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub(crate) struct GithubAuth {
    pub oidc_request_url: String,
    pub oidc_bearer_token: String,
    pub oidc_audience: String,
    pub jwt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenResponse {
    value: String,
}

impl GithubAuth {
    pub fn new(audience: impl Into<String>) -> Result<GithubAuth> {
        let actions_id_token_request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").wrap_err("Could not find `ACTIONS_ID_TOKEN_REQUEST_TOKEN` in the environment. Ensure that your workflow has a permissions setting with `id-token: write`.")?;
        let actions_id_token_request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .wrap_err("Could not find `ACTIONS_ID_TOKEN_REQUEST_URL` in the environment.")?;
        Ok(GithubAuth {
            oidc_request_url: actions_id_token_request_url,
            oidc_bearer_token: actions_id_token_request_token,
            oidc_audience: audience.into(),
            jwt: None,
        })
    }

    pub async fn get_token(&mut self) -> Result<String> {
        let client = crate::common::new_http_client();
        let res = client
            .get(format!(
                "{url}&audience={audience}",
                url = &self.oidc_request_url,
                audience = &self.oidc_audience
            ))
            .bearer_auth(&self.oidc_bearer_token)
            .send()
            .await
            .wrap_err("Couldn't get ID token from GitHub.")?;
        if res.status().is_success() {
            let token_data = res
                .json::<IdTokenResponse>()
                .await
                .wrap_err("Failed to process JWT response body from Github's.")?;
            self.jwt = Some(token_data.value);
            return Ok(self.jwt.clone().unwrap());
        }

        Err(eyre!("Failed to mint an OIDC token from Github."))
    }
}
