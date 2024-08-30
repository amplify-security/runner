//! Authentication/JWT stuff for Amplify
//!
//! WIP

use color_eyre::eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub(crate) struct AmplifyAuth {
    pub endpoint: String,
    pub provider_token: String,
    pub jwt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JWTResponse {
    token: String,
}

impl AmplifyAuth {
    pub fn new(endpoint: String, provider_token: String) -> Result<AmplifyAuth> {
        Ok(AmplifyAuth {
            endpoint,
            provider_token,
            jwt: None,
        })
    }

    pub async fn get_token(&mut self) -> Result<String> {
        let client = crate::common::new_http_client();
        let res = client
            .get(format!("{url}/v1.0/auth/jwt", url = &self.endpoint))
            .bearer_auth(&self.provider_token)
            .send()
            .await
            .wrap_err("Failed to complete request for a run token from Amplify.")?;
        if res.status().is_success() {
            let token_data = res
                .json::<JWTResponse>()
                .await
                .wrap_err("Failed to process JWT response body from Amplify.")?;
            self.jwt = Some(token_data.token);
            return Ok(self.jwt.clone().unwrap());
        }

        Err(eyre!("Failed to mint a run token from Amplify. Please ensure that this repository is configured in Amplify."))
    }
}
