//! Authentication for Gitlab Pipelines

use color_eyre::eyre::{eyre, Result};

#[derive(Debug, Clone)]
pub(crate) struct GitlabAuth {
    pub jwt: Option<String>,
}

impl GitlabAuth {
    pub fn new() -> Result<GitlabAuth> {
        Ok(GitlabAuth { jwt: None })
    }

    pub async fn get_token(&mut self) -> Result<String> {
        // GitLab generates JWTs for specific audiences within the pipeline
        // configuration itself, so all we have to do is pull the env variable
        // https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html
        if let Ok(token) = std::env::var("AMPLIFY_ID_TOKEN") {
            self.jwt = Some(token);
            return Ok(self.jwt.clone().unwrap());
        }

        Err(eyre!("Failed to locate an ID Token from Gitlab."))
    }
}
