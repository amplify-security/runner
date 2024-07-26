pub(crate) mod amplify;
pub(crate) mod github;

use color_eyre::eyre::Result;

pub(crate) struct LocalAuth;

impl LocalAuth {
    pub fn new() -> Result<LocalAuth> {
        Ok(LocalAuth {})
    }

    pub async fn get_token(&mut self) -> Result<String> {
        let token: &str = "local token";
        Ok(token.to_string())
    }
}
