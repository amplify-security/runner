use color_eyre::eyre::{eyre, Result, WrapErr};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AmplifyConfigResponse {
    pub tools: Vec<Tools>,
    pub merge_comments_enabled: bool,
    pub merge_approvals_enabled: bool,
    pub deleted: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Tools {
    Semgrep,
}

pub async fn get_config(endpoint: String, token: String) -> Result<AmplifyConfigResponse> {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{url}/v1.0/config", url = &endpoint))
        .bearer_auth(&token)
        .send()
        .await
        .wrap_err("Failed to complete request for a run token from Amplify.")?;
    if res.status().is_success() {
        let mut config_data = res
            .json::<AmplifyConfigResponse>()
            .await
            .wrap_err("Failed to process response body for project configuration from Amplify.")?;
        // Testing against this repo seems to return no tools, so just default to Semgrep for now.
        if config_data.tools.is_empty() {
            config_data.tools.insert(0, Tools::Semgrep);
        }
        return Ok(config_data);
    }

    Err(eyre!(
        "Received a non-successful HTTP response when requesting project configuration."
    ))
}

#[enum_dispatch(Tool)]
pub trait ToolActions {
    async fn setup(&self) -> Result<()>;
    async fn launch(&self) -> Result<()>;
}

#[enum_dispatch]
pub enum Tool {
    Semgrep,
}

impl Tool {
    pub fn new_from(tool: Tools) -> Tool {
        match tool {
            Tools::Semgrep => Tool::Semgrep(Semgrep {}),
        }
    }
}

#[derive(Debug, Default)]
pub struct Semgrep {}

impl ToolActions for Semgrep {
    async fn setup(&self) -> Result<()> {
        Ok(())
    }

    async fn launch(&self) -> Result<()> {
        Ok(())
    }
}
