use color_eyre::eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AmplifyConfigResponse {
    tools: Vec<Tool>,
    merge_comments_enabled: bool,
    merge_approvals_enabled: bool,
    deleted: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Tool {
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
            config_data.tools.insert(0, Tool::Semgrep);
        }
        return Ok(config_data);
    }

    Err(eyre!(
        "Received a non-successful HTTP response when requesting project configuration."
    ))
}
