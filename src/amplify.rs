use color_eyre::eyre::{eyre, Result, WrapErr};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;
// use tokio::select;

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
    Uname,
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
    async fn launch(&self) -> Result<String>;
}

#[enum_dispatch]
pub enum Tool {
    Semgrep,
    Uname,
}

impl Tool {
    pub fn new_from(tool: Tools) -> Tool {
        match tool {
            Tools::Semgrep => Tool::Semgrep(Semgrep {}),
            Tools::Uname => Tool::Uname(Uname {}),
        }
    }
}

#[derive(Debug, Default)]
pub struct Semgrep {}

#[derive(Debug, Default)]
pub struct Uname {}

impl ToolActions for Semgrep {
    async fn setup(&self) -> Result<()> {
        for cmd in [
            vec!["apk", "add", "python3", "py3-pip"],
            vec!["mkdir", "/semgrep"],
            vec!["python", "-m", "venv", "/semgrep"],
            vec!["/semgrep/bin/pip", "install", "semgrep"],
        ]
        .into_iter()
        {
            let cmd_full = cmd.join(" ");
            println!("::group::{}", cmd_full);
            println!("RUN: {:?}\n", cmd_full);
            let mut process = Command::new(cmd[0])
                .args(&cmd[1..])
                .spawn()
                .expect("Failed to launch process.");
            process.wait().await?;
            println!("::endgroup::");
        }

        println!("Completed semgrep installation.");
        Ok(())
    }

    async fn launch(&self) -> Result<String> {
        // TODO: Split out command execution grouped output into helper functions
        println!("::group::semgrep ci (scan job)");
        let semgrep_scan = Command::new("/semgrep/bin/semgrep")
            .args(["ci", "--config", "auto", "--json", "--oss-only"])
            .env("SEMGREP_RULES", ["p/security-audit", "p/secrets"].join(" "))
            .env("SEMGREP_IN_DOCKER", "1")
            .env("SEMGREP_USER_AGENT_APPEND", "Docker")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start Semgrep scan.");
        println!("Started Semgrep scan: {:?}", semgrep_scan);

        let result = semgrep_scan.wait_with_output().await?;
        println!("Finished Semgrep scan.");

        match result.status.code() {
            Some(code) => println!("Exited with code {}", code),
            None => println!("Process terminated by signal."),
        }
        println!("::endgroup::");
        String::from_utf8(result.stdout).context("Failed to read stdout from Semgrep.")
    }
}

impl ToolActions for Uname {
    async fn setup(&self) -> Result<()> {
        println!("Attempted setup function for uname.");
        Ok(())
    }

    async fn launch(&self) -> Result<String> {
        let uname = Command::new("uname").args(["-a"]).spawn()?;
        println!("Pushed off request for uname.");
        uname.wait_with_output().await?;
        println!("Finished running uname.");
        Ok("".to_string())
    }
}
