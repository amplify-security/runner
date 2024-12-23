use color_eyre::eyre::{eyre, Result, WrapErr};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use std::env;
use std::process::Stdio;
use tokio::process::Command;

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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ArtifactType {
    Json,
    #[allow(dead_code)]
    Sarif,
}

impl ArtifactType {
    fn as_str(&self) -> &'static str {
        match self {
            ArtifactType::Json => "application/json",
            ArtifactType::Sarif => "application/sarif+json",
        }
    }
}

pub async fn get_config(endpoint: String, token: String) -> Result<AmplifyConfigResponse> {
    let client = crate::common::new_http_client();
    let res = client
        .get(format!("{url}/v1.0/config", url = &endpoint))
        .bearer_auth(&token)
        .send()
        .await
        .wrap_err("Failed to complete request for project configuration from Amplify.")?;
    if res.status().is_success() {
        let config_data = res
            .json::<AmplifyConfigResponse>()
            .await
            .wrap_err("Failed to process response body for project configuration from Amplify.")?;
        if config_data.tools.is_empty() {
            return Err(eyre!("Received a configuration with no tools."));
        }
        return Ok(config_data);
    }

    Err(eyre!(
        "Received a non-successful HTTP response when requesting project configuration."
    ))
}

pub async fn submit_artifact(
    endpoint: String,
    token: String,
    artifact: String,
    artifact_type: ArtifactType,
) -> Result<()> {
    let client = crate::common::new_http_client();
    let res = client
        .put(format!("{url}/v1.0/artifact", url = &endpoint))
        .header(reqwest::header::CONTENT_TYPE, artifact_type.as_str())
        .bearer_auth(&token)
        .body(artifact)
        .send()
        .await
        .wrap_err("Failed to complete request for submitting an artifact to Amplify.")?;
    if res.status().is_success() {
        println!("Successfully submitted tool result to Amplify.");
        return Ok(());
    }

    Err(eyre!(
        "Received a non-successful HTTP response when submitting artifact to Amplify."
    ))
}

#[enum_dispatch(Tool)]
pub trait ToolActions {
    async fn setup(&self) -> Result<()>;
    async fn launch(&self) -> Result<(ArtifactType, String)>;
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
            vec!["/semgrep/bin/pip", "install", "semgrep==1.96.0"],
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
            let status = process.wait().await?;
            let mut success = false;
            match status.code() {
                Some(code) => {
                    if code == 0 {
                        success = true;
                    } else {
                        println!("{:?} returned a non-successful exit code: {code}", cmd_full);
                    }
                }
                None => println!("{:?} was terminated by an external signal.", cmd_full),
            }
            println!("::endgroup::");
            if !success {
                return Err(eyre!("Failed to execute {:?}", cmd_full));
            }
        }

        println!("Completed semgrep installation.");
        Ok(())
    }

    async fn launch(&self) -> Result<(ArtifactType, String)> {
        // TODO: Split out command execution grouped output into helper functions
        println!("::group::semgrep ci (scan job)");
        let search_paths: String = env::var("PATH").expect("Couldn't identify PATH.");
        let semgrep_scan = Command::new("/semgrep/bin/semgrep")
            // When public-api supports SARIF artifact ingestion, just change --json to --sarif here and update the return type
            .args(["ci", "--config", "auto", "--json", "--oss-only"])
            .env("PATH", format!("{search_paths}:/semgrep/bin"))
            .env("SEMGREP_RULES", ["p/security-audit", "p/secrets"].join(" "))
            .env("SEMGREP_IN_DOCKER", "1")
            .env("SEMGREP_USER_AGENT_APPEND", "Docker")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start Semgrep scan.");
        println!("Started Semgrep scan: {:?}", semgrep_scan);

        let result = semgrep_scan.wait_with_output().await?;
        println!("Finished Semgrep scan.");

        let mut success = false;
        match result.status.code() {
            Some(code) => {
                // Per Semgrep documentation (https://semgrep.dev/docs/cli-reference#exit-codes):
                //   Semgrep can finish with the following exit codes:
                //     0: Semgrep ran successfully and found no errors (or did find errors, but the --error flag is not
                //        being used).
                //     1: Semgrep ran successfully and found issues in your code (while using the --error flag).
                // so we can treat 1 as success as well since we get a scan result.
                if code == 0 || code == 1 {
                    success = true;
                } else {
                    println!("Exited with non-successful exit code: {code}");
                }
            }
            None => println!("Scan was prematurely terminated by an external signal."),
        }
        println!("::endgroup::");
        if !success {
            return Err(eyre!("Semgrep scan did not complete successfully."));
        }
        match String::from_utf8(result.stdout).context("Failed to read stdout from Semgrep.") {
            Ok(out) => Ok((ArtifactType::Json, out)),
            Err(e) => Err(e),
        }
    }
}

impl ToolActions for Uname {
    async fn setup(&self) -> Result<()> {
        println!("Attempted setup function for uname.");
        Ok(())
    }

    async fn launch(&self) -> Result<(ArtifactType, String)> {
        let uname = Command::new("uname").args(["-a"]).spawn()?;
        println!("Pushed off request for uname.");
        uname.wait_with_output().await?;
        println!("Finished running uname.");
        Ok((ArtifactType::Json, "".to_string()))
    }
}
