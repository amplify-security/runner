use color_eyre::eyre::{eyre, Result, WrapErr};
use enum_dispatch::enum_dispatch;
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io;
use std::process::Stdio;
use tokei::{Config, Languages};
use tokio::process::Command;

const OPENGREP_VERSION: &str = "1.9.1";
// opengrep_musllinux_x86 from https://github.com/opengrep/opengrep/releases
const OPENGREP_CHECKSUM: [u8; 32] =
    hex!("d2ccdaf540b865b8bd54902b2c7e66dc5893e13577ff50eb0fb278ca60ef8500");
const OPENGREP_RULES_URI: &str =
    "https://github.com/amplify-security/opengrep-rules/releases/download/latest/rules.json";

const HEADER_X_AMPLIFY_CODE_LINES: &str = "X-Amplify-Code-Lines";

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

pub fn get_code_lines() -> usize {
    let paths = &["."];
    let exclude = &[];
    let config = Config::default();
    let mut languages = Languages::new();
    languages.get_statistics(paths, exclude, &config);
    let total = Languages::total(&languages);
    total.code
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
    code_lines: usize,
) -> Result<()> {
    let client = crate::common::new_http_client();
    let res = client
        .put(format!("{url}/v1.0/artifact", url = &endpoint))
        .header(reqwest::header::CONTENT_TYPE, artifact_type.as_str())
        .header(HEADER_X_AMPLIFY_CODE_LINES, code_lines.to_string())
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
        "Received a non-successful {} HTTP response when submitting artifact to Amplify.",
        res.status().as_str()
    ))
}

#[enum_dispatch(Tool)]
pub trait ToolActions {
    async fn setup(&self) -> Result<()>;
    async fn launch(&self) -> Result<(ArtifactType, String)>;
}

#[enum_dispatch]
pub enum Tool {
    Opengrep,
    Uname,
}

impl Tool {
    pub fn new_from(tool: Tools) -> Tool {
        match tool {
            // Map Semgrep from API to Opengrep. May change later depending on
            // if Amplify's API retroactively renames the tool for everyone.
            Tools::Semgrep => Tool::Opengrep(Opengrep {}),
            Tools::Uname => Tool::Uname(Uname {}),
        }
    }
}

#[derive(Debug, Default)]
pub struct Opengrep {}

#[derive(Debug, Default)]
pub struct Uname {}

impl Opengrep {
    async fn install_rules(&self) -> Result<()> {
        let body = reqwest::get(OPENGREP_RULES_URI)
            .await
            .wrap_err("Failed to fetch Amplify ruleset for Opengrep.")?
            .bytes()
            .await?;
        let mut rules_file = File::create("/ruleset.json")?;
        io::copy(&mut body.as_ref(), &mut rules_file)?;
        Ok(())
    }
}

impl ToolActions for Opengrep {
    async fn setup(&self) -> Result<()> {
        println!("::group::opengrep install");
        let binary_url = format!(
            "https://github.com/{repository}/releases/download/v{version}/{binary_name}",
            repository = "opengrep/opengrep",
            version = OPENGREP_VERSION,
            binary_name = "opengrep_musllinux_x86"
        );
        let opengrep_binary = reqwest::get(binary_url)
            .await
            .wrap_err("Failed to fetch Opengrep binary.")?
            .bytes()
            .await?;
        let mut binary_file = File::create("/usr/bin/opengrep")?;
        let mut hasher = Sha256::new();
        hasher.update(&opengrep_binary);
        let hash = hasher.finalize();
        if hash[..] != OPENGREP_CHECKSUM[..] {
            return Err(eyre!(
                "Downloaded Opengrep binary failed checksum verification."
            ));
        }
        io::copy(&mut opengrep_binary.as_ref(), &mut binary_file)?;

        println!("Completed opengrep installation.");
        println!("::endgroup::");
        Ok(())
    }

    async fn launch(&self) -> Result<(ArtifactType, String)> {
        // TODO: Split out command execution grouped output into helper functions
        println!("::group::opengrep ci (scan job)");
        let search_paths: String = env::var("PATH").expect("Couldn't identify PATH.");
        self.install_rules().await?;
        let opengrep_scan = Command::new("/usr/bin/opengrep")
            // When public-api supports SARIF artifact ingestion, just change --json to --sarif here and update the return type
            .args(["ci", "--json", "--oss-only"])
            .env("PATH", format!("{search_paths}:/opengrep/bin"))
            .env("SEMGREP_RULES", "/ruleset.json")
            .env("SEMGREP_IN_DOCKER", "1")
            .env("SEMGREP_USER_AGENT_APPEND", "Docker")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start Opengrep scan.");
        println!("Started Opengrep scan: {opengrep_scan:?}");

        let result = opengrep_scan.wait_with_output().await?;
        println!("Finished Opengrep scan.");

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
            return Err(eyre!("Opengrep scan did not complete successfully."));
        }
        match String::from_utf8(result.stdout).context("Failed to read stdout from Opengrep.") {
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
