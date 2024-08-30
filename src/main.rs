//! Amplify Security's Runner
//!
//! This application runs as a wrapper around local code scanners and
//! interfaces with Amplify's API to provide remediations to the user.

use color_eyre::eyre::{eyre, Result, WrapErr};
use std::process::ExitCode;

pub(crate) mod amplify;
pub(crate) mod auth;
pub(crate) mod cli;
pub(crate) mod common;

use crate::amplify::{Tool, ToolActions};

#[tokio::main]
async fn main() -> Result<ExitCode> {
    // Initializes error summary handler with support for directing end users
    // (ppl reading Github Action logs) to opening issues with actionable info
    color_eyre::config::HookBuilder::default()
        .issue_url(concat!(env!("CARGO_PKG_REPOSITORY"), "/issues/new"))
        .add_issue_metadata("version", env!("CARGO_PKG_VERSION"))
        .issue_filter(|kind| match kind {
            color_eyre::ErrorKind::NonRecoverable(_) => false,
            color_eyre::ErrorKind::Recoverable(_) => true,
        })
        .install()?;

    let args = cli::init();
    let endpoint = args.endpoint.clone().unwrap();

    if let Some(ci) = args.ci.clone() {
        let provider_token = match ci {
            cli::ExecutionEnvironment::Github => {
                let mut provider = auth::github::GithubAuth::new(endpoint.to_owned())
                    .wrap_err("Failed to setup GithubAuth provider")?;
                provider.get_token().await?
            }
            cli::ExecutionEnvironment::Gitlab => {
                let mut provider = auth::gitlab::GitlabAuth::new()
                    .wrap_err("Failed to setup GitlabAuth provider")?;
                provider.get_token().await?
            }
            cli::ExecutionEnvironment::Local => {
                let mut provider =
                    auth::LocalAuth::new().wrap_err("Failed to setup LocalAuth provider")?;
                provider.get_token().await?
            }
            cli::ExecutionEnvironment::Unsupported => {
                return Err(eyre!("This CI environment is currently unsupported."))
            }
        };
        let amplify_token: String = if ci == cli::ExecutionEnvironment::Local {
            // No integration exists between this runner and the Amplify API to
            // test against locally generated JWTs, so this is a placeholder
            // for now.
            "local amplify token".to_owned()
        } else {
            let mut amplify_auth =
                auth::amplify::AmplifyAuth::new(endpoint.to_owned(), provider_token)
                    .wrap_err("Failed to setup AmplifyAuth provider.")?;
            amplify_auth.get_token().await?
        };

        let config = if ci == cli::ExecutionEnvironment::Local {
            amplify::AmplifyConfigResponse {
                tools: vec![amplify::Tools::Uname],
                merge_comments_enabled: false,
                merge_approvals_enabled: false,
                deleted: false,
            }
        } else {
            amplify::get_config(endpoint.to_owned(), amplify_token.to_owned()).await?
        };

        for tool_name in config.tools.into_iter() {
            let tool = Tool::new_from(tool_name);
            tool.setup().await?;
            let (tool_output_type, tool_output) = tool.launch().await?;
            amplify::submit_artifact(
                endpoint.to_owned(),
                amplify_token.to_owned(),
                tool_output,
                tool_output_type,
            )
            .await?;
        }
    } else {
        println!("CI environment is unknown! You may need to specify one via --ci.");
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}
