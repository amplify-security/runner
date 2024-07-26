//! Amplify Security's Runner
//!
//! This application runs as a wrapper around local code scanners and
//! interfaces with Amplify's API to provide remediations to the user.

use color_eyre::eyre::{eyre, Result, WrapErr};
use std::process::ExitCode;

pub(crate) mod auth;
pub(crate) mod cli;

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
    let endpoint = args.endpoint.expect("Couldn't find endpoint.");

    if let Some(ci) = args.ci {
        let provider_token = match ci {
            cli::ExecutionEnvironment::Github => {
                let mut provider = auth::github::GithubAuth::new(endpoint.to_owned())
                    .wrap_err("Failed to setup GithubAuth provider")?;
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
        let mut amplify_auth = auth::amplify::AmplifyAuth::new(endpoint.to_owned(), provider_token)
            .wrap_err("Failed to setup AmplifyAuth provider.")?;
        let _amplify_token = amplify_auth.get_token().await?;
    } else {
        println!("CI environment is unknown! You may need to specify one via --ci.");
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}
