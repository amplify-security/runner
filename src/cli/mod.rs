use bpaf::*;
use color_eyre::eyre::Result;
use std::str::FromStr;

const DEFAULT_AMPLIFY_ENDPOINT: &str = "https://api.amplify.security";

#[derive(Debug, Clone)]
pub struct RunnerArgs {
    pub ci: Option<ExecutionEnvironment>,
    pub endpoint: Option<String>,
}

pub fn init() -> RunnerArgs {
    let endpoint = long("endpoint")
        .help("URL to Amplify Security's public API.")
        .argument::<String>("API_URL")
        .optional();

    let ci = long("ci")
        .help("CI Environment that this runner is executing in.")
        .argument::<ExecutionEnvironment>("PLATFORM")
        .optional();

    let parser = construct!(RunnerArgs { ci, endpoint })
        .to_options()
        .descr("Amplify Runner");

    let mut args = parser.run();

    // Autodetect CI environment if not specified by CLI flags
    if args.ci.is_none() {
        args.ci = identify_ci_from_environment();
    }

    if args.endpoint.is_none() {
        args.endpoint =
            Some(std::env::var("AMPLIFY_ENDPOINT").unwrap_or(DEFAULT_AMPLIFY_ENDPOINT.to_owned()));
    }

    args
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExecutionEnvironment {
    Github,
    //Gitlab,
    Local,
    Unsupported,
}

impl ExecutionEnvironment {
    #[allow(dead_code)]
    fn as_str(&self) -> &str {
        match self {
            Self::Github => "github",
            //Self::Gitlab => "gitlab",
            Self::Local => "local",
            Self::Unsupported => "",
        }
    }
}

impl FromStr for ExecutionEnvironment {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "github" => Ok(Self::Github),
            //"gitlab" => Ok(Self::Gitlab)
            "local" => Ok(Self::Local),
            _ => Ok(Self::Unsupported),
        }
    }
}

fn identify_ci_from_environment() -> Option<ExecutionEnvironment> {
    // https://docs.github.com/en/actions/learn-github-actions/variables
    if std::env::var("GITHUB_ACTIONS").unwrap_or_default() == "true" {
        return Some(ExecutionEnvironment::Github);
    }
    // https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    /*if std::env::var("GITLAB_CI").unwrap_or_default() == "true" {
        return Some(ExecutionEnvironment::Gitlab);
    }*/
    None
}
