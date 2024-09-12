use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{
    default_on_request_failure, default_on_request_success, policies::ExponentialBackoff,
    RetryTransientMiddleware, Retryable, RetryableStrategy,
};
use std::time::Duration;

pub fn new_http_client() -> ClientWithMiddleware {
    // Retry on failure for up to 15 seconds
    let retry_policy =
        ExponentialBackoff::builder().build_with_total_retry_duration(Duration::from_secs(15));
    ClientBuilder::new(reqwest::Client::new())
        .with(RetryTransientMiddleware::new_with_policy_and_strategy(
            retry_policy,
            DefaultRetryStrategyWith401,
        ))
        .build()
}

struct DefaultRetryStrategyWith401;
impl RetryableStrategy for DefaultRetryStrategyWith401 {
    fn handle(&self, res: &reqwest_middleware::Result<reqwest::Response>) -> Option<Retryable> {
        match res {
            Ok(success) if success.status() == 401 => Some(Retryable::Transient),
            Ok(success) => default_on_request_success(success),
            Err(error) => default_on_request_failure(error),
        }
    }
}
