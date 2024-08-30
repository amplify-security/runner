use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use std::time::Duration;

pub fn new_http_client() -> ClientWithMiddleware {
    // Retry on failure for up to 15 seconds
    let retry_policy =
        ExponentialBackoff::builder().build_with_total_retry_duration(Duration::from_secs(15));
    ClientBuilder::new(reqwest::Client::new())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
}
