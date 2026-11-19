use std::future::Future;
use std::pin::Pin;

/// Client metadata read from a client ID metadata document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientMetadata {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CimdError {
    #[error("client metadata address not allowed: {0}")]
    NotAllowed(String),
    #[error("client metadata fetch failed: {0}")]
    Fetch(String),
    #[error("client metadata invalid: {0}")]
    Invalid(String),
}

pub type CimdFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ClientMetadata, CimdError>> + Send + 'a>>;

/// Fetches the metadata document named by a client ID.
pub trait CimdFetcher: Send + Sync + 'static {
    fn fetch<'a>(&'a self, client_id: &'a str) -> CimdFuture<'a>;
}

/// Refuses every fetch; stands in until the real fetcher exists.
pub struct UnavailableCimd;

impl CimdFetcher for UnavailableCimd {
    fn fetch<'a>(&'a self, _client_id: &'a str) -> CimdFuture<'a> {
        Box::pin(std::future::ready(Err(CimdError::Fetch(
            "client metadata fetching is not available".into(),
        ))))
    }
}
