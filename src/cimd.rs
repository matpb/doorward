use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

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

pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Looks up the addresses of a host name.
pub trait Resolver: Send + Sync + 'static {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a>;
}

/// Whether a fetch may connect to this address. Skeleton: refuses every address.
pub fn address_allowed(_ip: IpAddr) -> bool {
    false
}

/// Settings for `HttpCimdFetcher`.
pub struct FetcherParts {
    pub resolver: Arc<dyn Resolver>,
    pub address_allowed: fn(IpAddr) -> bool,
    /// The port fetches connect to; 443 in `system()`.
    pub port: u16,
    pub extra_roots_pem: Option<Vec<u8>>,
    pub timeout: Duration,
    pub max_bytes: usize,
}

/// Fetches client metadata documents over HTTPS.
pub struct HttpCimdFetcher {
    #[allow(dead_code)]
    parts: FetcherParts,
}

/// Resolver used by `system()` until name lookup is implemented; fails every lookup.
struct UnavailableResolver;

impl Resolver for UnavailableResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> ResolveFuture<'a> {
        Box::pin(std::future::ready(Err(std::io::Error::other(
            "name lookup is not available",
        ))))
    }
}

impl HttpCimdFetcher {
    pub fn system() -> HttpCimdFetcher {
        HttpCimdFetcher::from_parts(FetcherParts {
            resolver: Arc::new(UnavailableResolver),
            address_allowed,
            port: 443,
            extra_roots_pem: None,
            timeout: Duration::from_secs(5),
            max_bytes: 65536,
        })
    }

    pub fn from_parts(parts: FetcherParts) -> HttpCimdFetcher {
        HttpCimdFetcher { parts }
    }
}

impl CimdFetcher for HttpCimdFetcher {
    fn fetch<'a>(&'a self, _client_id: &'a str) -> CimdFuture<'a> {
        Box::pin(std::future::ready(Err(CimdError::Fetch(
            "not implemented".into(),
        ))))
    }
}
