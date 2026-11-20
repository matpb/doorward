use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::ACCEPT;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use url::{Host, Url};

use crate::mcp::json::parse_strict;

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

/// Refuses every fetch; for fixtures that must not reach the network.
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

/// Whether a fetch may connect to this address: false for every range that is not public,
/// and for every IPv6 address outside `2000::/3`.
pub fn address_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_allowed(v4),
        IpAddr::V6(v6) => ipv6_allowed(v6),
    }
}

fn ipv4_allowed(ip: Ipv4Addr) -> bool {
    !matches!(
        ip.octets(),
        [0, ..]
            | [10, ..]
            | [100, 64..=127, ..]
            | [127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0, ..]
            | [192, 0, 2, ..]
            | [192, 88, 99, ..]
            | [192, 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, ..]
            | [203, 0, 113, ..]
            | [224..=255, ..]
    )
}

fn ipv6_allowed(ip: Ipv6Addr) -> bool {
    // ::ffff:0:0/96 is judged by the IPv4 address it carries.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_allowed(v4);
    }
    let s = ip.segments();
    match s {
        // ::/96 (includes :: and ::1), 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32.
        [0, 0, 0, 0, 0, 0, _, _] => false,
        [0x64, 0xff9b, 1, _, _, _, _, _] => false,
        [0x100, 0, 0, 0, _, _, _, _] => false,
        [0x2001, 0..=0x1ff, _, _, _, _, _, _] => false,
        [0x2001, 0xdb8, _, _, _, _, _, _] => false,
        // ::ffff:0:0:0/96 (IPv4-translated) and 3fff::/20 (documentation).
        [0, 0, 0, 0, 0xffff, 0, _, _] => false,
        [0x3fff, 0..=0x0fff, _, _, _, _, _, _] => false,
        // 64:ff9b::/96 (NAT64) and 2002::/16 (6to4) are judged by the embedded address.
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] => ipv4_allowed(embedded(hi, lo)),
        [0x2002, hi, lo, _, _, _, _, _] => ipv4_allowed(embedded(hi, lo)),
        _ if s[0] & 0xfe00 == 0xfc00 => false,
        _ if matches!(s[0] & 0xffc0, 0xfe80 | 0xfec0) => false,
        _ if s[0] & 0xff00 == 0xff00 => false,
        // Only global unicast 2000::/3 is allowed.
        _ => s[0] & 0xe000 == 0x2000,
    }
}

/// The IPv4 address carried in the last 32 bits of an IPv6 address.
fn embedded(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo))
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
    parts: FetcherParts,
}

/// A name lookup, run on the blocking pool.
pub(crate) type LookupFn = Arc<dyn Fn(&str) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

/// Looks names up on the blocking pool, with at most `limit` lookups running at a time.
pub(crate) struct BlockingResolver {
    permits: Arc<Semaphore>,
    lookup: LookupFn,
}

impl BlockingResolver {
    pub(crate) fn new(limit: usize, lookup: LookupFn) -> BlockingResolver {
        BlockingResolver {
            permits: Arc::new(Semaphore::new(limit)),
            lookup,
        }
    }

    pub(crate) fn system() -> BlockingResolver {
        BlockingResolver::new(SYSTEM_LOOKUPS, Arc::new(os_lookup))
    }
}

impl Resolver for BlockingResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            let permit = Arc::clone(&self.permits)
                .try_acquire_owned()
                .map_err(|_| std::io::Error::other("too many name lookups"))?;
            let lookup = Arc::clone(&self.lookup);
            let host = host.to_owned();
            // The permit is held until the lookup returns, even when the caller has stopped waiting.
            tokio::task::spawn_blocking(move || {
                let answer = lookup(&host);
                drop(permit);
                answer
            })
            .await
            .map_err(std::io::Error::other)
            .and_then(|answer| answer)
        })
    }
}

/// The operating system's addresses for a name, looked up as an absolute name.
fn os_lookup(host: &str) -> std::io::Result<Vec<IpAddr>> {
    let name = absolute(host);
    Ok((name.as_str(), 0)
        .to_socket_addrs()?
        .map(|addr| addr.ip())
        .collect())
}

/// The name with one trailing dot, so a resolver search list cannot extend it.
pub(crate) fn absolute(host: &str) -> String {
    format!("{host}.")
}

/// Answers every name with the addresses already checked for one fetch; never looks anything up.
pub(crate) struct PinnedResolver {
    addrs: Vec<SocketAddr>,
}

impl PinnedResolver {
    pub(crate) fn new(addrs: Vec<SocketAddr>) -> PinnedResolver {
        PinnedResolver { addrs }
    }
}

impl Resolve for PinnedResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let addrs: Addrs = Box::new(self.addrs.clone().into_iter());
        Box::pin(std::future::ready(Ok(addrs)))
    }
}

/// The longest client ID the fetcher accepts, in bytes.
const MAX_CLIENT_ID_BYTES: usize = 2048;
const HTTPS_PREFIX: &str = "https://";
const DEFAULT_PORT: u16 = 443;
const USER_AGENT: &str = concat!("doorward/", env!("CARGO_PKG_VERSION"));
const SYSTEM_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEM_MAX_BYTES: usize = 65536;
const SYSTEM_LOOKUPS: usize = 8;
/// The most time a single connection attempt may take, within the fetch budget.
const CONNECT_LIMIT: Duration = Duration::from_secs(2);

fn not_allowed() -> CimdError {
    CimdError::NotAllowed("the client ID is not an allowed https address".into())
}

fn refused_address() -> CimdError {
    CimdError::NotAllowed("the name resolves to a refused address".into())
}

fn fetch_failed() -> CimdError {
    CimdError::Fetch("the document could not be fetched".into())
}

fn invalid() -> CimdError {
    CimdError::Invalid("the document is not a valid client metadata document".into())
}

/// The host name and the URL of a client ID, read from its text alone.
struct Target {
    host: String,
    url: Url,
}

/// Accepts only `https://` with a host name, no userinfo, port, query or fragment, and a path.
/// Refuses spaces and control characters, which the URL parser would rewrite.
fn parse_client_id(client_id: &str) -> Result<Target, CimdError> {
    let bytes = client_id.as_bytes();
    if !client_id.is_ascii()
        || bytes.len() > MAX_CLIENT_ID_BYTES
        || bytes.iter().any(|&b| b <= b' ' || b == 0x7f)
    {
        return Err(not_allowed());
    }
    let rest = client_id
        .strip_prefix(HTTPS_PREFIX)
        .ok_or_else(not_allowed)?;
    let slash = rest.find('/').ok_or_else(not_allowed)?;
    let (authority, path) = rest.split_at(slash);
    let name_chars = authority
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if authority.is_empty()
        || !name_chars
        || path == "/"
        || path.contains('#')
        || client_id.contains('?')
    {
        return Err(not_allowed());
    }
    let labels: Vec<&str> = authority.split('.').collect();
    let label_ok =
        |label: &&str| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-');
    if labels.len() < 2 || !labels.iter().all(label_ok) {
        return Err(not_allowed());
    }
    if !matches!(Host::parse(authority), Ok(Host::Domain(_))) {
        return Err(not_allowed());
    }
    let url = Url::parse(client_id).map_err(|_| not_allowed())?;
    // The fetch goes to the URL the parser builds, so the text must be that URL unchanged.
    if url.as_str() != client_id {
        return Err(not_allowed());
    }
    Ok(Target {
        host: authority.to_ascii_lowercase(),
        url,
    })
}

/// The extra roots as certificates; none when no PEM is configured.
fn extra_roots(pem: Option<&[u8]>) -> Result<Vec<reqwest::Certificate>, CimdError> {
    match pem {
        None => Ok(Vec::new()),
        Some(pem) => reqwest::Certificate::from_pem_bundle(pem).map_err(|_| fetch_failed()),
    }
}

/// A field that may be absent; present with a value that is not a string is invalid.
fn optional_text(object: &Map<String, Value>, key: &str) -> Result<Option<String>, CimdError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(invalid()),
    }
}

/// Reads the fields of a document that name this client, its redirects and its auth method.
fn read_document(value: &Value, client_id: &str) -> Result<ClientMetadata, CimdError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(invalid());
    }
    let redirect_uris = object
        .get("redirect_uris")
        .and_then(Value::as_array)
        .and_then(|uris| {
            uris.iter()
                .map(|uri| uri.as_str().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
        })
        .filter(|uris| !uris.is_empty())
        .ok_or_else(invalid)?;
    let token_endpoint_auth_method = optional_text(object, "token_endpoint_auth_method")?;
    if token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| method != "none")
    {
        return Err(invalid());
    }
    let client_name = optional_text(object, "client_name")?;
    Ok(ClientMetadata {
        client_id: client_id.to_owned(),
        client_name,
        redirect_uris,
        token_endpoint_auth_method,
    })
}

impl HttpCimdFetcher {
    pub fn system() -> HttpCimdFetcher {
        HttpCimdFetcher::from_parts(FetcherParts {
            resolver: Arc::new(BlockingResolver::system()),
            address_allowed,
            port: DEFAULT_PORT,
            extra_roots_pem: None,
            timeout: SYSTEM_TIMEOUT,
            max_bytes: SYSTEM_MAX_BYTES,
        })
    }

    pub fn from_parts(parts: FetcherParts) -> HttpCimdFetcher {
        HttpCimdFetcher { parts }
    }

    /// One lookup, one connection to the checked addresses, one GET, one validated document.
    async fn fetch_document(
        &self,
        target: Target,
        client_id: &str,
    ) -> Result<ClientMetadata, CimdError> {
        let addrs = self
            .parts
            .resolver
            .resolve(&target.host)
            .await
            .map_err(|_| fetch_failed())?;
        if addrs.is_empty() {
            return Err(fetch_failed());
        }
        if !addrs.iter().all(|ip| (self.parts.address_allowed)(*ip)) {
            return Err(refused_address());
        }
        let port = self.parts.port;
        let pinned: Vec<SocketAddr> = addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
        let client = reqwest::Client::builder()
            .dns_resolver(PinnedResolver::new(pinned))
            .tls_certs_merge(extra_roots(self.parts.extra_roots_pem.as_deref())?)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .connect_timeout(self.parts.timeout.min(CONNECT_LIMIT))
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| fetch_failed())?;

        let mut url = target.url;
        if port != DEFAULT_PORT {
            url.set_port(Some(port)).map_err(|()| fetch_failed())?;
        }
        let mut response = client
            .get(url)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| fetch_failed())?;
        if response.status() != StatusCode::OK {
            return Err(invalid());
        }
        let max = self.parts.max_bytes;
        if response
            .content_length()
            .is_some_and(|len| len > u64::try_from(max).unwrap_or(u64::MAX))
        {
            return Err(invalid());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| fetch_failed())? {
            if chunk.len() > max.saturating_sub(body.len()) {
                return Err(invalid());
            }
            body.extend_from_slice(&chunk);
        }
        let value = parse_strict(&body).map_err(|_| invalid())?;
        read_document(&value, client_id)
    }
}

impl CimdFetcher for HttpCimdFetcher {
    fn fetch<'a>(&'a self, client_id: &'a str) -> CimdFuture<'a> {
        Box::pin(async move {
            let target = parse_client_id(client_id)?;
            match tokio::time::timeout(self.parts.timeout, self.fetch_document(target, client_id))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(fetch_failed()),
            }
        })
    }
}
