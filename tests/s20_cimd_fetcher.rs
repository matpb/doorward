use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use doorward::cimd::{FetcherParts, HttpCimdFetcher, ResolveFuture, Resolver, address_allowed};
use doorward::{CimdError, CimdFetcher, ClientMetadata};
use futures_util::FutureExt;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const HOST: &str = "client.example.com";
const URL: &str = "https://client.example.com/app.json";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
const DISCARD_PORT: u16 = 9;
const MAX_BYTES: usize = 65536;
const FIVE_SECONDS: Duration = Duration::from_secs(5);

/// Answers names from a fixed table and counts the lookups.
struct FakeResolver {
    answers: HashMap<String, Vec<IpAddr>>,
    lookups: AtomicUsize,
}

impl FakeResolver {
    fn new(answers: &[(&str, Vec<IpAddr>)]) -> Arc<FakeResolver> {
        Arc::new(FakeResolver {
            answers: answers
                .iter()
                .map(|(host, ips)| ((*host).to_owned(), ips.clone()))
                .collect(),
            lookups: AtomicUsize::new(0),
        })
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl Resolver for FakeResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let answer = match self.answers.get(host) {
            Some(ips) => Ok(ips.clone()),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no answer in the test table",
            )),
        };
        Box::pin(std::future::ready(answer))
    }
}

fn allow_any(_ip: IpAddr) -> bool {
    true
}

fn fetcher(
    resolver: Arc<FakeResolver>,
    allowed: fn(IpAddr) -> bool,
    port: u16,
    extra_roots_pem: Option<Vec<u8>>,
    timeout: Duration,
    max_bytes: usize,
) -> HttpCimdFetcher {
    HttpCimdFetcher::from_parts(FetcherParts {
        resolver,
        address_allowed: allowed,
        port,
        extra_roots_pem,
        timeout,
        max_bytes,
    })
}

/// A fetcher that reaches the test server at its loopback port and trusts its CA.
fn server_fetcher(server: &Server, timeout: Duration, max_bytes: usize) -> HttpCimdFetcher {
    fetcher(
        FakeResolver::new(&[(HOST, vec![LOOPBACK])]),
        allow_any,
        server.port,
        Some(server.ca_pem.clone()),
        timeout,
        max_bytes,
    )
}

/// The client metadata document the server sends by default.
fn document() -> Value {
    json!({
        "client_id": URL,
        "client_name": "Example App",
        "redirect_uris": ["http://127.0.0.1:40123/callback"],
        "token_endpoint_auth_method": "none"
    })
}

/// The document with `client_name` padded so the whole body is `total` bytes.
fn padded_document(total: usize) -> String {
    let mut doc = document();
    doc["client_name"] = json!("");
    let base = doc.to_string().len();
    doc["client_name"] = json!("a".repeat(total - base));
    doc.to_string()
}

#[derive(Clone)]
enum Reply {
    Document(String),
    Redirect(String),
    Silent,
}

#[derive(Debug, PartialEq)]
enum Seen {
    Request(String),
    HandshakeFailed,
}

/// A TLS server on a loopback port that answers every connection with one reply.
struct Server {
    events: UnboundedReceiver<Seen>,
    ca_pem: Vec<u8>,
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_server(reply: Reply) -> Server {
    let (ca_pem, config) = tls_material();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let port = listener.local_addr().expect("test server address").port();
    let (events_tx, events) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.expect("accept test connection");
            tokio::spawn(serve_connection(
                tcp,
                acceptor.clone(),
                reply.clone(),
                events_tx.clone(),
            ));
        }
    });
    Server {
        events,
        ca_pem,
        port,
        task,
    }
}

async fn serve_connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    reply: Reply,
    events: UnboundedSender<Seen>,
) {
    let Ok(mut stream) = acceptor.accept(tcp).await else {
        let _ = events.send(Seen::HandshakeFailed);
        return;
    };
    let Ok(head) = read_head(&mut stream).await else {
        return;
    };
    let _ = events.send(Seen::Request(head));
    let response = match reply {
        Reply::Document(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        Reply::Redirect(location) => format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        Reply::Silent => {
            std::future::pending::<()>().await;
            return;
        }
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<String> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 512];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// A CA PEM for the test client, and the server config with a certificate for HOST from it.
fn tls_material() -> (Vec<u8>, ServerConfig) {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA certificate");

    let server_key = KeyPair::generate().expect("server key");
    let server_params = CertificateParams::new(vec![HOST.to_owned()]).expect("server params");
    let server = server_params
        .signed_by(&server_key, &*ca)
        .expect("server certificate");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![server.der().clone()], key)
        .expect("server certificate and key");
    (ca.pem().into_bytes(), config)
}

async fn next_event(server: &mut Server) -> Seen {
    tokio::time::timeout(FIVE_SECONDS, server.events.recv())
        .await
        .expect("the test server must report within 5 seconds")
        .expect("the test server stopped")
}

async fn next_request(server: &mut Server) -> String {
    match next_event(server).await {
        Seen::Request(head) => head,
        Seen::HandshakeFailed => panic!("the TLS handshake failed before the request"),
    }
}

fn request_line(head: &str) -> &str {
    head.lines().next().unwrap_or_default()
}

/// Starts a server that answers with `reply` and fetches the test URL from it.
async fn fetch_reply(reply: Reply) -> Result<ClientMetadata, CimdError> {
    let server = start_server(reply).await;
    let fetcher = server_fetcher(&server, FIVE_SECONDS, MAX_BYTES);
    fetcher.fetch(URL).await
}

#[tokio::test(flavor = "multi_thread")]
async fn address_table() {
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        "IPv4 loopback must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
        "IPv6 loopback must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        "private class A IPv4 range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
        "private class B IPv4 range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
        "private class C IPv4 range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
        "IPv4 link-local range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
        "the cloud metadata address must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        "carrier-grade NAT range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        "IPv4 unspecified address must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
        "IPv6 unspecified address must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))),
        "IPv4 multicast range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))),
        "IPv6 multicast range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))),
        "IPv4 broadcast address must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        "IPv4 documentation range 192.0.2 must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
        "IPv4 documentation range 198.51.100 must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        "IPv4 documentation range 203.0.113 must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))),
        "IPv6 documentation range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
        "IPv4 benchmarking range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
        "IPv6 unique-local range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        "IPv6 link-local range must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped())),
        "the IPv4-mapped form of a private address must be refused"
    );
    assert!(
        !address_allowed(IpAddr::V6(Ipv6Addr::new(
            0x0064, 0xff9b, 0, 0, 0, 0, 0x7f00, 0x0001
        ))),
        "the NAT64 form of a loopback address must be refused"
    );
    assert!(
        address_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        "an ordinary public IPv4 address must be allowed"
    );
    assert!(
        address_allowed(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        "a second ordinary public IPv4 address must be allowed"
    );
    assert!(
        address_allowed(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))),
        "an ordinary public IPv6 address must be allowed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_private_answer_is_refused_before_any_connection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("listener address").port();
    let resolver = FakeResolver::new(&[(HOST, vec![LOOPBACK])]);
    let fetcher = fetcher(
        resolver.clone(),
        address_allowed,
        port,
        None,
        FIVE_SECONDS,
        MAX_BYTES,
    );
    let result = fetcher.fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::NotAllowed(_))),
        "a loopback answer must be refused as not allowed, got {result:?}"
    );
    assert_eq!(resolver.lookups(), 1, "the host must be resolved once");
    assert!(
        listener.accept().now_or_never().is_none(),
        "no connection may reach a refused address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_answer_is_refused() {
    for (order, answer) in [
        ("public address first", vec![PUBLIC, PRIVATE]),
        ("private address first", vec![PRIVATE, PUBLIC]),
    ] {
        let resolver = FakeResolver::new(&[(HOST, answer)]);
        let fetcher = fetcher(
            resolver.clone(),
            address_allowed,
            DISCARD_PORT,
            None,
            FIVE_SECONDS,
            MAX_BYTES,
        );
        let result = fetcher.fetch(URL).await;
        assert!(
            matches!(result, Err(CimdError::NotAllowed(_))),
            "an answer with one private address ({order}) must be refused as not allowed, got {result:?}"
        );
        assert_eq!(
            resolver.lookups(),
            1,
            "the host must be resolved once ({order})"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_https_host_names_on_the_default_port() {
    let resolver = FakeResolver::new(&[(HOST, vec![PUBLIC])]);
    let fetcher = fetcher(
        resolver.clone(),
        address_allowed,
        DISCARD_PORT,
        None,
        FIVE_SECONDS,
        MAX_BYTES,
    );
    let refused = [
        "http://client.example.com/a",
        "https://127.0.0.1/a",
        "https://client.example.com:8443/a",
        "https://user@client.example.com/a",
        "https://client.example.com/a#f",
        "https://client.example.com",
    ];
    for url in refused {
        let result = fetcher.fetch(url).await;
        assert!(
            matches!(result, Err(CimdError::NotAllowed(_))),
            "{url} must be refused as not allowed, got {result:?}"
        );
        assert_eq!(
            resolver.lookups(),
            0,
            "{url} must be refused before any name lookup"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_good_document_is_returned() {
    let mut server = start_server(Reply::Document(document().to_string())).await;
    let fetcher = server_fetcher(&server, FIVE_SECONDS, MAX_BYTES);
    let result = fetcher.fetch(URL).await;
    assert_eq!(
        result,
        Ok(ClientMetadata {
            client_id: URL.to_owned(),
            client_name: Some("Example App".to_owned()),
            redirect_uris: vec!["http://127.0.0.1:40123/callback".to_owned()],
            token_endpoint_auth_method: Some("none".to_owned()),
        }),
        "the name, redirect list and auth method of the document must be returned"
    );
    let head = next_request(&mut server).await;
    assert_eq!(
        request_line(&head),
        "GET /app.json HTTP/1.1",
        "the fetch must send one GET for the document path"
    );
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("accept: application/json")),
        "the request must accept JSON, got {head:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_not_followed() {
    let mut server = start_server(Reply::Redirect(
        "https://client.example.com/other.json".to_owned(),
    ))
    .await;
    let fetcher = server_fetcher(&server, FIVE_SECONDS, MAX_BYTES);
    let result = fetcher.fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a 302 answer must be refused as invalid, got {result:?}"
    );
    let head = next_request(&mut server).await;
    assert_eq!(
        request_line(&head),
        "GET /app.json HTTP/1.1",
        "the first request must be for the document path"
    );
    assert!(
        matches!(server.events.try_recv(), Err(TryRecvError::Empty)),
        "the redirect target must never be requested"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_document_is_refused() {
    let body = padded_document(4096);
    assert_eq!(body.len(), 4096, "the test document must be 4096 bytes");
    let server = start_server(Reply::Document(body)).await;
    let fetcher = fetcher(
        FakeResolver::new(&[(HOST, vec![LOOPBACK])]),
        allow_any,
        server.port,
        Some(server.ca_pem.clone()),
        FIVE_SECONDS,
        1024,
    );
    let result = fetcher.fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a body over max_bytes must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_server_times_out() {
    let mut server = start_server(Reply::Silent).await;
    let fetcher = server_fetcher(&server, Duration::from_millis(300), MAX_BYTES);
    let result = tokio::time::timeout(Duration::from_secs(2), fetcher.fetch(URL))
        .await
        .expect("a silent server must not hold the fetch past 2 seconds");
    assert!(
        matches!(result, Err(CimdError::Fetch(_))),
        "a timed out fetch must be a fetch error, got {result:?}"
    );
    let head = next_request(&mut server).await;
    assert_eq!(
        request_line(&head),
        "GET /app.json HTTP/1.1",
        "the request must have reached the silent server before the timeout"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mismatched_client_id_is_refused() {
    let mut doc = document();
    doc["client_id"] = json!("https://client.example.com/other.json");
    let result = fetch_reply(Reply::Document(doc.to_string())).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a client_id different from the URL must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_confidential_document_is_refused() {
    let mut doc = document();
    doc["token_endpoint_auth_method"] = json!("client_secret_basic");
    let result = fetch_reply(Reply::Document(doc.to_string())).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "an auth method other than none must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_without_redirects_is_refused() {
    let mut missing = document();
    missing
        .as_object_mut()
        .expect("document is an object")
        .remove("redirect_uris");
    let result = fetch_reply(Reply::Document(missing.to_string())).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a document without redirect_uris must be refused as invalid, got {result:?}"
    );

    let mut empty = document();
    empty["redirect_uris"] = json!([]);
    let result = fetch_reply(Reply::Document(empty.to_string())).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a document with an empty redirect_uris must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_is_not_json_is_refused() {
    let result = fetch_reply(Reply::Document("this is not json".to_owned())).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a body that is not JSON must be refused as invalid, got {result:?}"
    );
    let result = fetch_reply(Reply::Document("[]".to_owned())).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a JSON body that is not an object must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_certificate_is_refused() {
    let mut server = start_server(Reply::Document(document().to_string())).await;
    let fetcher = fetcher(
        FakeResolver::new(&[(HOST, vec![LOOPBACK])]),
        allow_any,
        server.port,
        None,
        FIVE_SECONDS,
        MAX_BYTES,
    );
    let result = fetcher.fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::Fetch(_))),
        "a certificate from an unknown CA must be a fetch error, got {result:?}"
    );
    assert_eq!(
        next_event(&mut server).await,
        Seen::HandshakeFailed,
        "the server must see the handshake refused"
    );
    assert!(
        matches!(server.events.try_recv(), Err(TryRecvError::Empty)),
        "no request may be sent over an untrusted connection"
    );
}
