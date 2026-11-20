//! Tests of the client ID metadata fetcher: URL shape, address table, lookups, document fields, requests.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use reqwest::dns::{Name, Resolve};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::cimd::{
    BlockingResolver, CimdError, CimdFetcher, ClientMetadata, FetcherParts, HttpCimdFetcher,
    LookupFn, PinnedResolver, ResolveFuture, Resolver, absolute, address_allowed,
};

const HOST: &str = "client.example.com";
const URL: &str = "https://client.example.com/app.json";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const DISCARD_PORT: u16 = 9;
const MAX_BYTES: usize = 65536;
const FIVE_SECONDS: Duration = Duration::from_secs(5);

/// Answers names from a fixed table, fails the others, and counts the lookups.
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

/// Refuses only the private address, so a mixed answer can be built without a real network address.
fn refuse_private(ip: IpAddr) -> bool {
    ip != PRIVATE
}

fn fetcher_with(
    resolver: Arc<FakeResolver>,
    allowed: fn(IpAddr) -> bool,
    port: u16,
    extra_roots_pem: Option<Vec<u8>>,
    max_bytes: usize,
) -> HttpCimdFetcher {
    HttpCimdFetcher::from_parts(FetcherParts {
        resolver,
        address_allowed: allowed,
        port,
        extra_roots_pem,
        timeout: FIVE_SECONDS,
        max_bytes,
    })
}

/// A fetcher that reaches the test server at its loopback port and trusts its CA.
fn server_fetcher(server: &Server, max_bytes: usize) -> HttpCimdFetcher {
    fetcher_with(
        FakeResolver::new(&[(HOST, vec![LOOPBACK])]),
        allow_any,
        server.port,
        Some(server.ca_pem.clone()),
        max_bytes,
    )
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
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

fn expected_metadata() -> ClientMetadata {
    ClientMetadata {
        client_id: URL.to_owned(),
        client_name: Some("Example App".to_owned()),
        redirect_uris: vec!["http://127.0.0.1:40123/callback".to_owned()],
        token_endpoint_auth_method: Some("none".to_owned()),
    }
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
    /// A 200 answer with this body and a correct Content-Length.
    Document(String),
    /// These exact bytes, headers and body, as the whole answer.
    Raw(String),
}

/// A TLS server on a loopback port that answers every connection with one reply.
struct Server {
    heads: UnboundedReceiver<String>,
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
    let (heads_tx, heads) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.expect("accept test connection");
            tokio::spawn(serve_connection(
                tcp,
                acceptor.clone(),
                reply.clone(),
                heads_tx.clone(),
            ));
        }
    });
    Server {
        heads,
        ca_pem,
        port,
        task,
    }
}

async fn serve_connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    reply: Reply,
    heads: UnboundedSender<String>,
) {
    let Ok(mut stream) = acceptor.accept(tcp).await else {
        return;
    };
    let Ok(head) = read_head(&mut stream).await else {
        return;
    };
    let _ = heads.send(head);
    let response = match reply {
        Reply::Document(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        Reply::Raw(text) => text,
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

async fn next_head(server: &mut Server) -> String {
    tokio::time::timeout(FIVE_SECONDS, server.heads.recv())
        .await
        .expect("the test server must report within 5 seconds")
        .expect("the test server stopped")
}

/// Starts a server that answers with `reply` and fetches the test URL from it.
async fn fetch_reply(reply: Reply) -> Result<ClientMetadata, CimdError> {
    let server = start_server(reply).await;
    server_fetcher(&server, MAX_BYTES).fetch(URL).await
}

#[tokio::test(flavor = "multi_thread")]
async fn shape_refusals_come_before_any_lookup() {
    let long_path = format!("https://{HOST}/a{}", "x".repeat(2100));
    let refused = [
        "https://client.example.com:443/a",
        "https://[::1]/a",
        "https://client.example.com/",
        "HTTP://client.example.com/a",
        long_path.as_str(),
        "https://cl\u{e9}ent.example.com/a",
        "https:///a",
        "https://user:pw@client.example.com/a",
        "http://client.example.com/a",
        "https://127.0.0.1/a",
        "https://127.1/a",
        "https://client.example.com:8443/a",
        "https://user@client.example.com/a",
        "https://client.example.com/a#f",
        "https://client.example.com",
        "https://client.example.com/a b",
        "https://client.example.com/a\u{7}",
        "https://client.example.com/a?x=1",
        "https://client.example.com/a/b.json?x=1",
    ];
    for url in refused {
        let resolver = FakeResolver::new(&[(HOST, vec![LOOPBACK])]);
        let fetcher = fetcher_with(
            resolver.clone(),
            address_allowed,
            DISCARD_PORT,
            None,
            MAX_BYTES,
        );
        let result = fetcher.fetch(url).await;
        assert!(
            matches!(result, Err(CimdError::NotAllowed(_))),
            "{url:?} must be refused as not allowed, got {result:?}"
        );
        assert_eq!(
            resolver.lookups(),
            0,
            "{url:?} must be refused before any name lookup"
        );
    }
}

#[test]
fn ipv4_boundaries_follow_the_ranges() {
    let cases = [
        (v4(0, 0, 0, 0), false),
        (v4(0, 255, 255, 255), false),
        (v4(1, 0, 0, 0), true),
        (v4(10, 0, 0, 1), false),
        (v4(100, 63, 255, 255), true),
        (v4(100, 64, 0, 0), false),
        (v4(100, 127, 255, 255), false),
        (v4(100, 128, 0, 0), true),
        (v4(126, 255, 255, 255), true),
        (v4(127, 0, 0, 1), false),
        (v4(169, 253, 255, 255), true),
        (v4(169, 254, 0, 0), false),
        (v4(169, 254, 169, 254), false),
        (v4(169, 255, 0, 0), true),
        (v4(172, 15, 255, 255), true),
        (v4(172, 16, 0, 0), false),
        (v4(172, 31, 255, 255), false),
        (v4(172, 32, 0, 0), true),
        (v4(192, 0, 0, 0), false),
        (v4(192, 0, 1, 255), true),
        (v4(192, 0, 2, 0), false),
        (v4(192, 0, 3, 0), true),
        (v4(192, 88, 98, 255), true),
        (v4(192, 88, 99, 0), false),
        (v4(192, 88, 100, 0), true),
        (v4(192, 167, 255, 255), true),
        (v4(192, 168, 0, 1), false),
        (v4(192, 169, 0, 0), true),
        (v4(198, 17, 255, 255), true),
        (v4(198, 18, 0, 0), false),
        (v4(198, 19, 255, 255), false),
        (v4(198, 20, 0, 0), true),
        (v4(198, 51, 99, 255), true),
        (v4(198, 51, 100, 0), false),
        (v4(198, 51, 101, 0), true),
        (v4(203, 0, 112, 255), true),
        (v4(203, 0, 113, 0), false),
        (v4(203, 0, 114, 0), true),
        (v4(223, 255, 255, 255), true),
        (v4(224, 0, 0, 0), false),
        (v4(239, 255, 255, 255), false),
        (v4(240, 0, 0, 0), false),
        (v4(255, 255, 255, 255), false),
        (v4(8, 8, 8, 8), true),
        (v4(93, 184, 216, 34), true),
    ];
    for (ip, expected) in cases {
        assert_eq!(address_allowed(ip), expected, "address_allowed({ip})");
    }
}

#[test]
fn ipv6_ranges_and_embedded_ipv4_forms_follow_the_address() {
    let cases = [
        (v6([0, 0, 0, 0, 0, 0, 0, 0]), false),
        (v6([0, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0, 0, 0, 0, 0, 0, 0, 2]), false),
        (v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 1]), false),
        (v6([0x100, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x2001, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x2001, 0x200, 0, 0, 0, 0, 0, 1]), true),
        (v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x2606, 0x4700, 0, 0, 0, 0, 0, 1]), true),
        (v6([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]), true),
        (v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0xfdff, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0xfe7f, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0xfebf, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0xfec0, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0xff02, 0, 0, 0, 0, 0, 0, 1]), false),
    ];
    for (ip, expected) in cases {
        assert_eq!(address_allowed(ip), expected, "address_allowed({ip})");
    }

    let mapped = IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped());
    assert!(
        address_allowed(mapped),
        "the mapped form of a public address"
    );
    let nat64 = v6([0x64, 0xff9b, 0, 0, 0, 0, 0x808, 0x808]);
    assert!(address_allowed(nat64), "the NAT64 form of a public address");
    let six_to_four = v6([0x2002, 0x808, 0x808, 0, 0, 0, 0, 0]);
    assert!(
        address_allowed(six_to_four),
        "the 6to4 form of a public address"
    );

    let refused_embedded = [
        (Ipv4Addr::new(10, 0, 0, 1), "a private address"),
        (Ipv4Addr::new(127, 0, 0, 1), "a loopback address"),
        (Ipv4Addr::new(169, 254, 169, 254), "the metadata address"),
    ];
    for (embedded, label) in refused_embedded {
        let [e0, e1, e2, e3] = embedded.octets();
        let hi = u16::from_be_bytes([e0, e1]);
        let lo = u16::from_be_bytes([e2, e3]);
        let forms = [
            ("mapped", IpAddr::V6(embedded.to_ipv6_mapped())),
            ("NAT64", v6([0x64, 0xff9b, 0, 0, 0, 0, hi, lo])),
            ("6to4", v6([0x2002, hi, lo, 0, 0, 0, 0, 0])),
        ];
        for (form, ip) in forms {
            assert!(
                !address_allowed(ip),
                "the {form} form of {label} must be refused, got {ip}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_answer_and_a_lookup_error_are_fetch_errors() {
    let empty = FakeResolver::new(&[(HOST, Vec::new())]);
    let failing = FakeResolver::new(&[]);
    for resolver in [empty, failing] {
        let fetcher = fetcher_with(
            resolver.clone(),
            address_allowed,
            DISCARD_PORT,
            None,
            MAX_BYTES,
        );
        let result = fetcher.fetch(URL).await;
        assert!(
            matches!(result, Err(CimdError::Fetch(_))),
            "an empty answer or a lookup error must be a fetch error, got {result:?}"
        );
        assert_eq!(resolver.lookups(), 1, "the host must be resolved once");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_answer_is_refused_in_either_order_with_one_lookup() {
    for (order, answer) in [
        ("allowed address first", vec![LOOPBACK, PRIVATE]),
        ("private address first", vec![PRIVATE, LOOPBACK]),
    ] {
        let resolver = FakeResolver::new(&[(HOST, answer)]);
        let fetcher = fetcher_with(
            resolver.clone(),
            refuse_private,
            DISCARD_PORT,
            None,
            MAX_BYTES,
        );
        let result = fetcher.fetch(URL).await;
        assert!(
            matches!(result, Err(CimdError::NotAllowed(_))),
            "an answer with one private address ({order}) must be refused, got {result:?}"
        );
        assert_eq!(
            resolver.lookups(),
            1,
            "the host must be resolved once ({order})"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refusal_texts_never_contain_the_address() {
    for answer in [vec![LOOPBACK], vec![PRIVATE], vec![LOOPBACK, PRIVATE]] {
        let resolver = FakeResolver::new(&[(HOST, answer.clone())]);
        let fetcher = fetcher_with(resolver, address_allowed, DISCARD_PORT, None, MAX_BYTES);
        match fetcher.fetch(URL).await {
            Err(CimdError::NotAllowed(text)) => {
                for ip in answer {
                    assert!(
                        !text.contains(&ip.to_string()),
                        "the refusal text must not name {ip}, got {text:?}"
                    );
                }
            }
            other => panic!("a refused answer must be NotAllowed, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn document_fields_that_are_present_with_a_wrong_type_are_invalid() {
    let twice = format!(
        r#"{{"client_id":"{URL}","client_id":"{URL}","redirect_uris":["http://127.0.0.1:40123/callback"]}}"#
    );
    let mut numbered_redirects = document();
    numbered_redirects["redirect_uris"] = json!(["http://127.0.0.1:40123/callback", 42]);
    let mut numbered_name = document();
    numbered_name["client_name"] = json!(7);
    let bodies = [
        ("a duplicate client_id key", twice),
        (
            "a redirect_uris entry that is a number",
            numbered_redirects.to_string(),
        ),
        ("a client_name that is a number", numbered_name.to_string()),
    ];
    for (label, body) in bodies {
        let result = fetch_reply(Reply::Document(body)).await;
        assert!(
            matches!(result, Err(CimdError::Invalid(_))),
            "{label} must be refused as invalid, got {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_statuses_are_invalid_and_never_followed() {
    let replies = [
        (
            "404",
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        (
            "204",
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ),
        (
            "307",
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://client.example.com/other.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    ];
    for (status, text) in replies {
        let result = fetch_reply(Reply::Raw(text.to_owned())).await;
        assert!(
            matches!(result, Err(CimdError::Invalid(_))),
            "a {status} answer must be refused as invalid, got {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_document_under_a_wrong_status_is_invalid() {
    let body = document().to_string();
    for status in [
        "404 Not Found",
        "500 Internal Server Error",
        "201 Created",
        "203 Non-Authoritative Information",
    ] {
        let text = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let result = fetch_reply(Reply::Raw(text)).await;
        assert!(
            matches!(result, Err(CimdError::Invalid(_))),
            "a valid document under status {status} must be refused as invalid, got {result:?}"
        );
    }
}

/// The whole answer for `body` with no Content-Length: close-delimited, or one chunk when `chunked`.
fn unframed_answer(body: &str, chunked: bool) -> String {
    if chunked {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_without_a_length_is_cut_at_the_cap() {
    let over = padded_document(4096);
    let under = document().to_string();
    for chunked in [false, true] {
        let server = start_server(Reply::Raw(unframed_answer(&over, chunked))).await;
        let result = server_fetcher(&server, 1024).fetch(URL).await;
        assert!(
            matches!(result, Err(CimdError::Invalid(_))),
            "an unframed body over max_bytes (chunked: {chunked}) must be refused as invalid, got {result:?}"
        );

        let server = start_server(Reply::Raw(unframed_answer(&under, chunked))).await;
        let result = server_fetcher(&server, 1024).fetch(URL).await;
        assert_eq!(
            result,
            Ok(expected_metadata()),
            "an unframed body under max_bytes (chunked: {chunked}) must pass"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_content_length_over_the_cap_is_refused_before_the_body() {
    let text = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n{}";
    let server = start_server(Reply::Raw(text.to_owned())).await;
    let result = server_fetcher(&server, 1024).fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a Content-Length over max_bytes must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_of_exactly_max_bytes_passes_and_one_byte_more_is_invalid() {
    let body = padded_document(4096);
    assert_eq!(body.len(), 4096, "the test document must be 4096 bytes");
    let padded: Value = serde_json::from_str(&body).expect("the padded document is JSON");
    let expected = ClientMetadata {
        client_name: padded["client_name"].as_str().map(str::to_owned),
        ..expected_metadata()
    };
    let server = start_server(Reply::Document(body.clone())).await;
    let result = server_fetcher(&server, 4096).fetch(URL).await;
    assert_eq!(
        result,
        Ok(expected),
        "a body of exactly max_bytes must pass"
    );

    let server = start_server(Reply::Document(body)).await;
    let result = server_fetcher(&server, 4095).fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::Invalid(_))),
        "a body one byte over max_bytes must be refused as invalid, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_request_carries_accept_and_the_host_only() {
    let mut server = start_server(Reply::Document(document().to_string())).await;
    let result = server_fetcher(&server, MAX_BYTES).fetch(URL).await;
    assert_eq!(result, Ok(expected_metadata()), "the document must be read");
    let head = next_head(&mut server).await;
    let lines: Vec<&str> = head.lines().skip(1).collect();
    let header = |name: &str| -> Option<&str> {
        lines.iter().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim())
        })
    };
    assert_eq!(
        header("accept"),
        Some("application/json"),
        "the request must accept JSON, got {head:?}"
    );
    let host = format!("{HOST}:{}", server.port);
    assert_eq!(
        header("host"),
        Some(host.as_str()),
        "the host must be the document's host name, with the port the fetch uses"
    );
    for name in ["cookie", "authorization", "referer"] {
        assert_eq!(header(name), None, "the request must not carry {name}");
    }
}

/// Serializes the one test that changes the process environment.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread")]
async fn proxy_variables_of_the_environment_are_not_used() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a port to close");
        listener.local_addr().expect("closed port address").port()
    };
    let _guard = ENV_LOCK.lock().await;
    let previous = std::env::var_os("HTTPS_PROXY");
    // SAFETY: ENV_LOCK is held, so no other test in this module reads or writes the variable.
    unsafe { std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{closed}")) };
    let server = start_server(Reply::Document(document().to_string())).await;
    let result = server_fetcher(&server, MAX_BYTES).fetch(URL).await;
    // SAFETY: as above, the variable is restored while ENV_LOCK is still held.
    unsafe {
        match previous {
            Some(value) => std::env::set_var("HTTPS_PROXY", value),
            None => std::env::remove_var("HTTPS_PROXY"),
        }
    }
    assert_eq!(
        result,
        Ok(expected_metadata()),
        "a fetch must not use a proxy from the environment"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_answer_connects_nowhere() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("listener address").port();
    let resolver = FakeResolver::new(&[(HOST, vec![LOOPBACK])]);
    let fetcher = fetcher_with(resolver.clone(), address_allowed, port, None, MAX_BYTES);
    let result = fetcher.fetch(URL).await;
    assert!(
        matches!(result, Err(CimdError::NotAllowed(_))),
        "a loopback answer must be refused, got {result:?}"
    );
    assert!(
        listener.accept().now_or_never().is_none(),
        "no connection may reach a refused address"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_id_must_be_the_text_the_parser_keeps() {
    let refused = [
        "https://client.example.com/a/../b",
        "https://client.example.com/a/./b",
        "https://CLIENT.example.com/a",
        "https://client.example.com/a\\b",
        "https://client.example.com/a?x=1#",
    ];
    for url in refused {
        let resolver = FakeResolver::new(&[(HOST, vec![LOOPBACK])]);
        let fetcher = fetcher_with(
            resolver.clone(),
            address_allowed,
            DISCARD_PORT,
            None,
            MAX_BYTES,
        );
        let result = fetcher.fetch(url).await;
        assert!(
            matches!(result, Err(CimdError::NotAllowed(_))),
            "{url:?} must be refused as not allowed, got {result:?}"
        );
        assert_eq!(
            resolver.lookups(),
            0,
            "{url:?} must be refused before any name lookup"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_the_parser_keeps_reaches_the_resolver_once() {
    for url in [
        "https://client.example.com/a/b.json",
        "https://client.example.com/a%zz",
    ] {
        let resolver = FakeResolver::new(&[(HOST, Vec::new())]);
        let fetcher = fetcher_with(
            resolver.clone(),
            address_allowed,
            DISCARD_PORT,
            None,
            MAX_BYTES,
        );
        let result = fetcher.fetch(url).await;
        assert!(
            matches!(result, Err(CimdError::Fetch(_))),
            "{url:?} must pass the shape and fail on the empty answer, got {result:?}"
        );
        assert_eq!(resolver.lookups(), 1, "{url:?} must be resolved once");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_host_must_be_a_public_style_name() {
    let refused = [
        "https://localhost/a",
        "https://intranet/a",
        "https://client.example.com./a",
        "https://.example.com/a",
        "https://a..b/a",
        "https://-a.example.com/a",
        "https://a-.example.com/a",
    ];
    for url in refused {
        let resolver = FakeResolver::new(&[(HOST, vec![LOOPBACK])]);
        let fetcher = fetcher_with(
            resolver.clone(),
            address_allowed,
            DISCARD_PORT,
            None,
            MAX_BYTES,
        );
        let result = fetcher.fetch(url).await;
        assert!(
            matches!(result, Err(CimdError::NotAllowed(_))),
            "{url:?} must be refused as not allowed, got {result:?}"
        );
        assert_eq!(
            resolver.lookups(),
            0,
            "{url:?} must be refused before any name lookup"
        );
    }
}

#[test]
fn ipv6_translated_and_documentation_ranges_are_refused() {
    let cases = [
        (v6([0, 0, 0, 0, 0xffff, 0, 0x0a00, 0x0001]), false),
        (v6([0, 0, 0, 0, 0xffff, 0, 0x0808, 0x0808]), false),
        (v6([0x3fff, 0x0fff, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x3fff, 0x1000, 0, 0, 0, 0, 0, 1]), true),
    ];
    for (ip, expected) in cases {
        assert_eq!(address_allowed(ip), expected, "address_allowed({ip})");
    }
}

#[test]
fn name_lookups_use_the_absolute_name() {
    assert_eq!(absolute(HOST), "client.example.com.");
}

/// A lookup that blocks until opened, counting its calls and its returns.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
    calls: AtomicUsize,
    returns: AtomicUsize,
}

impl Gate {
    fn open_gate(&self) {
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.opened.notify_all();
    }

    /// Parks the calling lookup until the gate is open.
    fn park(&self) {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
            open = self
                .opened
                .wait(open)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Opens the gate when dropped, so parked lookups return even when the test panics.
struct OpenOnExit(Arc<Gate>);

impl Drop for OpenOnExit {
    fn drop(&mut self) {
        self.0.open_gate();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lookups_are_capped_and_a_slot_is_held_until_the_lookup_returns() {
    let gate = Arc::new(Gate::default());
    let _open_on_exit = OpenOnExit(gate.clone());
    let lookup_gate = gate.clone();
    let lookup: LookupFn = Arc::new(move |_host: &str| {
        lookup_gate.calls.fetch_add(1, Ordering::SeqCst);
        lookup_gate.park();
        lookup_gate.returns.fetch_add(1, Ordering::SeqCst);
        Ok(vec![LOOPBACK])
    });
    let fetcher = HttpCimdFetcher::from_parts(FetcherParts {
        resolver: Arc::new(BlockingResolver::new(2, lookup)),
        address_allowed,
        port: DISCARD_PORT,
        extra_roots_pem: None,
        timeout: Duration::from_millis(200),
        max_bytes: MAX_BYTES,
    });

    // Two fetches take both slots and time out while their lookups block.
    for _ in 0..2 {
        let result = fetcher.fetch(URL).await;
        assert!(
            matches!(result, Err(CimdError::Fetch(_))),
            "a fetch whose lookup blocks must time out as a fetch error, got {result:?}"
        );
    }
    assert_eq!(gate.calls.load(Ordering::SeqCst), 2, "two lookups run");

    // With no free slot a fetch fails at once and never reaches the lookup.
    for attempt in ["third", "fourth"] {
        let started = Instant::now();
        let result = fetcher.fetch(URL).await;
        assert!(
            matches!(result, Err(CimdError::Fetch(_))),
            "the {attempt} fetch must fail as a fetch error, got {result:?}"
        );
        assert_eq!(
            gate.calls.load(Ordering::SeqCst),
            2,
            "the {attempt} fetch must not reach the lookup: two lookups must still run"
        );
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "the {attempt} fetch must fail at once, took {:?}",
            started.elapsed()
        );
    }

    gate.open_gate();
    let deadline = Instant::now() + FIVE_SECONDS;
    while gate.returns.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < deadline,
            "the two blocked lookups must return within 5 seconds once the gate is open"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // A slot is freed a few instructions after its lookup returns, so retry until one is free.
    let mut last = None;
    while gate.calls.load(Ordering::SeqCst) < 3 {
        assert!(
            Instant::now() < deadline,
            "a freed slot must reach the lookup, last result {last:?}"
        );
        last = Some(fetcher.fetch(URL).await);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        matches!(last, Some(Err(CimdError::NotAllowed(_)))),
        "the fetch that reached the lookup gets its answer, got {last:?}"
    );
    assert_eq!(gate.calls.load(Ordering::SeqCst), 3, "a fifth lookup runs");
}

#[test]
fn ipv6_outside_2000_3_is_refused() {
    let cases = [
        (v6([0x1000, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x0400, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x1fff, 0xffff, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x2000, 0, 0, 0, 0, 0, 0, 1]), true),
        (v6([0x3fff, 0x1000, 0, 0, 0, 0, 0, 1]), true),
        (v6([0x4000, 0, 0, 0, 0, 0, 0, 0]), false),
        (v6([0x5f00, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x8000, 0, 0, 0, 0, 0, 0, 1]), false),
        (v6([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]), true),
        (v6([0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808]), true),
        (v6([0x64, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001]), false),
        (v6([0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1]), true),
        (v6([0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1]), false),
    ];
    for (ip, expected) in cases {
        assert_eq!(address_allowed(ip), expected, "address_allowed({ip})");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_request_carries_the_gateways_user_agent() {
    let mut server = start_server(Reply::Document(document().to_string())).await;
    let result = server_fetcher(&server, MAX_BYTES).fetch(URL).await;
    assert_eq!(result, Ok(expected_metadata()), "the document must be read");
    let head = next_head(&mut server).await;
    let agent = format!("doorward/{}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        header_value(&head, "user-agent"),
        Some(agent.as_str()),
        "the request must carry the gateway's user agent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fetch_never_looks_a_name_up_a_second_time() {
    let mut server = start_server(Reply::Document(document().to_string())).await;
    let resolver = FakeResolver::new(&[(HOST, vec![LOOPBACK])]);
    let fetcher = fetcher_with(
        resolver.clone(),
        allow_any,
        server.port,
        Some(server.ca_pem.clone()),
        MAX_BYTES,
    );
    let result = fetcher.fetch(URL).await;
    assert_eq!(result, Ok(expected_metadata()), "the document must be read");
    assert_eq!(
        resolver.lookups(),
        1,
        "the name must be looked up exactly once"
    );
    let _ = next_head(&mut server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pinned_resolver_answers_every_name_with_the_checked_addresses() {
    let pinned = vec![
        SocketAddr::new(LOOPBACK, 8443),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443),
    ];
    let resolver = PinnedResolver::new(pinned.clone());
    for host in ["intranet.example.net", HOST] {
        let name: Name = host.parse().expect("a valid host name");
        let answer: Vec<SocketAddr> = resolver
            .resolve(name)
            .await
            .expect("the pinned answer")
            .collect();
        assert_eq!(
            answer, pinned,
            "{host} must be answered with exactly the pinned addresses"
        );
    }
}

/// The value of one header in a request head, matched without regard to case.
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        line.split_once(':')
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    })
}
