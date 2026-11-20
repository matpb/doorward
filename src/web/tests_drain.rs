//! The unread request body: an answer waits until the gateway has read the rest of the body, or
//! has given up on it, so the connection closes cleanly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout};

use crate::app::{Deps, assemble, serve};
use crate::cimd::UnavailableCimd;
use crate::clock::SystemClock;
use crate::config::{Config, Limits};
use crate::crypto::PasswordHasher;

const FORM: &str = "Content-Type: application/x-www-form-urlencoded\r\n";
const BEARER_WRONG: &str = "Authorization: Bearer wrong\r\n";
const SILENCE: Duration = Duration::from_millis(300);

/// A gateway on a real port with a temporary database; `edit` changes its config first.
struct Gateway {
    address: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn start(edit: impl FnOnce(&mut Config)) -> Gateway {
    let dir = tempfile::tempdir().expect("temporary directory");
    let hasher = PasswordHasher::new().await.expect("hasher");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let mut config = Config {
        public_url: format!("http://{address}"),
        listen: address,
        database: dir.path().join("doorward.db"),
        key_file: None,
        trusted_proxies: Vec::new(),
        shared_client_address: false,
        allowed_origins: Vec::new(),
        lifetimes: Default::default(),
        limits: Limits::default(),
        mail: Default::default(),
    };
    edit(&mut config);
    let deps = Deps {
        clock: Arc::new(SystemClock),
        cimd: Arc::new(UnavailableCimd),
    };
    let gateway = assemble(config, deps, Arc::new(hasher))
        .await
        .expect("build");
    tokio::spawn(serve(listener, gateway.router, std::future::pending()));
    Gateway { address, _dir: dir }
}

async fn connect(gateway: &Gateway) -> TcpStream {
    TcpStream::connect(gateway.address)
        .await
        .expect("the gateway accepts a connection")
}

/// The head of one request on a connection that closes after its answer.
fn head(method: &str, path: &str, headers: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Connection: close\r\n\r\n")
}

/// `n` bytes of body.
fn part(n: usize) -> Vec<u8> {
    vec![b'a'; n]
}

/// One chunk of a chunked body.
fn chunk(data: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{:x}\r\n", data.len()).into_bytes();
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(b"\r\n");
    bytes
}

/// Asserts that no byte of an answer arrives within `span`.
async fn assert_silent(stream: &mut TcpStream, span: Duration, what: &str) {
    let mut byte = [0u8; 1];
    match timeout(span, stream.read(&mut byte)).await {
        Err(_elapsed) => {}
        Ok(Ok(0)) => panic!("{what}: the gateway closed the connection without answering"),
        Ok(Ok(_)) => panic!("{what}: an answer arrived before the request body was complete"),
        Ok(Err(err)) => panic!("{what}: the connection failed: {err}"),
    }
}

/// Reads every byte until the gateway closes; a reset or any other read error fails the test.
async fn read_to_close(stream: &mut TcpStream) -> Vec<u8> {
    let mut answer = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .expect("the gateway closes within 5 seconds")
        .expect("the connection closes cleanly");
    answer
}

/// The status code of a raw HTTP/1.1 answer.
fn status_of(answer: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(answer);
    text.split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"))
}

/// The value of header `name` in a raw answer, matched without regard to case.
fn header_of(answer: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(answer);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

#[tokio::test]
async fn an_early_answer_waits_for_the_rest_of_the_body() {
    let gateway = start(|_| {}).await;
    let mut stream = connect(&gateway).await;
    let headers = format!("{FORM}Content-Length: 300000\r\n");
    stream
        .write_all(head("POST", "/oauth/token", &headers).as_bytes())
        .await
        .expect("the head is written");
    stream
        .write_all(&part(100_000))
        .await
        .expect("the first part is written");
    assert_silent(&mut stream, SILENCE, "POST /oauth/token").await;
    stream
        .write_all(&part(200_000))
        .await
        .expect("the second part is written");
    let answer = read_to_close(&mut stream).await;
    assert_eq!(status_of(&answer), 400);
}

#[tokio::test]
async fn a_bad_bearer_with_a_large_body_is_still_challenged() {
    let gateway = start(|_| {}).await;
    let mut stream = connect(&gateway).await;
    let headers = format!("{FORM}{BEARER_WRONG}Content-Length: 300000\r\n");
    stream
        .write_all(head("POST", "/demo", &headers).as_bytes())
        .await
        .expect("the head is written");
    stream
        .write_all(&part(100_000))
        .await
        .expect("the first part is written");
    assert_silent(&mut stream, SILENCE, "POST /demo").await;
    stream
        .write_all(&part(200_000))
        .await
        .expect("the second part is written");
    let answer = read_to_close(&mut stream).await;
    assert_eq!(status_of(&answer), 401);
    assert!(
        header_of(&answer, "www-authenticate").is_some(),
        "the challenge carries WWW-Authenticate"
    );
}

#[tokio::test]
async fn a_limited_request_with_a_body_is_still_told_to_wait() {
    let gateway = start(|config| {
        config.limits.general_burst = 1;
        config.limits.general_per_minute = 1;
    })
    .await;
    let mut first = connect(&gateway).await;
    first
        .write_all(head("GET", "/no/such/page", "").as_bytes())
        .await
        .expect("the first head is written");
    assert_eq!(status_of(&read_to_close(&mut first).await), 404);
    let mut stream = connect(&gateway).await;
    let headers = format!("{FORM}Content-Length: 300000\r\n");
    stream
        .write_all(head("POST", "/no/such/page", &headers).as_bytes())
        .await
        .expect("the head is written");
    stream
        .write_all(&part(100_000))
        .await
        .expect("the first part is written");
    assert_silent(&mut stream, SILENCE, "POST /no/such/page").await;
    stream
        .write_all(&part(200_000))
        .await
        .expect("the second part is written");
    let answer = read_to_close(&mut stream).await;
    assert_eq!(status_of(&answer), 429);
    let retry = header_of(&answer, "retry-after").expect("a limited answer carries Retry-After");
    assert!(
        retry.parse::<u64>().is_ok_and(|seconds| seconds >= 1),
        "Retry-After is whole seconds of at least 1, got {retry:?}"
    );
}

#[tokio::test]
async fn a_client_that_never_sends_the_rest_is_answered_after_the_limit() {
    let gateway = start(|_| {}).await;
    let mut stream = connect(&gateway).await;
    let headers = format!("{BEARER_WRONG}Content-Length: 300000\r\n");
    stream
        .write_all(head("POST", "/demo", &headers).as_bytes())
        .await
        .expect("the head is written");
    stream
        .write_all(&part(100))
        .await
        .expect("the first bytes are written");
    let started = Instant::now();
    let mut buffer = [0u8; 4096];
    let read = timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .expect("the answer arrives within 5 seconds")
        .expect("the answer is read");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1500),
        "the answer came after {waited:?}, before the gateway had waited for the rest"
    );
    assert_eq!(status_of(&buffer[..read]), 401);
}

#[tokio::test]
async fn a_body_over_the_limit_is_answered_at_once() {
    let gateway = start(|_| {}).await;
    let mut stream = connect(&gateway).await;
    let declared = Limits::default().body_bytes + 1;
    let headers = format!("{BEARER_WRONG}Content-Length: {declared}\r\n");
    stream
        .write_all(head("POST", "/demo", &headers).as_bytes())
        .await
        .expect("the head is written");
    let mut buffer = [0u8; 4096];
    let read = timeout(Duration::from_secs(1), stream.read(&mut buffer))
        .await
        .expect("the answer arrives within 1 second")
        .expect("the answer is read");
    assert_eq!(status_of(&buffer[..read]), 401);
}

#[tokio::test]
async fn a_chunked_body_is_drained_too() {
    let gateway = start(|_| {}).await;
    let mut stream = connect(&gateway).await;
    let headers = format!("{FORM}Transfer-Encoding: chunked\r\n");
    stream
        .write_all(head("POST", "/oauth/token", &headers).as_bytes())
        .await
        .expect("the head is written");
    sleep(SILENCE).await;
    for _ in 0..3 {
        stream
            .write_all(&chunk(&part(50_000)))
            .await
            .expect("a chunk is written");
    }
    assert_silent(&mut stream, SILENCE, "POST /oauth/token").await;
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .expect("the last chunk is written");
    let answer = read_to_close(&mut stream).await;
    assert_eq!(status_of(&answer), 400);
}
