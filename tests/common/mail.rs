//! Stand-ins for SMTP, Resend and Mailgun that capture every message they receive.

use std::convert::Infallible;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path as PathParam, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The channel a captured message arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    Smtp,
    Resend,
    Mailgun,
}

/// One message as a fake provider received it.
#[derive(Clone, Debug)]
pub struct Captured {
    pub via: Via,
    /// SMTP: the MAIL FROM address; HTTP: the `from` field as sent.
    pub from: String,
    /// SMTP: the RCPT TO addresses; HTTP: the `to` values.
    pub to: Vec<String>,
    pub subject: String,
    /// The plain-text body.
    pub text: String,
    /// The HTML body, empty when absent.
    pub html: String,
    /// SMTP: the full DATA content; HTTP: the raw request body as lossy UTF-8.
    pub raw: String,
    /// SMTP only: true when the message arrived over TLS.
    pub tls: bool,
    /// SMTP AUTH user, or "api" for Mailgun basic auth.
    pub auth_user: Option<String>,
    /// SMTP AUTH password, Resend bearer token, or Mailgun basic-auth password.
    pub auth_secret: Option<String>,
    /// HTTP request path, empty for SMTP.
    pub path: String,
    /// HTTP only.
    pub user_agent: Option<String>,
    /// HTTP only.
    pub content_type: Option<String>,
}

/// A failure armed with `fail_next`, applied to the next request of its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// SMTP answers `550 5.7.1 Relaying denied` to RCPT TO.
    SmtpReject,
    /// Resend answers 403 with a validation error for an unverified domain.
    ResendForbidden,
    /// Mailgun answers 401 with `Invalid private key`.
    MailgunUnauthorized,
}

#[derive(Default)]
struct Shared {
    messages: Mutex<Vec<Captured>>,
    fails: Mutex<Vec<Fail>>,
}

impl Shared {
    fn record(&self, message: Captured) {
        self.messages.lock().expect("messages lock").push(message);
    }

    /// Consumes the oldest armed failure of `kind`, reporting whether there was one.
    fn take_fail(&self, kind: Fail) -> bool {
        let mut fails = self.fails.lock().expect("fails lock");
        match fails.iter().position(|armed| *armed == kind) {
            Some(index) => {
                fails.remove(index);
                true
            }
            None => false,
        }
    }
}

/// Running fakes for the three mail channels, with a CA for the SMTP TLS ports.
pub struct MailCatcher {
    shared: Arc<Shared>,
    smtp_plain: u16,
    smtp_starttls: u16,
    smtp_tls: u16,
    resend: u16,
    mailgun: u16,
    ca_dir: TempDir,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for MailCatcher {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl MailCatcher {
    pub async fn start() -> MailCatcher {
        let shared = Arc::new(Shared::default());
        let ca_dir = tempfile::tempdir().expect("temp dir");
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(ca_dir.path())));
        let (smtp_plain, plain_task) =
            serve_smtp(Port::Plain, shared.clone(), acceptor.clone()).await;
        let (smtp_starttls, starttls_task) =
            serve_smtp(Port::StartTls, shared.clone(), acceptor.clone()).await;
        let (smtp_tls, tls_task) = serve_smtp(Port::Implicit, shared.clone(), acceptor).await;
        let (resend, resend_task) = serve_http(resend_router(shared.clone())).await;
        let (mailgun, mailgun_task) = serve_http(mailgun_router(shared.clone())).await;
        MailCatcher {
            shared,
            smtp_plain,
            smtp_starttls,
            smtp_tls,
            resend,
            mailgun,
            ca_dir,
            tasks: vec![
                plain_task,
                starttls_task,
                tls_task,
                resend_task,
                mailgun_task,
            ],
        }
    }

    /// SMTP on a port that offers no TLS.
    pub fn smtp_plain_port(&self) -> u16 {
        self.smtp_plain
    }

    /// SMTP that advertises STARTTLS and refuses MAIL FROM until TLS is up.
    pub fn smtp_starttls_port(&self) -> u16 {
        self.smtp_starttls
    }

    /// SMTP with implicit TLS from the first byte.
    pub fn smtp_tls_port(&self) -> u16 {
        self.smtp_tls
    }

    /// PEM file of the CA that signed the server certificate.
    pub fn ca_pem_path(&self) -> PathBuf {
        self.ca_dir.path().join("ca.pem")
    }

    pub fn resend_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.resend)
    }

    pub fn mailgun_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.mailgun)
    }

    pub fn messages(&self) -> Vec<Captured> {
        self.shared.messages.lock().expect("messages lock").clone()
    }

    /// Messages with `address` among their recipients, compared case-insensitively.
    pub fn to(&self, address: &str) -> Vec<Captured> {
        self.messages()
            .into_iter()
            .filter(|message| message.to.iter().any(|to| same_address(to, address)))
            .collect()
    }

    pub fn last_to(&self, address: &str) -> Option<Captured> {
        self.to(address).pop()
    }

    /// Returns the newest message to `address`, polling every 20 ms until one arrives or the timeout passes.
    pub async fn wait_to(&self, address: &str, timeout: Duration) -> Option<Captured> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(message) = self.last_to(address) {
                return Some(message);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let pause = (deadline - now).min(Duration::from_millis(20));
            tokio::time::sleep(pause).await;
        }
    }

    pub fn clear(&self) {
        self.shared.messages.lock().expect("messages lock").clear();
    }

    /// Makes the next request of the failure's kind answer with that failure.
    pub fn fail_next(&self, fail: Fail) {
        self.shared.fails.lock().expect("fails lock").push(fail);
    }
}

/// First URL in `text` that starts with `prefix`, up to the next whitespace, `"`, `<` or `>`.
pub fn link_with_prefix(text: &str, prefix: &str) -> Option<String> {
    let start = text.find(prefix)?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '<' | '>'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// True when the address part of `entry` equals `address`, ignoring case.
fn same_address(entry: &str, address: &str) -> bool {
    let entry = entry.trim();
    let entry = match entry.find('<') {
        Some(start) => match entry[start..].find('>') {
            Some(end) => entry[start + 1..start + end].trim(),
            None => entry,
        },
        None => entry,
    };
    entry.eq_ignore_ascii_case(address.trim())
}

async fn bind() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mail catcher")
}

async fn serve_http(router: Router) -> (u16, JoinHandle<()>) {
    let listener = bind().await;
    let port = listener.local_addr().expect("local address").port();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve mail catcher HTTP")
    });
    (port, task)
}

fn server_tls_config(dir: &Path) -> ServerConfig {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Harness mail CA");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA certificate");
    std::fs::write(dir.join("ca.pem"), ca.pem()).expect("write CA PEM");

    let server_key = KeyPair::generate().expect("server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("server params");
    let server = server_params
        .signed_by(&server_key, &*ca)
        .expect("server certificate");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![server.der().clone()], key)
        .expect("server certificate and key")
}

#[derive(Clone, Copy)]
enum Port {
    Plain,
    StartTls,
    Implicit,
}

/// What the SMTP session may do: plain text, offer STARTTLS, or already encrypted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plain,
    StartTls,
    Tls,
}

#[derive(Default)]
struct Envelope {
    from: Option<String>,
    to: Vec<String>,
}

async fn serve_smtp(
    port: Port,
    shared: Arc<Shared>,
    acceptor: TlsAcceptor,
) -> (u16, JoinHandle<()>) {
    let listener = bind().await;
    let number = listener.local_addr().expect("local address").port();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept SMTP connection");
            let shared = shared.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Err(err) = smtp_connection(stream, &shared, port, acceptor).await {
                    eprintln!("mail catcher: SMTP connection ended with error: {err}");
                }
            });
        }
    });
    (number, task)
}

const GREETING: &str = "220 localhost ESMTP";

/// Serves one connection; the greeting is sent once, before any TLS upgrade.
async fn smtp_connection(
    stream: TcpStream,
    shared: &Shared,
    port: Port,
    acceptor: TlsAcceptor,
) -> io::Result<()> {
    match port {
        Port::Plain => {
            let mut io = BufReader::new(stream);
            reply(&mut io, GREETING).await?;
            smtp_session(io, shared, Mode::Plain).await?;
        }
        Port::Implicit => {
            let mut io = BufReader::new(acceptor.accept(stream).await?);
            reply(&mut io, GREETING).await?;
            smtp_session(io, shared, Mode::Tls).await?;
        }
        Port::StartTls => {
            let mut io = BufReader::new(stream);
            reply(&mut io, GREETING).await?;
            if let Some(plain) = smtp_session(io, shared, Mode::StartTls).await? {
                let tls = acceptor.accept(plain).await?;
                smtp_session(BufReader::new(tls), shared, Mode::Tls).await?;
            }
        }
    }
    Ok(())
}

/// Runs one SMTP session. Returns the socket when the client asked for STARTTLS.
async fn smtp_session<S>(mut io: BufReader<S>, shared: &Shared, mode: Mode) -> io::Result<Option<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut envelope = Envelope::default();
    let mut auth = None;
    let mut line = String::new();
    loop {
        line.clear();
        if io.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        let command = line.trim_end_matches(['\r', '\n']);
        let (verb, arg) = command.split_once(' ').unwrap_or((command, ""));
        match verb.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" => {
                reply(&mut io, "250-localhost").await?;
                reply(&mut io, "250-AUTH PLAIN LOGIN").await?;
                if mode == Mode::StartTls {
                    reply(&mut io, "250-STARTTLS").await?;
                }
                reply(&mut io, "250 8BITMIME").await?;
            }
            "STARTTLS" if mode == Mode::StartTls => {
                reply(&mut io, "220 Ready to start TLS").await?;
                // Bytes buffered before the handshake would be lost, so such a client is dropped.
                if !io.buffer().is_empty() {
                    return Ok(None);
                }
                return Ok(Some(io.into_inner()));
            }
            "AUTH" => {
                if let Some(credentials) = smtp_auth(&mut io, arg).await? {
                    auth = Some(credentials);
                }
            }
            "MAIL" if mode == Mode::StartTls => {
                reply(&mut io, "530 5.7.0 Must issue a STARTTLS command first").await?;
            }
            "MAIL" => match strip_prefix_ci(arg, "FROM:").and_then(address_in_brackets) {
                None => reply(&mut io, "501 5.1.7 Bad sender address syntax").await?,
                Some(_) if envelope.from.is_some() => {
                    reply(&mut io, "503 5.5.1 Nested MAIL command").await?
                }
                Some(from) => {
                    envelope.from = Some(from);
                    reply(&mut io, "250 OK").await?;
                }
            },
            "RCPT" => {
                let to = strip_prefix_ci(arg, "TO:").and_then(address_in_brackets);
                match (envelope.from.is_some(), to) {
                    (false, _) => reply(&mut io, "503 5.5.1 Need MAIL command").await?,
                    (true, None) => {
                        reply(&mut io, "501 5.1.3 Bad recipient address syntax").await?
                    }
                    (true, Some(_)) if shared.take_fail(Fail::SmtpReject) => {
                        reply(&mut io, "550 5.7.1 Relaying denied").await?
                    }
                    (true, Some(to)) => {
                        envelope.to.push(to);
                        reply(&mut io, "250 OK").await?;
                    }
                }
            }
            "DATA" => {
                let Some(from) = envelope.from.clone() else {
                    reply(&mut io, "503 5.5.1 Need MAIL command").await?;
                    continue;
                };
                if envelope.to.is_empty() {
                    reply(&mut io, "503 5.5.1 Need RCPT command").await?;
                    continue;
                }
                reply(&mut io, "354 End data with <CR><LF>.<CR><LF>").await?;
                let Some(content) = read_data(&mut io).await? else {
                    return Ok(None);
                };
                let raw = String::from_utf8_lossy(&content).into_owned();
                let to = std::mem::take(&mut envelope.to);
                envelope = Envelope::default();
                let tls = mode == Mode::Tls;
                shared.record(smtp_capture(raw, from, to, tls, auth.clone()));
                reply(&mut io, "250 OK queued").await?;
            }
            "RSET" => {
                envelope = Envelope::default();
                reply(&mut io, "250 OK").await?;
            }
            "NOOP" => reply(&mut io, "250 OK").await?,
            "QUIT" => {
                reply(&mut io, "221 Bye").await?;
                return Ok(None);
            }
            _ => reply(&mut io, "500 Unrecognized command").await?,
        }
    }
}

async fn reply<S>(io: &mut BufReader<S>, line: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let writer = io.get_mut();
    writer.write_all(format!("{line}\r\n").as_bytes()).await?;
    writer.flush().await
}

async fn next_line<S>(io: &mut BufReader<S>) -> io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut line = String::new();
    io.read_line(&mut line).await?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Answers an AUTH command. Any credentials are accepted; returns them when the exchange completed.
async fn smtp_auth<S>(io: &mut BufReader<S>, arg: &str) -> io::Result<Option<(String, String)>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mechanism, initial) = arg.split_once(' ').unwrap_or((arg, ""));
    let initial = (!initial.is_empty()).then_some(initial);
    match mechanism.to_ascii_uppercase().as_str() {
        "PLAIN" => {
            let response = match initial {
                Some(response) => response.to_owned(),
                None => {
                    reply(io, "334 ").await?;
                    next_line(io).await?
                }
            };
            let credentials = decode_b64(&response).and_then(|bytes| {
                let fields: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
                match fields.as_slice() {
                    [_, user, secret] => Some((
                        String::from_utf8(user.to_vec()).ok()?,
                        String::from_utf8(secret.to_vec()).ok()?,
                    )),
                    _ => None,
                }
            });
            auth_outcome(io, credentials).await
        }
        "LOGIN" => {
            let user = match initial {
                Some(response) => response.to_owned(),
                None => {
                    reply(io, "334 VXNlcm5hbWU6").await?;
                    next_line(io).await?
                }
            };
            reply(io, "334 UGFzc3dvcmQ6").await?;
            let secret = next_line(io).await?;
            let credentials = decode_text(&user).zip(decode_text(&secret));
            auth_outcome(io, credentials).await
        }
        _ => {
            reply(io, "504 5.5.4 Unrecognized authentication type").await?;
            Ok(None)
        }
    }
}

async fn auth_outcome<S>(
    io: &mut BufReader<S>,
    credentials: Option<(String, String)>,
) -> io::Result<Option<(String, String)>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match credentials {
        Some(credentials) => {
            reply(io, "235 2.7.0 Authentication successful").await?;
            Ok(Some(credentials))
        }
        None => {
            reply(io, "501 5.5.2 Cannot decode response").await?;
            Ok(None)
        }
    }
}

/// Reads DATA lines up to the lone dot, undoing dot-stuffing. None when the client hangs up first.
async fn read_data<S>(io: &mut BufReader<S>) -> io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut content = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if io.read_until(b'\n', &mut line).await? == 0 {
            return Ok(None);
        }
        if line == b".\r\n" || line == b".\n" {
            return Ok(Some(content));
        }
        let unstuffed = if line.starts_with(b"..") {
            &line[1..]
        } else {
            &line[..]
        };
        content.extend_from_slice(unstuffed);
    }
}

fn smtp_capture(
    raw: String,
    from: String,
    to: Vec<String>,
    tls: bool,
    auth: Option<(String, String)>,
) -> Captured {
    let (headers, body) = split_entity(&raw);
    let subject = header(&headers, "subject")
        .map(decode_header)
        .unwrap_or_default();
    let (text, html) = bodies(&headers, &body);
    let (auth_user, auth_secret) = match auth {
        Some((user, secret)) => (Some(user), Some(secret)),
        None => (None, None),
    };
    Captured {
        via: Via::Smtp,
        from,
        to,
        subject,
        text,
        html,
        raw,
        tls,
        auth_user,
        auth_secret,
        path: String::new(),
        user_agent: None,
        content_type: None,
    }
}

/// Splits an address out of `<address>`, ignoring anything after the closing bracket.
fn address_in_brackets(text: &str) -> Option<String> {
    let inner = text.trim_start().strip_prefix('<')?;
    let (address, _) = inner.split_once('>')?;
    Some(address.to_owned())
}

/// Case-insensitive `strip_prefix`.
fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

fn decode_b64(encoded: &str) -> Option<Vec<u8>> {
    STANDARD.decode(encoded.trim()).ok()
}

fn decode_text(encoded: &str) -> Option<String> {
    String::from_utf8(decode_b64(encoded)?).ok()
}

type Headers = Vec<(String, String)>;

/// Splits a message into lower-cased, unfolded headers and its body, with LF line endings.
fn split_entity(text: &str) -> (Headers, String) {
    let normalized = text.replace("\r\n", "\n");
    let (head, body) = normalized
        .split_once("\n\n")
        .unwrap_or((normalized.as_str(), ""));
    let mut headers: Headers = Vec::new();
    for line in head.split('\n') {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = headers.last_mut() {
                value.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    (headers, body.to_owned())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.as_str() == name)
        .map(|(_, value)| value.as_str())
}

/// Returns the lower-cased media type and the boundary parameter, when present.
fn content_type(value: &str) -> (String, Option<String>) {
    let mut parts = value.split(';');
    let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    let boundary = parts.find_map(|param| {
        let (key, value) = param.trim().split_once('=')?;
        key.eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_owned())
    });
    (media, boundary)
}

/// Returns the text of each part of a multipart body, without its delimiter lines.
fn multipart_parts(body: &str, boundary: &str) -> Vec<String> {
    let delimiter = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut current: Option<String> = None;
    for line in body.split('\n') {
        match line.trim_end().strip_prefix(delimiter.as_str()) {
            Some("--") => break,
            Some("") => {
                parts.extend(current.take());
                current = Some(String::new());
            }
            _ => {
                if let Some(part) = current.as_mut() {
                    part.push_str(line);
                    part.push('\n');
                }
            }
        }
    }
    parts.extend(current);
    parts
}

/// Returns the plain-text and HTML bodies of a single-part or multipart message.
fn bodies(headers: &Headers, body: &str) -> (String, String) {
    let (media, boundary) = content_type(header(headers, "content-type").unwrap_or("text/plain"));
    if media.starts_with("multipart/") {
        let Some(boundary) = boundary else {
            return (String::new(), String::new());
        };
        let mut text = None;
        let mut html = None;
        for part in multipart_parts(body, &boundary) {
            let (part_headers, part_body) = split_entity(&part);
            let (part_media, _) =
                content_type(header(&part_headers, "content-type").unwrap_or("text/plain"));
            let encoding = header(&part_headers, "content-transfer-encoding").unwrap_or("7bit");
            let decoded = decode_body(&part_body, encoding);
            match part_media.as_str() {
                "text/plain" if text.is_none() => text = Some(decoded),
                "text/html" if html.is_none() => html = Some(decoded),
                _ => {}
            }
        }
        (text.unwrap_or_default(), html.unwrap_or_default())
    } else {
        let encoding = header(headers, "content-transfer-encoding").unwrap_or("7bit");
        let decoded = decode_body(body, encoding);
        if media == "text/html" {
            (String::new(), decoded)
        } else {
            (decoded, String::new())
        }
    }
}

fn decode_body(body: &str, encoding: &str) -> String {
    let bytes = match encoding.trim().to_ascii_lowercase().as_str() {
        "quoted-printable" => quoted(body.as_bytes(), false),
        "base64" => {
            let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            STANDARD
                .decode(compact)
                .unwrap_or_else(|err| format!("<invalid base64: {err}>").into_bytes())
        }
        _ => body.as_bytes().to_vec(),
    };
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes quoted-printable bytes. In a header, `_` stands for a space.
fn quoted(input: &[u8], header: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        if header && byte == b'_' {
            out.push(b' ');
            i += 1;
        } else if byte != b'=' {
            out.push(byte);
            i += 1;
        } else if let (Some(high), Some(low)) = (
            input.get(i + 1).copied().and_then(hex_digit),
            input.get(i + 2).copied().and_then(hex_digit),
        ) {
            out.push(high * 16 + low);
            i += 3;
        } else {
            let mut j = i + 1;
            while matches!(input.get(j), Some(b' ' | b'\t')) {
                j += 1;
            }
            if j == input.len() {
                break;
            }
            if input[j] == b'\n' {
                i = j + 1;
            } else {
                out.push(b'=');
                i += 1;
            }
        }
    }
    out
}

/// Decodes RFC 2047 encoded words in a header value; adjacent words lose the space between them.
fn decode_header(value: &str) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut rest = value;
    let mut after_word = false;
    while let Some(start) = rest.find("=?") {
        let (plain, tail) = rest.split_at(start);
        if !(after_word && plain.trim().is_empty()) {
            out.extend_from_slice(plain.as_bytes());
        }
        match encoded_word(tail) {
            Some((bytes, consumed)) => {
                out.extend_from_slice(&bytes);
                rest = &tail[consumed..];
                after_word = true;
            }
            None => {
                out.extend_from_slice(b"=?");
                rest = &tail[2..];
                after_word = false;
            }
        }
    }
    out.extend_from_slice(rest.as_bytes());
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes the encoded word at the start of `tail`; returns its bytes and length in `tail`.
fn encoded_word(tail: &str) -> Option<(Vec<u8>, usize)> {
    let body = tail.strip_prefix("=?")?;
    let charset_end = body.find('?')?;
    let after_charset = &body[charset_end + 1..];
    let encoding_end = after_charset.find('?')?;
    let encoding = &after_charset[..encoding_end];
    let after_encoding = &after_charset[encoding_end + 1..];
    let text_end = after_encoding.find("?=")?;
    let text = &after_encoding[..text_end];
    let consumed = 2 + charset_end + 1 + encoding_end + 1 + text_end + 2;
    let bytes = if encoding.eq_ignore_ascii_case("B") {
        STANDARD.decode(text).ok()?
    } else if encoding.eq_ignore_ascii_case("Q") {
        quoted(text.as_bytes(), true)
    } else {
        return None;
    };
    Some((bytes, consumed))
}

fn random_hex() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    strip_prefix_ci(value, "Bearer ").map(str::to_owned)
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let decoded = decode_text(strip_prefix_ci(value, "Basic ")?)?;
    let (user, secret) = decoded.split_once(':')?;
    Some((user.to_owned(), secret.to_owned()))
}

fn json_response(status: StatusCode, body: &str) -> Response {
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.to_owned(),
    )
        .into_response()
}

const RESEND_NO_KEY: &str =
    r#"{"statusCode":401,"name":"missing_api_key","message":"Missing API Key"}"#;
const RESEND_NO_AGENT: &str =
    r#"{"statusCode":403,"name":"validation_error","message":"Missing User-Agent header"}"#;
const RESEND_MISSING_FIELD: &str =
    r#"{"statusCode":422,"name":"validation_error","message":"Missing required field"}"#;
const RESEND_FORBIDDEN: &str = r#"{"statusCode":403,"name":"validation_error","message":"The example.com domain is not verified. Please, add and verify your domain."}"#;
const MAILGUN_INVALID_KEY: &str = r#"{"message":"Invalid private key"}"#;

fn resend_router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/emails", post(resend_emails))
        .fallback(not_found)
        .with_state(shared)
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// The `to` field as a list: one string, or a non-empty array of strings.
fn recipients(value: Option<&Value>) -> Option<Vec<String>> {
    match value? {
        Value::String(address) => Some(vec![address.clone()]),
        Value::Array(items) => {
            let list = items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?;
            (!list.is_empty()).then_some(list)
        }
        _ => None,
    }
}

fn optional_string(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

async fn resend_emails(
    State(shared): State<Arc<Shared>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return json_response(StatusCode::UNAUTHORIZED, RESEND_NO_KEY);
    };
    if !headers.contains_key(USER_AGENT) {
        return json_response(StatusCode::FORBIDDEN, RESEND_NO_AGENT);
    }
    // Bodies that are not JSON are answered like a body with no fields.
    let payload = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
    let from = payload.get("from").and_then(Value::as_str);
    let subject = payload.get("subject").and_then(Value::as_str);
    let (Some(from), Some(subject), Some(to)) = (from, subject, recipients(payload.get("to")))
    else {
        return json_response(StatusCode::UNPROCESSABLE_ENTITY, RESEND_MISSING_FIELD);
    };
    if shared.take_fail(Fail::ResendForbidden) {
        return json_response(StatusCode::FORBIDDEN, RESEND_FORBIDDEN);
    }
    shared.record(Captured {
        via: Via::Resend,
        from: from.to_owned(),
        to,
        subject: subject.to_owned(),
        text: optional_string(&payload, "text"),
        html: optional_string(&payload, "html"),
        raw: String::from_utf8_lossy(&body).into_owned(),
        tls: false,
        auth_user: None,
        auth_secret: Some(token),
        path: uri.path().to_owned(),
        user_agent: header_text(&headers, USER_AGENT),
        content_type: header_text(&headers, CONTENT_TYPE),
    });
    (StatusCode::OK, Json(json!({ "id": random_hex() }))).into_response()
}

fn mailgun_router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v3/{domain}/messages", post(mailgun_messages))
        .fallback(not_found)
        .with_state(shared)
}

/// Reads a multipart or URL-encoded form into (name, value) pairs in order.
async fn form_fields(
    content_type: Option<&str>,
    body: Bytes,
) -> Result<Vec<(String, String)>, String> {
    if let Some(content_type) =
        content_type.filter(|value| value.starts_with("multipart/form-data"))
    {
        let boundary = multer::parse_boundary(content_type).map_err(|err| err.to_string())?;
        let stream = futures_util::stream::iter([Ok::<Bytes, Infallible>(body)]);
        let mut multipart = multer::Multipart::new(stream, boundary);
        let mut fields = Vec::new();
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|err| err.to_string())?
        {
            let name = field.name().unwrap_or_default().to_owned();
            let value = field.text().await.map_err(|err| err.to_string())?;
            fields.push((name, value));
        }
        Ok(fields)
    } else {
        Ok(url::form_urlencoded::parse(&body)
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect())
    }
}

fn mailgun_missing(name: &str) -> Response {
    let message = format!("{name} parameter is missing");
    (StatusCode::BAD_REQUEST, Json(json!({ "message": message }))).into_response()
}

async fn mailgun_messages(
    State(shared): State<Arc<Shared>>,
    PathParam(domain): PathParam<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((user, secret)) =
        basic_credentials(&headers).filter(|(user, _)| user.as_str() == "api")
    else {
        return json_response(StatusCode::UNAUTHORIZED, MAILGUN_INVALID_KEY);
    };
    let content_type = header_text(&headers, CONTENT_TYPE);
    let fields = match form_fields(content_type.as_deref(), body.clone()).await {
        Ok(fields) => fields,
        Err(message) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "message": message }))).into_response();
        }
    };
    let first = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, value)| value.clone())
    };
    let to: Vec<String> = fields
        .iter()
        .filter(|(key, _)| key.as_str() == "to")
        .map(|(_, value)| value.clone())
        .collect();
    let Some(from) = first("from") else {
        return mailgun_missing("from");
    };
    if to.is_empty() {
        return mailgun_missing("to");
    }
    let Some(subject) = first("subject") else {
        return mailgun_missing("subject");
    };
    if shared.take_fail(Fail::MailgunUnauthorized) {
        return json_response(StatusCode::UNAUTHORIZED, MAILGUN_INVALID_KEY);
    }
    shared.record(Captured {
        via: Via::Mailgun,
        from,
        to,
        subject,
        text: first("text").unwrap_or_default(),
        html: first("html").unwrap_or_default(),
        raw: String::from_utf8_lossy(&body).into_owned(),
        tls: false,
        auth_user: Some(user),
        auth_secret: Some(secret),
        path: uri.path().to_owned(),
        user_agent: header_text(&headers, USER_AGENT),
        content_type,
    });
    let id = format!("<{}@{domain}>", random_hex());
    (
        StatusCode::OK,
        Json(json!({ "id": id, "message": "Queued. Thank you." })),
    )
        .into_response()
}
