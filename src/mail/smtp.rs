//! Raw SMTP through lettre. The TLS mode is the stored one; trust is the system roots plus the CA file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as Email, Tokio1Executor};

use super::{MailError, Message, SmtpSettings, TlsMode};
use crate::crypto::random_id;

/// lettre's timeout: applies to connecting and to each command.
const IO_LIMIT: Duration = Duration::from_secs(5);
const FROM_INVALID: &str = "The From address is not valid.";
const TO_INVALID: &str = "The recipient address is not valid.";
const CA_UNREADABLE: &str = "The SMTP CA file cannot be read.";
const MESSAGE_INVALID: &str = "The message cannot be built.";

/// Sends `message` from `from` through the server in `settings`.
pub async fn send(
    ca_file: Option<&Path>,
    from: &str,
    settings: &SmtpSettings,
    message: &Message,
) -> Result<(), MailError> {
    let sender: Mailbox = from
        .parse()
        .map_err(|_| MailError(FROM_INVALID.to_owned()))?;
    let recipient: Mailbox = message
        .to
        .parse()
        .map_err(|_| MailError(TO_INVALID.to_owned()))?;
    let domain = sender.email.domain().to_owned();
    let email = build_message(sender, recipient, message, message_id(&domain))?;
    let tls = match settings.tls {
        TlsMode::Off => Tls::None,
        TlsMode::StartTls => Tls::Required(tls_parameters(ca_file, &settings.host).await?),
        TlsMode::Implicit => Tls::Wrapper(tls_parameters(ca_file, &settings.host).await?),
    };
    // builder_dangerous only sets the server and the plain defaults; TLS is the mode chosen above.
    let mut builder =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(settings.host.as_str())
            .port(settings.port)
            .tls(tls)
            .hello_name(ClientId::Domain(domain))
            .timeout(Some(IO_LIMIT));
    if let Some(credentials) = login(settings) {
        builder = builder.credentials(credentials);
    }
    let transport: AsyncSmtpTransport<Tokio1Executor> = builder.build();
    transport
        .send(email)
        .await
        .map(|_| ())
        .map_err(|err| MailError(err.to_string()))
}

/// The login, when both the username and the stored password are set.
fn login(settings: &SmtpSettings) -> Option<Credentials> {
    let password = settings.password.as_ref()?;
    (!settings.username.is_empty() && !password.is_empty())
        .then(|| Credentials::new(settings.username.clone(), password.as_str().to_owned()))
}

/// Trust roots: the system's, plus every certificate of the CA file when one is set.
async fn tls_parameters(ca_file: Option<&Path>, host: &str) -> Result<TlsParameters, MailError> {
    let mut builder = TlsParameters::builder(host.to_owned());
    if let Some(certificate) = ca_certificate(ca_file).await? {
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().map_err(|err| MailError(err.to_string()))
}

/// The certificates of the CA file, read off the async threads.
async fn ca_certificate(ca_file: Option<&Path>) -> Result<Option<Certificate>, MailError> {
    let Some(path) = ca_file else {
        return Ok(None);
    };
    let path: PathBuf = path.to_path_buf();
    let pem = tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(|_| MailError(CA_UNREADABLE.to_owned()))?
        .map_err(|_| MailError(CA_UNREADABLE.to_owned()))?;
    Certificate::from_pem(&pem)
        .map(Some)
        .map_err(|err| MailError(err.to_string()))
}

/// `<32 random hex characters@domain>`, so the host name never appears in the message.
fn message_id(domain: &str) -> String {
    format!("<{}@{domain}>", random_id())
}

/// The multipart/alternative message: a plain-text part and an HTML part.
fn build_message(
    sender: Mailbox,
    recipient: Mailbox,
    message: &Message,
    id: String,
) -> Result<Email, MailError> {
    Email::builder()
        .from(sender)
        .to(recipient)
        .subject(message.subject.as_str())
        .message_id(Some(id))
        .multipart(MultiPart::alternative_plain_html(
            message.text.clone(),
            message.html.clone(),
        ))
        .map_err(|_| MailError(MESSAGE_INVALID.to_owned()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;

    const FROM: &str = "gateway@example.com";

    fn sample() -> Message {
        Message {
            to: "probe@example.com".to_owned(),
            subject: "Doorward test email".to_owned(),
            text: "Plain text.".to_owned(),
            html: "<p>HTML.</p>".to_owned(),
        }
    }

    fn built(from: &str) -> Result<Email, MailError> {
        let sender: Mailbox = from.parse().expect("sender");
        let recipient: Mailbox = "probe@example.com".parse().expect("recipient");
        let id = message_id("example.com");
        build_message(sender, recipient, &sample(), id)
    }

    /// The machine's host name, or None when it cannot be read or is localhost.
    fn host_name() -> Option<String> {
        let name = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
        let name = name.trim().to_owned();
        (!name.is_empty() && name != "localhost").then_some(name)
    }

    #[test]
    fn message_id_ends_with_the_from_domain() {
        let formatted =
            String::from_utf8(built(FROM).expect("message").formatted()).expect("utf-8 headers");
        let id_line = formatted
            .lines()
            .find(|line| line.starts_with("Message-ID:"))
            .expect("a Message-ID header");
        let id = id_line.trim_start_matches("Message-ID:").trim();
        assert!(id.ends_with("@example.com>"), "Message-ID was {id}");
        let local = id.trim_start_matches('<').trim_end_matches("@example.com>");
        assert_eq!(local.len(), 32, "the local part must be 32 hex characters");
        assert!(local.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn no_header_holds_this_machine_host_name() {
        let Some(name) = host_name() else {
            return;
        };
        let formatted =
            String::from_utf8(built(FROM).expect("message").formatted()).expect("utf-8 headers");
        let head = formatted.split("\r\n\r\n").next().unwrap_or_default();
        assert!(
            !head.contains(&name),
            "no header may contain the host name {name}"
        );
    }

    #[test]
    fn a_message_has_plain_and_html_parts() {
        let formatted =
            String::from_utf8(built(FROM).expect("message").formatted()).expect("utf-8 headers");
        assert!(formatted.contains("multipart/alternative"));
        assert!(formatted.contains("text/plain"));
        assert!(formatted.contains("text/html"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unparseable_sender_or_recipient_is_refused_before_any_connection() {
        let settings = SmtpSettings {
            host: "127.0.0.1".to_owned(),
            port: 9,
            username: String::new(),
            password: None,
            tls: TlsMode::Off,
        };
        let refused = send(None, "not an address", &settings, &sample())
            .await
            .expect_err("the sender must be refused");
        assert_eq!(refused.0, FROM_INVALID);
        let mut bad = sample();
        bad.to = "nobody".to_owned();
        let refused = send(None, FROM, &settings, &bad)
            .await
            .expect_err("the recipient must be refused");
        assert_eq!(refused.0, TO_INVALID);
    }

    /// Accepts one connection, returns the first command line it reads, then closes.
    async fn first_command(listener: TcpListener) -> String {
        let (stream, _) = listener.accept().await.expect("accept");
        let (read, mut write) = stream.into_split();
        write
            .write_all(b"220 test ESMTP\r\n")
            .await
            .expect("greeting");
        let mut lines = BufReader::new(read).lines();
        lines.next_line().await.expect("read").unwrap_or_default()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_smtp_hello_name_is_the_from_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let server = tokio::spawn(first_command(listener));
        let settings = SmtpSettings {
            host: "127.0.0.1".to_owned(),
            port,
            username: String::new(),
            password: None,
            tls: TlsMode::Off,
        };
        let outcome = send(None, FROM, &settings, &sample()).await;
        assert!(outcome.is_err(), "the fake server closes after the hello");
        let hello = server.await.expect("server task");
        assert_eq!(hello, "EHLO example.com");
    }
}
