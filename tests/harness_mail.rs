#[path = "common/mail.rs"]
mod mail;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, USER_AGENT};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lettre::message::{Mailbox, Message, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail::{Captured, Fail, MailCatcher, Via, link_with_prefix};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const LINK: &str = "https://gateway.example.com/invite/abc123";

fn sample_message() -> Message {
    Message::builder()
        .from(
            "gateway@example.com"
                .parse::<Mailbox>()
                .expect("from address"),
        )
        .to("bob@example.com".parse::<Mailbox>().expect("to address"))
        .subject("Hello ✓ world")
        .multipart(MultiPart::alternative_plain_html(
            format!("plain body {LINK} end"),
            "<p>html body</p>".to_owned(),
        ))
        .expect("message")
}

fn credentials() -> Credentials {
    Credentials::new("user@example.com".to_owned(), "pw1".to_owned())
}

fn trusted_tls(catcher: &MailCatcher) -> TlsParameters {
    let pem = std::fs::read(catcher.ca_pem_path()).expect("read CA PEM");
    let ca = Certificate::from_pem(&pem).expect("parse CA PEM");
    TlsParameters::builder("localhost".to_owned())
        .certificate_store(CertificateStore::None)
        .add_root_certificate(ca)
        .build_rustls()
        .expect("TLS parameters")
}

fn assert_smtp_message(message: &Captured, tls: bool) {
    assert_eq!(message.via, Via::Smtp);
    assert_eq!(message.tls, tls);
    assert_eq!(message.from, "gateway@example.com");
    assert_eq!(message.to, vec!["bob@example.com"]);
    assert_eq!(message.subject, "Hello ✓ world");
    assert!(message.text.contains(&format!("plain body {LINK} end")));
    assert_eq!(
        link_with_prefix(&message.text, "https://gateway.example.com/invite/").as_deref(),
        Some(LINK)
    );
    assert!(message.html.contains("<p>html body</p>"));
    assert!(message.raw.contains("multipart/alternative"));
    assert_eq!(message.auth_user.as_deref(), Some("user@example.com"));
    assert_eq!(message.auth_secret.as_deref(), Some("pw1"));
}

fn smtp_error_code(err: &lettre::transport::smtp::Error) -> Option<String> {
    err.status().map(|code| code.to_string())
}

async fn send_resend(client: &reqwest::Client, base: &str, to: &str) {
    let response = client
        .post(format!("{base}/emails"))
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .json(&json!({
            "from": "gateway@example.com",
            "to": [to],
            "subject": "Helper",
            "text": "helper",
        }))
        .send()
        .await
        .expect("resend request");
    assert_eq!(response.status(), StatusCode::OK);
}

fn mailgun_multipart(boundary: &str) -> String {
    let part = |name: &str, value: &str| {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
    };
    let mut body = String::new();
    body.push_str(&part("from", "Gateway <gateway@example.com>"));
    body.push_str(&part("to", "bob@example.com"));
    body.push_str(&part("to", "carol@example.com"));
    body.push_str(&part("subject", "Multipart"));
    body.push_str(&part("text", "hello"));
    body.push_str(&format!("--{boundary}--\r\n"));
    body
}

fn mailgun_urlencoded(subject: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("from", "Gateway <gateway@example.com>")
        .append_pair("to", "bob@example.com")
        .append_pair("to", "carol@example.com")
        .append_pair("subject", subject)
        .append_pair("text", "hi")
        .finish()
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_plain_captures() {
    let catcher = MailCatcher::start().await;
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
        .port(catcher.smtp_plain_port())
        .tls(Tls::None)
        .credentials(credentials())
        .build();
    transport
        .send(sample_message())
        .await
        .expect("send over plain SMTP");
    let messages = catcher.messages();
    assert_eq!(messages.len(), 1);
    assert_smtp_message(&messages[0], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_starttls_captures() {
    let catcher = MailCatcher::start().await;
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
        .port(catcher.smtp_starttls_port())
        .tls(Tls::Required(trusted_tls(&catcher)))
        .credentials(credentials())
        .build();
    transport
        .send(sample_message())
        .await
        .expect("send over STARTTLS");
    let messages = catcher.messages();
    assert_eq!(messages.len(), 1);
    assert_smtp_message(&messages[0], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_starttls_port_refuses_plain() {
    let catcher = MailCatcher::start().await;
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
        .port(catcher.smtp_starttls_port())
        .tls(Tls::None)
        .build();
    let err = transport
        .send(sample_message())
        .await
        .expect_err("plain send to the STARTTLS port must fail");
    assert!(err.is_permanent());
    assert_eq!(smtp_error_code(&err).as_deref(), Some("530"));
    assert!(catcher.messages().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_implicit_tls_captures() {
    let catcher = MailCatcher::start().await;
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
        .port(catcher.smtp_tls_port())
        .tls(Tls::Wrapper(trusted_tls(&catcher)))
        .credentials(credentials())
        .build();
    transport
        .send(sample_message())
        .await
        .expect("send over implicit TLS");
    let messages = catcher.messages();
    assert_eq!(messages.len(), 1);
    assert_smtp_message(&messages[0], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_untrusted_ca_fails() {
    let catcher = MailCatcher::start().await;
    let untrusted = TlsParameters::new_rustls("localhost".to_owned()).expect("TLS parameters");
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
        .port(catcher.smtp_starttls_port())
        .tls(Tls::Required(untrusted))
        .credentials(credentials())
        .build();
    let err = transport
        .send(sample_message())
        .await
        .expect_err("a client that does not trust the CA must fail");
    assert_eq!(
        err.to_string(),
        "Connection error: Connection error: invalid peer certificate: UnknownIssuer"
    );
    assert!(catcher.messages().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_reject_once() {
    let catcher = MailCatcher::start().await;
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("localhost")
        .port(catcher.smtp_plain_port())
        .tls(Tls::None)
        .credentials(credentials())
        .build();
    catcher.fail_next(Fail::SmtpReject);
    let err = transport
        .send(sample_message())
        .await
        .expect_err("the armed rejection must fail the first send");
    assert!(err.is_permanent());
    assert_eq!(smtp_error_code(&err).as_deref(), Some("550"));
    assert!(catcher.messages().is_empty());
    transport
        .send(sample_message())
        .await
        .expect("second send succeeds");
    assert_eq!(catcher.messages().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn resend_captures() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let body = json!({
        "from": "Gateway <gateway@example.com>",
        "to": ["bob@example.com"],
        "subject": "S",
        "html": "<p>h</p>",
        "text": "t",
    });
    let response = client
        .post(format!("{}/emails", catcher.resend_base()))
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .json(&body)
        .send()
        .await
        .expect("resend request");
    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().await.expect("JSON answer");
    assert!(answer["id"].as_str().is_some_and(|id| !id.is_empty()));

    let messages = catcher.messages();
    assert_eq!(messages.len(), 1);
    let message = &messages[0];
    assert_eq!(message.via, Via::Resend);
    assert_eq!(message.auth_secret.as_deref(), Some("re_test_key"));
    assert_eq!(message.auth_user, None);
    assert_eq!(message.to, vec!["bob@example.com"]);
    assert_eq!(message.path, "/emails");
    assert_eq!(message.from, "Gateway <gateway@example.com>");
    assert_eq!(message.subject, "S");
    assert_eq!(message.text, "t");
    assert_eq!(message.html, "<p>h</p>");
    assert_eq!(message.user_agent.as_deref(), Some("harness-test/1.0"));
    assert_eq!(message.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        serde_json::from_str::<Value>(&message.raw).expect("raw JSON"),
        body
    );

    let single = json!({
        "from": "Gateway <gateway@example.com>",
        "to": "carol@example.com",
        "subject": "S2",
    });
    let response = client
        .post(format!("{}/emails", catcher.resend_base()))
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .json(&single)
        .send()
        .await
        .expect("resend request with a string recipient");
    assert_eq!(response.status(), StatusCode::OK);
    let carol = catcher.to("carol@example.com");
    assert_eq!(carol.len(), 1);
    assert_eq!(carol[0].to, vec!["carol@example.com"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn resend_requires_auth_and_agent() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/emails", catcher.resend_base());
    let body = json!({
        "from": "Gateway <gateway@example.com>",
        "to": ["bob@example.com"],
        "subject": "S",
    });

    let no_key = client
        .post(&url)
        .header(USER_AGENT, "harness-test/1.0")
        .json(&body)
        .send()
        .await
        .expect("request without key");
    assert_eq!(no_key.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        no_key.json::<Value>().await.expect("JSON answer"),
        json!({"statusCode": 401, "name": "missing_api_key", "message": "Missing API Key"})
    );

    let no_agent = client
        .post(&url)
        .bearer_auth("re_test_key")
        .json(&body)
        .send()
        .await
        .expect("request without User-Agent");
    assert_eq!(no_agent.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        no_agent.json::<Value>().await.expect("JSON answer"),
        json!({
            "statusCode": 403,
            "name": "validation_error",
            "message": "Missing User-Agent header",
        })
    );
    assert!(catcher.messages().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn resend_forbidden_once() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/emails", catcher.resend_base());
    let body = json!({
        "from": "Gateway <gateway@example.com>",
        "to": ["bob@example.com"],
        "subject": "S",
    });
    catcher.fail_next(Fail::ResendForbidden);

    let first = client
        .post(&url)
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .json(&body)
        .send()
        .await
        .expect("first request");
    assert_eq!(first.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        first.json::<Value>().await.expect("JSON answer"),
        json!({
            "statusCode": 403,
            "name": "validation_error",
            "message": "The example.com domain is not verified. Please, add and verify your domain.",
        })
    );

    let second = client
        .post(&url)
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .json(&body)
        .send()
        .await
        .expect("second request");
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(catcher.messages().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn mailgun_multipart_and_urlencoded() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/v3/mg.example.com/messages", catcher.mailgun_base());

    let boundary = "harness-boundary";
    let multipart = client
        .post(&url)
        .basic_auth("api", Some("key-test"))
        .header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(mailgun_multipart(boundary))
        .send()
        .await
        .expect("multipart request");
    assert_eq!(multipart.status(), StatusCode::OK);
    let answer: Value = multipart.json().await.expect("JSON answer");
    assert_eq!(answer["message"], "Queued. Thank you.");

    let urlencoded = client
        .post(&url)
        .basic_auth("api", Some("key-test"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(mailgun_urlencoded("Form"))
        .send()
        .await
        .expect("urlencoded request");
    assert_eq!(urlencoded.status(), StatusCode::OK);
    let answer: Value = urlencoded.json().await.expect("JSON answer");
    assert_eq!(answer["message"], "Queued. Thank you.");

    let messages = catcher.messages();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].subject, "Multipart");
    assert_eq!(messages[0].text, "hello");
    assert!(
        messages[0]
            .content_type
            .as_deref()
            .is_some_and(|value| value.starts_with("multipart/form-data"))
    );
    assert_eq!(messages[1].subject, "Form");
    assert_eq!(messages[1].text, "hi");
    assert_eq!(
        messages[1].content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    for message in &messages {
        assert_eq!(message.via, Via::Mailgun);
        assert_eq!(message.auth_user.as_deref(), Some("api"));
        assert_eq!(message.auth_secret.as_deref(), Some("key-test"));
        assert_eq!(message.path, "/v3/mg.example.com/messages");
        assert_eq!(message.from, "Gateway <gateway@example.com>");
        assert_eq!(message.to, vec!["bob@example.com", "carol@example.com"]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mailgun_unauthorized() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/v3/mg.example.com/messages", catcher.mailgun_base());
    let expected = json!({"message": "Invalid private key"});

    let wrong_user = client
        .post(&url)
        .basic_auth("nope", Some("key-test"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(mailgun_urlencoded("Wrong user"))
        .send()
        .await
        .expect("request with wrong user");
    assert_eq!(wrong_user.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong_user.json::<Value>().await.expect("JSON answer"),
        expected
    );
    assert!(catcher.messages().is_empty());

    catcher.fail_next(Fail::MailgunUnauthorized);
    let armed = client
        .post(&url)
        .basic_auth("api", Some("key-test"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(mailgun_urlencoded("Armed"))
        .send()
        .await
        .expect("armed request");
    assert_eq!(armed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(armed.json::<Value>().await.expect("JSON answer"), expected);

    let retry = client
        .post(&url)
        .basic_auth("api", Some("key-test"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(mailgun_urlencoded("Retry"))
        .send()
        .await
        .expect("retry request");
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(catcher.messages().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn helpers() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let base = catcher.resend_base();

    send_resend(&client, &base, "Bob <bob@example.com>").await;
    let found = catcher.to("BOB@example.com");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].to, vec!["Bob <bob@example.com>"]);
    assert!(catcher.last_to("BOB@example.com").is_some());

    let started = Instant::now();
    assert!(
        catcher
            .wait_to("nobody@example.com", Duration::from_millis(100))
            .await
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_millis(100));

    let sender_base = base.clone();
    let sender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        send_resend(&reqwest::Client::new(), &sender_base, "dave@example.com").await;
    });
    let waited = catcher
        .wait_to("dave@example.com", Duration::from_secs(5))
        .await
        .expect("message sent 100 ms later is returned");
    assert_eq!(waited.to, vec!["dave@example.com"]);
    sender.await.expect("sender task");

    catcher.clear();
    assert!(catcher.messages().is_empty());

    assert_eq!(
        link_with_prefix(
            "see https://gateway.example.com/invite/abc123 now",
            "https://gateway.example.com/invite/"
        )
        .as_deref(),
        Some(LINK)
    );
}

/// A raw SMTP client that sends exact bytes, for protocol details lettre never produces.
struct Wire {
    io: BufReader<TcpStream>,
}

impl Wire {
    async fn connect(port: u16) -> Wire {
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to mail catcher");
        let mut wire = Wire {
            io: BufReader::new(stream),
        };
        wire.expect_line("220 localhost ESMTP").await;
        wire
    }

    async fn send_raw(&mut self, data: &str) {
        self.io
            .get_mut()
            .write_all(data.as_bytes())
            .await
            .expect("write to mail catcher");
    }

    async fn line(&mut self) -> String {
        let mut line = String::new();
        self.io
            .read_line(&mut line)
            .await
            .expect("read from mail catcher");
        line.trim_end_matches(['\r', '\n']).to_owned()
    }

    async fn expect_line(&mut self, want: &str) {
        assert_eq!(self.line().await, want);
    }

    /// Reads a reply up to its final line, the one whose fourth byte is a space.
    async fn reply(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let line = self.line().await;
            let last = line.as_bytes().get(3) == Some(&b' ');
            lines.push(line);
            if last {
                return lines;
            }
        }
    }

    async fn command(&mut self, line: &str, want: &str) {
        self.send_raw(&format!("{line}\r\n")).await;
        self.expect_line(want).await;
    }
}

async fn deliver(wire: &mut Wire, to: &str, content: &str) {
    wire.command("MAIL FROM:<gateway@example.com>", "250 OK")
        .await;
    wire.command(&format!("RCPT TO:<{to}>"), "250 OK").await;
    wire.command("DATA", "354 End data with <CR><LF>.<CR><LF>")
        .await;
    wire.send_raw(content).await;
    wire.expect_line("250 OK queued").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_raw_login_and_data() {
    let catcher = MailCatcher::start().await;
    let mut wire = Wire::connect(catcher.smtp_plain_port()).await;
    wire.send_raw("EHLO test.example.com\r\n").await;
    assert_eq!(
        wire.reply().await,
        ["250-localhost", "250-AUTH PLAIN LOGIN", "250 8BITMIME"]
    );
    wire.command("AUTH LOGIN", "334 VXNlcm5hbWU6").await;
    wire.command(&STANDARD.encode("alice@example.com"), "334 UGFzc3dvcmQ6")
        .await;
    wire.command(
        &STANDARD.encode("pw2"),
        "235 2.7.0 Authentication successful",
    )
    .await;
    wire.command("MAIL FROM:<sender@example.com>", "250 OK")
        .await;
    wire.command("RCPT TO:<rcpt@example.com>", "250 OK").await;
    wire.command("DATA", "354 End data with <CR><LF>.<CR><LF>")
        .await;
    wire.send_raw("Subject: Raw\r\n\r\n..leading dot\r\n.\r\n")
        .await;
    wire.expect_line("250 OK queued").await;
    wire.command("NOOP", "250 OK").await;
    wire.command("RSET", "250 OK").await;
    wire.command("VRFY rcpt@example.com", "500 Unrecognized command")
        .await;
    wire.command("QUIT", "221 Bye").await;
    assert_eq!(wire.line().await, "");

    let messages = catcher.messages();
    assert_eq!(messages.len(), 1);
    let message = &messages[0];
    assert_eq!(message.from, "sender@example.com");
    assert_eq!(message.to, vec!["rcpt@example.com"]);
    assert_eq!(message.subject, "Raw");
    assert_eq!(message.raw, "Subject: Raw\r\n\r\n.leading dot\r\n");
    assert_eq!(message.auth_user.as_deref(), Some("alice@example.com"));
    assert_eq!(message.auth_secret.as_deref(), Some("pw2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_two_step_plain_and_encoded_bodies() {
    let catcher = MailCatcher::start().await;
    let mut wire = Wire::connect(catcher.smtp_plain_port()).await;
    wire.send_raw("EHLO test.example.com\r\n").await;
    wire.reply().await;
    wire.command("AUTH PLAIN", "334 ").await;
    wire.command(
        &STANDARD.encode("\0bob@example.com\0pw3"),
        "235 2.7.0 Authentication successful",
    )
    .await;

    let multipart = format!(
        "From: gateway@example.com\r\n\
         To: bob@example.com\r\n\
         Subject: =?UTF-8?Q?Caf=C3=A9_ol=C3=A9?=\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/alternative; boundary=\"b1\"\r\n\
         \r\n\
         --b1\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {}\r\n\
         --b1\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\
         \r\n\
         <p>caf=C3=A9 =\r\n\
         lines</p>\r\n\
         --b1--\r\n\
         .\r\n",
        STANDARD.encode("hello body")
    );
    deliver(&mut wire, "bob@example.com", &multipart).await;
    deliver(
        &mut wire,
        "bob@example.com",
        "Subject: plain\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         héllo\r\n\
         .\r\n",
    )
    .await;

    let messages = catcher.messages();
    assert_eq!(messages.len(), 2);
    let first = &messages[0];
    assert_eq!(first.auth_user.as_deref(), Some("bob@example.com"));
    assert_eq!(first.auth_secret.as_deref(), Some("pw3"));
    assert_eq!(first.subject, "Café olé");
    assert_eq!(first.text, "hello body");
    assert_eq!(first.html, "<p>café lines</p>\n");
    let second = &messages[1];
    assert_eq!(second.subject, "plain");
    assert_eq!(second.text, "héllo\n");
    assert_eq!(second.html, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn smtp_starttls_port_advertises_and_refuses_mail() {
    let catcher = MailCatcher::start().await;
    let mut wire = Wire::connect(catcher.smtp_starttls_port()).await;
    wire.send_raw("EHLO test.example.com\r\n").await;
    assert_eq!(
        wire.reply().await,
        [
            "250-localhost",
            "250-AUTH PLAIN LOGIN",
            "250-STARTTLS",
            "250 8BITMIME"
        ]
    );
    wire.command(
        "MAIL FROM:<sender@example.com>",
        "530 5.7.0 Must issue a STARTTLS command first",
    )
    .await;
    assert!(catcher.messages().is_empty());

    let mut plain = Wire::connect(catcher.smtp_plain_port()).await;
    plain.send_raw("EHLO test.example.com\r\n").await;
    assert_eq!(
        plain.reply().await,
        ["250-localhost", "250-AUTH PLAIN LOGIN", "250 8BITMIME"]
    );
    plain.command("STARTTLS", "500 Unrecognized command").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http_errors_and_unknown_paths() {
    let catcher = MailCatcher::start().await;
    let client = reqwest::Client::new();
    let resend = format!("{}/emails", catcher.resend_base());
    let missing =
        json!({"statusCode": 422, "name": "validation_error", "message": "Missing required field"});

    let bodies = [
        json!({"from": "a@example.com", "subject": "S"}),
        json!({"to": ["b@example.com"], "subject": "S"}),
        json!({"from": "a@example.com", "to": ["b@example.com"]}),
    ];
    for body in &bodies {
        let response = client
            .post(&resend)
            .bearer_auth("re_test_key")
            .header(USER_AGENT, "harness-test/1.0")
            .json(body)
            .send()
            .await
            .expect("resend request");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response.json::<Value>().await.expect("JSON answer"),
            missing
        );
    }
    let not_json = client
        .post(&resend)
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .body("not json")
        .send()
        .await
        .expect("resend request with a body that is not JSON");
    assert_eq!(not_json.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        not_json.json::<Value>().await.expect("JSON answer"),
        missing
    );

    let unknown = client
        .post(format!("{}/other", catcher.resend_base()))
        .bearer_auth("re_test_key")
        .header(USER_AGENT, "harness-test/1.0")
        .json(&bodies[0])
        .send()
        .await
        .expect("request to an unknown Resend path");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let encode = |fields: &[(&str, &str)]| {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in fields {
            serializer.append_pair(key, value);
        }
        serializer.finish()
    };
    let mailgun = format!("{}/v3/mg.example.com/messages", catcher.mailgun_base());
    let cases = [
        (
            vec![("from", "a@example.com"), ("subject", "S")],
            "to parameter is missing",
        ),
        (
            vec![("to", "b@example.com"), ("subject", "S")],
            "from parameter is missing",
        ),
        (
            vec![("from", "a@example.com"), ("to", "b@example.com")],
            "subject parameter is missing",
        ),
    ];
    for (fields, message) in cases {
        let response = client
            .post(&mailgun)
            .basic_auth("api", Some("key-test"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(encode(&fields))
            .send()
            .await
            .expect("Mailgun request");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>().await.expect("JSON answer"),
            json!({ "message": message })
        );
    }

    let no_auth = client
        .post(&mailgun)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(encode(&[
            ("from", "a@example.com"),
            ("to", "b@example.com"),
            ("subject", "S"),
        ]))
        .send()
        .await
        .expect("Mailgun request without auth");
    assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        no_auth.json::<Value>().await.expect("JSON answer"),
        json!({"message": "Invalid private key"})
    );

    let unknown = client
        .post(format!(
            "{}/v3/mg.example.com/other",
            catcher.mailgun_base()
        ))
        .basic_auth("api", Some("key-test"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(encode(&[
            ("from", "a@example.com"),
            ("to", "b@example.com"),
            ("subject", "S"),
        ]))
        .send()
        .await
        .expect("request to an unknown Mailgun path");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert!(catcher.messages().is_empty());
}

#[test]
fn link_prefix_edges() {
    let prefix = "https://gateway.example.com/invite/";
    assert_eq!(link_with_prefix("no link here", prefix), None);
    assert_eq!(
        link_with_prefix(
            "<a href=\"https://gateway.example.com/invite/x1\">go</a>",
            prefix
        )
        .as_deref(),
        Some("https://gateway.example.com/invite/x1")
    );
    assert_eq!(
        link_with_prefix(
            "https://gateway.example.com/invite/first second https://gateway.example.com/invite/second",
            prefix
        )
        .as_deref(),
        Some("https://gateway.example.com/invite/first")
    );
}
