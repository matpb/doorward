//! Sends mail through the stored settings: raw SMTP, Resend or Mailgun. Failed sends are logged.

mod mailgun;
mod resend;
mod smtp;
pub mod templates;

use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::audit::{self, OwnedEvent};
use crate::crypto::Keys;
use crate::db;
use crate::report;

const SEND_LIMIT: Duration = Duration::from_secs(8);
const TEXT_LIMIT: usize = 300;
const NOT_SET_UP: &str = "Mail is not set up.";
const SETTINGS_UNREADABLE: &str = "The mail settings cannot be read.";
const SECRET_UNREADABLE: &str = "The stored mail secret cannot be opened.";
const PORT_INVALID: &str = "The stored SMTP port is not valid.";
const TLS_INVALID: &str = "The stored SMTP TLS mode is not valid.";
const TIMED_OUT: &str = "The mail server did not answer in time.";
const LOG_FAILED: &str = "The activity log could not be written.";
const BASE_INVALID: &str = "The base address is not a valid URL.";
const BASE_SCHEME: &str = "The base address must start with http:// or https://.";
const DEFAULT_RESEND_BASE: &str = "https://api.resend.com";
const DEFAULT_MAILGUN_BASE: &str = "https://api.mailgun.net";
const ANSWER_LIMIT: usize = 16 * 1024;

/// What the owner sends. The sender comes from the stored settings.
pub struct Message {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// The text the owner sees, at most 300 characters. Never holds a secret.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MailError(pub String);

/// The stored settings a send needs. `from` is shared by every provider.
struct Settings {
    from: String,
    provider: Provider,
}

enum Provider {
    Smtp(SmtpSettings),
    Resend(ResendSettings),
    Mailgun(MailgunSettings),
}

struct SmtpSettings {
    host: String,
    port: u16,
    username: String,
    password: Option<Zeroizing<String>>,
    tls: TlsMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TlsMode {
    Off,
    StartTls,
    Implicit,
}

struct ResendSettings {
    api_key: Zeroizing<String>,
    base_url: String,
}

struct MailgunSettings {
    api_key: Zeroizing<String>,
    domain: String,
    base_url: String,
}

/// A read failure: a database error, or a settings problem the owner is shown.
#[derive(Debug, thiserror::Error)]
enum ReadError {
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Mail(#[from] MailError),
}

/// Sends through the stored settings. On failure records `mail_failed` with `kind` and returns the
/// error. `kind` is one of `invitation`, `reset`, `new_connection` and `test`.
pub async fn send(state: &AppState, kind: &'static str, message: Message) -> Result<(), MailError> {
    match deliver(state, &message).await {
        Ok(()) => Ok(()),
        Err(error) => Err(record_failure(state, kind, error).await),
    }
}

async fn deliver(state: &AppState, message: &Message) -> Result<(), MailError> {
    let settings = load_settings(state).await?;
    match tokio::time::timeout(SEND_LIMIT, deliver_now(state, settings, message)).await {
        Ok(result) => result,
        Err(_) => Err(MailError(TIMED_OUT.to_owned())),
    }
}

async fn deliver_now(
    state: &AppState,
    settings: Settings,
    message: &Message,
) -> Result<(), MailError> {
    match settings.provider {
        Provider::Smtp(smtp) => {
            let ca_file = state.config.mail.smtp_ca_file.as_deref();
            smtp::send(ca_file, &settings.from, &smtp, message).await
        }
        Provider::Resend(resend) => {
            resend::send(&state.http, &settings.from, &resend, message).await
        }
        Provider::Mailgun(mailgun) => {
            mailgun::send(&state.http, &settings.from, &mailgun, message).await
        }
    }
}

/// One short database call: the plain values and the selected provider's secret.
async fn load_settings(state: &AppState) -> Result<Settings, MailError> {
    let keys = Arc::clone(&state.keys);
    let read = state
        .db
        .call(move |conn| match read_settings(conn, &keys) {
            Ok(settings) => Ok(Ok(settings)),
            Err(ReadError::Mail(err)) => Ok(Err(err)),
            Err(ReadError::Db(err)) => Err(err),
        })
        .await;
    match read {
        Ok(Ok(settings)) => Ok(settings),
        Ok(Err(err)) => Err(err),
        Err(err) => {
            report::failure("mail settings", &err);
            Err(MailError(SETTINGS_UNREADABLE.to_owned()))
        }
    }
}

fn read_settings(conn: &Connection, keys: &Keys) -> Result<Settings, ReadError> {
    let from = text_or_empty(conn, "mail.from")?;
    let provider = match db::setting_text(conn, "mail.provider")?.as_deref() {
        Some("smtp") => Provider::Smtp(read_smtp(conn, keys)?),
        Some("resend") => Provider::Resend(read_resend(conn, keys)?),
        Some("mailgun") => Provider::Mailgun(read_mailgun(conn, keys)?),
        _ => return Err(MailError(NOT_SET_UP.to_owned()).into()),
    };
    Ok(Settings { from, provider })
}

fn read_smtp(conn: &Connection, keys: &Keys) -> Result<SmtpSettings, ReadError> {
    let port_text = text_or_empty(conn, "mail.smtp_port")?;
    let port = match port_text.parse::<u16>() {
        Ok(port) if port >= 1 => port,
        _ => return Err(MailError(PORT_INVALID.to_owned()).into()),
    };
    let tls = match text_or_empty(conn, "mail.smtp_tls")?.as_str() {
        "off" => TlsMode::Off,
        "starttls" => TlsMode::StartTls,
        "implicit" => TlsMode::Implicit,
        _ => return Err(MailError(TLS_INVALID.to_owned()).into()),
    };
    Ok(SmtpSettings {
        host: text_or_empty(conn, "mail.smtp_host")?,
        port,
        username: text_or_empty(conn, "mail.smtp_username")?,
        password: secret(conn, keys, "mail.smtp_password")?,
        tls,
    })
}

fn read_resend(conn: &Connection, keys: &Keys) -> Result<ResendSettings, ReadError> {
    Ok(ResendSettings {
        api_key: secret_or_empty(conn, keys, "mail.resend_api_key")?,
        base_url: base_or_default(conn, "mail.resend_base_url", DEFAULT_RESEND_BASE)?,
    })
}

fn read_mailgun(conn: &Connection, keys: &Keys) -> Result<MailgunSettings, ReadError> {
    Ok(MailgunSettings {
        api_key: secret_or_empty(conn, keys, "mail.mailgun_api_key")?,
        domain: text_or_empty(conn, "mail.mailgun_domain")?,
        base_url: base_or_default(conn, "mail.mailgun_base_url", DEFAULT_MAILGUN_BASE)?,
    })
}

fn text_or_empty(conn: &Connection, key: &str) -> rusqlite::Result<String> {
    Ok(db::setting_text(conn, key)?.unwrap_or_default())
}

/// The stored base address, or the provider's own when it is empty.
fn base_or_default(conn: &Connection, key: &str, default: &str) -> rusqlite::Result<String> {
    let stored = text_or_empty(conn, key)?;
    Ok(if stored.is_empty() {
        default.to_owned()
    } else {
        stored
    })
}

/// The opened secret, or None when the key is absent.
fn secret(
    conn: &Connection,
    keys: &Keys,
    key: &str,
) -> Result<Option<Zeroizing<String>>, ReadError> {
    let Some(sealed) = db::setting_text(conn, key)? else {
        return Ok(None);
    };
    let context = format!("settings.value:{key}");
    let plain = Zeroizing::new(
        keys.open(&context, &sealed)
            .map_err(|_| MailError(SECRET_UNREADABLE.to_owned()))?,
    );
    let text = std::str::from_utf8(&plain).map_err(|_| MailError(SECRET_UNREADABLE.to_owned()))?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}

/// The opened secret, or an empty one when the key is absent.
fn secret_or_empty(
    conn: &Connection,
    keys: &Keys,
    key: &str,
) -> Result<Zeroizing<String>, ReadError> {
    Ok(secret(conn, keys, key)?.unwrap_or_else(|| Zeroizing::new(String::new())))
}

/// Writes the `mail_failed` row, its detail `<kind>: <text>`. The returned text is the one the owner
/// sees; the row holds the same text after the kind.
async fn record_failure(state: &AppState, kind: &'static str, error: MailError) -> MailError {
    let shown = limit(&error.0);
    let event = OwnedEvent {
        kind: "mail_failed".to_owned(),
        detail: format!("{kind}: {shown}"),
        ..Default::default()
    };
    match audit::record_now(state, event).await {
        Ok(()) => MailError(shown),
        Err(err) => {
            report::failure("mail failure record", &err);
            MailError(limit(&format!("{shown} {LOG_FAILED}")))
        }
    }
}

fn limit(text: &str) -> String {
    text.chars().take(TEXT_LIMIT).collect()
}

/// The base address with `segments` appended as percent-encoded path segments. Only http and https.
fn endpoint(base: &str, segments: &[&str]) -> Result<url::Url, MailError> {
    let mut url = url::Url::parse(base).map_err(|_| MailError(BASE_INVALID.to_owned()))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(MailError(BASE_SCHEME.to_owned())),
    }
    url.path_segments_mut()
        .map_err(|_| MailError(BASE_INVALID.to_owned()))?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// A connection or request failure, with the timeout named as such. The address is left out.
fn transport_error(error: reqwest::Error) -> MailError {
    if error.is_timeout() {
        MailError(TIMED_OUT.to_owned())
    } else {
        MailError(error.without_url().to_string())
    }
}

/// The first 16 KiB of a provider's answer as text. An unreadable answer is "".
async fn answer_text(mut response: reqwest::Response) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    while bytes.len() < ANSWER_LIMIT {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = ANSWER_LIMIT - bytes.len();
                bytes.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) => break,
            Err(_) => return String::new(),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The `message` field of a JSON answer, when it has one.
fn json_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("message")?
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_address_must_be_http_or_https() {
        let resend = endpoint("https://api.resend.com", &["emails"]).expect("https");
        assert_eq!(resend.as_str(), "https://api.resend.com/emails");
        let local = endpoint("http://127.0.0.1:9/", &["emails"]).expect("http");
        assert_eq!(local.as_str(), "http://127.0.0.1:9/emails");
        let scheme = endpoint("ftp://example.com", &["emails"]).expect_err("ftp is refused");
        assert_eq!(scheme.0, BASE_SCHEME);
        let invalid = endpoint("not a url", &["emails"]).expect_err("text is refused");
        assert_eq!(invalid.0, BASE_INVALID);
    }

    #[test]
    fn a_path_segment_is_percent_encoded() {
        let url = endpoint(
            "https://api.mailgun.net",
            &["v3", "mg/x.example.com", "messages"],
        )
        .expect("https");
        assert_eq!(url.path(), "/v3/mg%2Fx.example.com/messages");
    }

    #[test]
    fn a_failure_text_is_cut_to_300_characters() {
        let long = "é".repeat(400);
        assert_eq!(limit(&long).chars().count(), 300);
        assert_eq!(limit("short"), "short");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_is_read_for_at_most_16_kib() {
        let app = axum::Router::new().fallback(|| async { "y".repeat(1 << 20) });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .expect("answer");
        let text = answer_text(response).await;
        assert_eq!(text.len(), ANSWER_LIMIT);
    }

    #[test]
    fn the_message_field_of_a_json_answer_is_used_when_present() {
        assert_eq!(
            json_message(r#"{"message":"Invalid private key"}"#).as_deref(),
            Some("Invalid private key")
        );
        assert_eq!(json_message(r#"{"message":""}"#), None);
        assert_eq!(json_message("not json"), None);
        assert_eq!(json_message(r#"["message"]"#), None);
    }
}
