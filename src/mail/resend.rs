//! Resend's HTTP API: one JSON POST to `{base}/emails`.

use reqwest::header::USER_AGENT;
use serde_json::json;

use super::{
    MailError, Message, ResendSettings, answer_text, endpoint, json_message, transport_error,
};

const AGENT: &str = concat!("doorward/", env!("CARGO_PKG_VERSION"));

/// Sends `message` from `from` with the key in `settings`.
pub async fn send(
    http: &reqwest::Client,
    from: &str,
    settings: &ResendSettings,
    message: &Message,
) -> Result<(), MailError> {
    let url = endpoint(&settings.base_url, &["emails"])?;
    let body = json!({
        "from": from,
        "to": [message.to],
        "subject": message.subject,
        "text": message.text,
        "html": message.html,
    });
    let response = http
        .post(url)
        .bearer_auth(settings.api_key.as_str())
        .header(USER_AGENT, AGENT)
        .json(&body)
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    // An unreadable answer leaves only the status in the message.
    let answer = answer_text(response).await;
    Err(MailError(json_message(&answer).unwrap_or_else(|| {
        format!("Resend answered {}", status.as_u16())
    })))
}
