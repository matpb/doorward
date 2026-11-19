//! Mailgun's HTTP API: one form POST to `{base}/v3/{domain}/messages`, basic authentication as `api`.

use super::{
    MailError, MailgunSettings, Message, answer_text, endpoint, json_message, transport_error,
};

/// Sends `message` from `from` through the domain and key in `settings`.
pub async fn send(
    http: &reqwest::Client,
    from: &str,
    settings: &MailgunSettings,
    message: &Message,
) -> Result<(), MailError> {
    let url = endpoint(
        &settings.base_url,
        &["v3", settings.domain.as_str(), "messages"],
    )?;
    let fields = [
        ("from", from),
        ("to", message.to.as_str()),
        ("subject", message.subject.as_str()),
        ("text", message.text.as_str()),
        ("html", message.html.as_str()),
    ];
    let response = http
        .post(url)
        .basic_auth("api", Some(settings.api_key.as_str()))
        .form(&fields)
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    // An unreadable answer leaves only the status in the message.
    let answer = answer_text(response).await;
    let shown = json_message(&answer).or_else(|| {
        let text = answer.trim();
        (!text.is_empty()).then(|| text.to_owned())
    });
    Err(MailError(shown.unwrap_or_else(|| {
        format!("Mailgun answered {}", status.as_u16())
    })))
}
