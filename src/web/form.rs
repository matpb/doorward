use axum::body::to_bytes;
use axum::extract::{FromRequest, Request};
use axum::http::HeaderMap;
use axum::http::header::{CONTENT_TYPE, ORIGIN};
use axum::response::Response;

use crate::app::AppState;
use crate::crypto::constant_time_eq;

use super::page::forbidden;
use super::viewer::Viewer;

const FORM_LIMIT: usize = 64 * 1024;
const FORM_TYPE: &str = "application/x-www-form-urlencoded";
const CSRF_FIELD: &str = "csrf";

/// A form post that passed the Origin and CSRF checks. The only way a handler reads a form.
pub struct VerifiedForm {
    pub viewer: Viewer,
    pub fields: FormFields,
}

/// The fields of a form in body order, without `csrf`.
pub struct FormFields(Vec<(String, String)>);

impl FormFields {
    /// The first value of `name`, or "" when absent.
    pub fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map_or("", |(_, value)| value.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Every name and value, in body order.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

impl FromRequest<AppState> for VerifiedForm {
    type Rejection = Response;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Response> {
        let (parts, body) = request.into_parts();
        if !origin_is(&parts.headers, &state.config.public_url) || !is_form_type(&parts.headers) {
            return Err(forbidden());
        }
        let viewer = Viewer::resolve(&parts, state).await;
        let bytes = to_bytes(body, FORM_LIMIT).await.map_err(|_| forbidden())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| forbidden())?;
        let mut pairs: Vec<(String, String)> = form_urlencoded::parse(text.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let submitted: Vec<&str> = pairs
            .iter()
            .filter(|(key, _)| key == CSRF_FIELD)
            .map(|(_, value)| value.as_str())
            .collect();
        let [submitted] = submitted.as_slice() else {
            return Err(forbidden());
        };
        let Some(binding) = viewer.binding() else {
            return Err(forbidden());
        };
        let expected = state.keys.csrf_token(binding);
        if !constant_time_eq(submitted.as_bytes(), expected.as_bytes()) {
            return Err(forbidden());
        }
        pairs.retain(|(key, _)| key != CSRF_FIELD);
        Ok(VerifiedForm {
            viewer,
            fields: FormFields(pairs),
        })
    }
}

/// True when exactly one Origin header is present and it equals the public address.
fn origin_is(headers: &HeaderMap, public_url: &str) -> bool {
    let mut values = headers.get_all(ORIGIN).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().is_ok_and(|text| text == public_url),
        _ => false,
    }
}

fn is_form_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(FORM_TYPE))
}
