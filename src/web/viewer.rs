use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::accounts::session;
use crate::app::AppState;
use crate::crypto::{CsrfBinding, Keys, random_token};
use crate::report;

use super::address::{client_address, log_warnings};
use super::cookies::{CSRF_COOKIE, SESSION_COOKIE, cookie_value};

const ANON_PREFIX: &str = "dw_cs_";
const ANON_BODY_LEN: usize = 43;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    User,
}

#[derive(Debug, Clone)]
pub struct SessionUser {
    pub id: i64,
    pub email: String,
    pub role: Role,
}

/// Who is asking: the signed-in user, the client address and the CSRF binding of the browser.
pub struct Viewer {
    pub user: Option<SessionUser>,
    pub address: IpAddr,
    binding: Option<CsrfBinding>,
    presented: Option<String>,
    keys: Arc<Keys>,
}

impl Viewer {
    /// The token to put in this response's forms, when the browser has a binding.
    pub fn csrf_token(&self) -> Option<String> {
        self.binding
            .as_ref()
            .map(|binding| self.keys.csrf_token(binding))
    }

    pub fn is_admin(&self) -> bool {
        self.user
            .as_ref()
            .is_some_and(|user| matches!(user.role, Role::Owner | Role::Admin))
    }

    pub fn is_owner(&self) -> bool {
        self.user
            .as_ref()
            .is_some_and(|user| user.role == Role::Owner)
    }

    pub(crate) fn binding(&self) -> Option<&CsrfBinding> {
        self.binding.as_ref()
    }

    /// The session cookie as sent, valid or not. Used only to delete its row, never to sign in.
    pub(crate) fn presented_session(&self) -> Option<&str> {
        self.presented.as_deref()
    }

    /// The form token, and the new pre-session cookie value when the browser had no binding.
    pub(crate) fn form_token(&self) -> (String, Option<String>) {
        match self.csrf_token() {
            Some(token) => (token, None),
            None => {
                let value = random_token(ANON_PREFIX);
                let token = self.keys.csrf_token(&CsrfBinding::Anonymous(value.clone()));
                (token, Some(value))
            }
        }
    }

    /// Reads the cookies and the peer. Never fails: an unreadable session is no session.
    pub(crate) async fn resolve(parts: &Parts, state: &AppState) -> Viewer {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip());
        let trusted = &state.config.trusted_proxies;
        let address = client_address(peer, &parts.headers, trusted);
        log_warnings(
            peer,
            &parts.headers,
            trusted,
            state.config.https_public(),
            address,
        );
        let now = state.clock.now().unix_timestamp();
        let mut user = None;
        let mut binding = None;
        let presented = cookie_value(&parts.headers, SESSION_COOKIE);
        if let Some(value) = presented.as_deref() {
            match session::find(&state.db, value, now).await {
                Ok(Some(found)) => {
                    user = Some(found);
                    binding = Some(CsrfBinding::Session(value.to_owned()));
                }
                Ok(None) => {}
                // A database error reads as no session, so the request stays anonymous.
                Err(err) => report::failure("session lookup", &err),
            }
        }
        if binding.is_none() {
            binding = cookie_value(&parts.headers, CSRF_COOKIE)
                .filter(|value| is_anonymous_shape(value))
                .map(CsrfBinding::Anonymous);
        }
        Viewer {
            user,
            address,
            binding,
            presented,
            keys: Arc::clone(&state.keys),
        }
    }
}

impl FromRequestParts<AppState> for Viewer {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Viewer, Infallible> {
        Ok(Viewer::resolve(parts, state).await)
    }
}

/// True for "dw_cs_" followed by 43 base64url characters.
fn is_anonymous_shape(value: &str) -> bool {
    value.strip_prefix(ANON_PREFIX).is_some_and(|body| {
        body.len() == ANON_BODY_LEN
            && body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}
