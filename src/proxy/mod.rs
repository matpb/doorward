//! The upstream side of the gateway: the client, the tool catalog, the sessions and the relay.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::Request;
use axum::http::Method;
use axum::response::Response;

use crate::app::AppState;
use crate::mcp::answer;
use crate::oauth::guard::Caller;

pub mod catalog;
mod handle;
pub mod links;
pub mod sessions;
mod sse;
mod stream;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod tests_handle;
#[cfg(test)]
mod tests_links;
#[cfg(test)]
mod tests_stream;
pub mod upstream;

/// Relays one request of an authorized caller on `/{slug}`, under the POST order and the GET and DELETE rules.
pub async fn handle(state: &AppState, caller: Caller, slug: &str, request: Request) -> Response {
    let Some(server_id) = caller.server_id else {
        return answer::unavailable(slug);
    };
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let ctx = handle::Ctx {
        state,
        slug,
        server_id,
        caller: Arc::new(caller),
        started,
    };
    if parts.method == Method::POST {
        handle::post(&ctx, &parts.headers, body).await
    } else if parts.method == Method::GET || parts.method == Method::DELETE {
        handle::get_or_delete(&ctx, &parts.method, &parts.headers).await
    } else {
        handle::not_allowed()
    }
}
