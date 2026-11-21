//! The two well-known documents. Built from the configured public address only.

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::app::AppState;
use crate::servers::valid_slug;
use crate::web::not_found_bare;

/// The slug the combined endpoint is published under.
const COMBINED_SLUG: &str = "mcp";

/// `GET /.well-known/oauth-authorization-server`.
pub async fn authorization_server(State(state): State<AppState>) -> Json<Value> {
    Json(authorization_document(&state.config.public_url))
}

/// `GET /.well-known/oauth-protected-resource/{slug}`: any valid path, existing or not, and `mcp`.
pub async fn protected_resource(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Response {
    if slug != COMBINED_SLUG && !valid_slug(&slug) {
        return not_found_bare();
    }
    Json(resource_document(&state.config.public_url, &slug)).into_response()
}

/// The authorization server metadata of the interface reference.
pub fn authorization_document(public_url: &str) -> Value {
    json!({
        "issuer": public_url,
        "authorization_endpoint": format!("{public_url}/oauth/authorize"),
        "token_endpoint": format!("{public_url}/oauth/token"),
        "registration_endpoint": format!("{public_url}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["mcp"],
    })
}

/// The protected resource metadata of one path, as the interface reference gives it.
pub fn resource_document(public_url: &str, slug: &str) -> Value {
    json!({
        "resource": format!("{public_url}/{slug}"),
        "authorization_servers": [public_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
    })
}
