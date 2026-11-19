use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::accounts::{self, account, invite, login, password, reset, setup, throttle};
use crate::admin;
use crate::cimd::{CimdFetcher, UnavailableCimd};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, ConfigError};
use crate::crypto::{CryptoError, KeyError, Keys, PasswordHasher, random_token};
use crate::db::{Db, DbError};
use crate::oauth;
use crate::web;

/// Password reset requests that may run their mail task at once.
const RESET_REQUEST_PERMITS: usize = 16;

pub struct Deps {
    pub clock: Arc<dyn Clock>,
    pub cimd: Arc<dyn CimdFetcher>,
}

impl Deps {
    pub fn system() -> Deps {
        Deps {
            clock: Arc::new(SystemClock),
            cimd: Arc::new(UnavailableCimd),
        }
    }
}

/// `setup_code` is present only while the instance has no owner.
pub struct Gateway {
    pub router: Router,
    pub setup_code: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("cannot build the HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub clock: Arc<dyn Clock>,
    pub cimd: Arc<dyn CimdFetcher>,
    pub keys: Arc<Keys>,
    pub hasher: Arc<PasswordHasher>,
    pub setup_code: Option<String>,
    /// Shared client for the HTTP mail providers.
    pub http: reqwest::Client,
    /// Permits for the background tasks of `POST /forgot`.
    pub reset_requests: Arc<Semaphore>,
}

/// Validates the config, opens the database and returns the gateway.
pub async fn build(config: Config, deps: Deps) -> Result<Gateway, StartError> {
    let hasher = PasswordHasher::new().await?;
    assemble(config, deps, Arc::new(hasher)).await
}

/// Like `build`, with the password hasher supplied by the caller.
pub(crate) async fn assemble(
    mut config: Config,
    deps: Deps,
    hasher: Arc<PasswordHasher>,
) -> Result<Gateway, StartError> {
    config.validate()?;
    let db = Db::open(&config.database)?;
    db.call(oauth::policy::sync_shipped).await?;
    let keys = load_keys(&db, &config).await?;
    let setup_code = if accounts::setup::owner_exists(&db).await? {
        None
    } else {
        Some(random_token(""))
    };
    let http = http_client()?;
    let state = AppState {
        config,
        db,
        clock: deps.clock,
        cimd: deps.cimd,
        keys: Arc::new(keys),
        hasher,
        http,
        setup_code: setup_code.clone(),
        reset_requests: Arc::new(Semaphore::new(RESET_REQUEST_PERMITS)),
    };
    Ok(Gateway {
        router: routes(state),
        setup_code,
    })
}

fn routes(state: AppState) -> Router {
    let pages = Router::new()
        .route("/setup", get(setup::get_setup).post(setup::post_setup))
        .route("/login", get(login::get_login).post(login::post_login))
        .route("/logout", post(login::post_logout))
        .route("/account", get(account::get_account))
        .route("/account/password", post(password::post_password))
        .route(
            "/invite/{token}",
            get(invite::get_invite).post(invite::post_invite),
        )
        .route("/forgot", get(reset::get_forgot).post(reset::post_forgot))
        .route(
            "/reset/{token}",
            get(reset::get_reset).post(reset::post_reset),
        )
        .nest("/admin", admin::router(state.clone()))
        .layer(middleware::from_fn(web::security_headers));
    Router::new()
        .route("/healthz", get(healthz))
        .route("/assets/doorward.css", get(web::stylesheet))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata::authorization_server),
        )
        .route(
            "/.well-known/oauth-protected-resource/{slug}",
            get(oauth::metadata::protected_resource),
        )
        .route("/oauth/register", post(oauth::register::post_register))
        .merge(pages)
        .with_state(state)
}

/// No redirects, no cookies, no proxy from the environment, and a 5 second connect timeout.
fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
}

/// Loads the key in one immediate transaction and records its id when none was stored.
async fn load_keys(db: &Db, config: &Config) -> Result<Keys, StartError> {
    let config = config.clone();
    let loaded = db.call(move |conn| load_keys_in(conn, &config)).await?;
    Ok(loaded?)
}

fn load_keys_in(
    conn: &mut Connection,
    config: &Config,
) -> rusqlite::Result<Result<Keys, KeyError>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = stored_key_id(&tx)?;
    let keys = match Keys::load(config, stored.as_deref()) {
        Ok(keys) => keys,
        Err(err) => return Ok(Err(err)),
    };
    if stored.is_none() {
        tx.execute(
            "INSERT INTO settings (key, value) VALUES ('crypto.key_id', ?1)",
            params![keys.key_id().as_bytes()],
        )?;
    }
    tx.commit()?;
    Ok(Ok(keys))
}

fn stored_key_id(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = 'crypto.key_id'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(err),
                )
            })
        })
        .transpose()
}

/// Clears the login block of one account, whether or not one existed.
pub async fn unlock(config: &Config, email: &str) -> Result<(), DbError> {
    let db = Db::open(&config.database)?;
    let email = email.to_owned();
    db.call(move |conn| throttle::lift_block(conn, &email))
        .await
}

/// Serves `router` until `shutdown` resolves; handlers can read the peer address.
pub async fn serve<F>(listener: TcpListener, router: Router, shutdown: F) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
