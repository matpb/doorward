use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use tokio::net::TcpListener;

use crate::accounts::{self, account, login, setup};
use crate::admin;
use crate::cimd::{CimdFetcher, UnavailableCimd};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, ConfigError};
use crate::crypto::{CryptoError, KeyError, Keys, PasswordHasher, random_token};
use crate::db::{Db, DbError};
use crate::web;

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
    let keys = load_keys(&db, &config).await?;
    let setup_code = if accounts::setup::owner_exists(&db).await? {
        None
    } else {
        Some(random_token(""))
    };
    let state = AppState {
        config,
        db,
        clock: deps.clock,
        cimd: deps.cimd,
        keys: Arc::new(keys),
        hasher,
        setup_code: setup_code.clone(),
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
        .route("/invite/{token}", get(accounts::invite_unavailable))
        .nest("/admin", admin::router(state.clone()))
        .layer(middleware::from_fn(web::security_headers));
    Router::new()
        .route("/healthz", get(healthz))
        .route("/assets/doorward.css", get(web::stylesheet))
        .merge(pages)
        .with_state(state)
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
