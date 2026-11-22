use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header::X_CONTENT_TYPE_OPTIONS;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::accounts::input::{normalize_email, to_i64};
use crate::accounts::{
    self, account, housekeeping, invite, login, password, reset, setup, throttle, values,
};
use crate::admin;
use crate::audit::{self, Event};
use crate::cimd::{CimdFetcher, HttpCimdFetcher};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, ConfigError};
use crate::crypto::{CryptoError, KeyError, Keys, PasswordHasher, random_token};
use crate::db::{Db, DbError};
use crate::oauth;
use crate::proxy::budget::Budget;
use crate::proxy::combined;
use crate::proxy::links::Links;
use crate::rate;
use crate::report;
use crate::web;
use crate::web::stall::{Peer, StallListener};

/// Password reset requests that may run their mail task at once.
const RESET_REQUEST_PERMITS: usize = 16;
/// How often the token housekeeping runs.
const SWEEP_EVERY: Duration = Duration::from_secs(600);

pub struct Deps {
    pub clock: Arc<dyn Clock>,
    pub cimd: Arc<dyn CimdFetcher>,
}

impl Deps {
    pub fn system() -> Deps {
        Deps {
            clock: Arc::new(SystemClock),
            cimd: Arc::new(HttpCimdFetcher::system()),
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
    /// Request buckets and the open MCP requests of each user.
    pub limiter: Arc<rate::Limiter>,
    /// The gateway's kept upstream links, one per token family and server.
    pub links: Arc<Links>,
    /// One tools/list at a time per user on the combined endpoint.
    pub turns: Arc<combined::Turns>,
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
    let limiter = Arc::new(rate::Limiter::new(&config.limits));
    let budget = Budget::new(
        config.limits.answer_memory_bytes,
        config.limits.answer_share(),
    );
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
        limiter,
        links: Arc::new(Links::with_budget(budget)),
        turns: Arc::new(combined::Turns::default()),
    };
    spawn_sweeps(&state);
    Ok(Gateway {
        router: routes(state),
        setup_code,
    })
}

fn routes(state: AppState) -> Router {
    let pages = Router::new()
        .route("/", get(root))
        .route("/setup", get(setup::get_setup).post(setup::post_setup))
        .route("/login", get(login::get_login).post(login::post_login))
        .route("/logout", post(login::post_logout))
        .route("/account", get(account::get_account))
        .route("/account/password", post(password::post_password))
        .route("/account/values/{slug}", post(values::post_values))
        .route(
            "/invite/{token}",
            get(invite::get_invite).post(invite::post_invite),
        )
        .route("/forgot", get(reset::get_forgot).post(reset::post_forgot))
        .route(
            "/reset/{token}",
            get(reset::get_reset).post(reset::post_reset),
        )
        .route("/oauth/authorize", get(oauth::authorize::get_authorize))
        .route(
            "/oauth/consent",
            get(oauth::consent::get_consent).post(oauth::consent::post_consent),
        )
        .route(
            "/account/clients/{public_id}/disconnect",
            post(oauth::connected::post_client_disconnect),
        )
        .route(
            "/account/disconnect/{token}",
            get(oauth::connected::get_disconnect_link).post(oauth::connected::post_disconnect_link),
        )
        .nest("/admin", admin::router(state.clone()))
        .fallback(|| async { web::not_found() })
        .layer(middleware::from_fn_with_state(
            state.clone(),
            web::limit::pages_by_address,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            web::security_headers,
        ));
    let api = Router::new()
        .route("/healthz", get(healthz))
        .route("/assets/doorward.css", get(web::stylesheet))
        .route("/assets/fonts/{name}", get(web::font))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata::authorization_server),
        )
        .route(
            "/.well-known/oauth-protected-resource/{slug}",
            get(oauth::metadata::protected_resource),
        )
        .route("/oauth/register", post(oauth::register::post_register))
        .route(
            "/oauth/token",
            post(oauth::token::post_token).fallback(oauth::token::not_post),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            web::limit::api_by_address,
        ))
        .layer(middleware::from_fn(nosniff));
    let bearer = Router::new()
        .route(
            "/mcp",
            get(oauth::guard::combined_path)
                .post(oauth::guard::combined_path)
                .delete(oauth::guard::combined_path),
        )
        .route(
            "/{slug}",
            get(oauth::guard::server_path)
                .post(oauth::guard::server_path)
                .delete(oauth::guard::server_path),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            oauth::origin::guard,
        ))
        .layer(middleware::from_fn(nosniff));
    api.merge(pages)
        .merge(bearer)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            web::drain::unread_body,
        ))
        .with_state(state)
}

/// Sets `x-content-type-options: nosniff` on a response, replacing any value it already has.
async fn nosniff(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// Runs the housekeeping at once and then every ten minutes. A failure goes to standard error.
fn spawn_sweeps(state: &AppState) {
    let db = state.db.clone();
    let clock = Arc::clone(&state.clock);
    let replay_seconds = oauth::families::replay_window(&state.config.lifetimes);
    let block_seconds = to_i64(state.config.limits.block_minutes).saturating_mul(60);
    let activity_seconds = to_i64(state.config.limits.activity_days).saturating_mul(86_400);
    let limiter = Arc::clone(&state.limiter);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_EVERY);
        loop {
            ticker.tick().await;
            limiter.sweep(web::limit::now_nanos(clock.as_ref()));
            let now = clock.now().unix_timestamp();
            let swept = db
                .call(move |conn| {
                    sweep_in(conn, now, replay_seconds, block_seconds, activity_seconds)
                })
                .await;
            if let Err(err) = swept {
                report::failure("housekeeping", &err);
            }
        }
    });
}

/// One immediate transaction for one housekeeping run.
fn sweep_in(
    conn: &mut Connection,
    now: i64,
    replay_seconds: i64,
    block_seconds: i64,
    activity_seconds: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    oauth::families::sweep(&tx, now, replay_seconds)?;
    housekeeping::sweep(&tx, now, block_seconds, activity_seconds)?;
    tx.commit()
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

/// Why `unlock` did nothing.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("no database at {}", .0.display())]
    NoDatabase(PathBuf),
    #[error("no account has that email address")]
    NoAccount,
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Clears the login block of one account and records it. Refuses, and creates nothing, when the
/// database file is missing or no account has the address.
pub async fn unlock(config: &Config, email: &str) -> Result<(), UnlockError> {
    if !config.database.exists() {
        return Err(UnlockError::NoDatabase(config.database.clone()));
    }
    let db = Db::open(&config.database)?;
    let email = normalize_email(email);
    let at = SystemClock.now().unix_timestamp();
    let found = db.call(move |conn| unlock_in(conn, &email, at)).await?;
    if found {
        Ok(())
    } else {
        Err(UnlockError::NoAccount)
    }
}

/// One transaction: the account must exist; its block is lifted and the activity row written.
/// False, with nothing changed, when no account has the address.
fn unlock_in(conn: &mut Connection, email: &str, at: i64) -> rusqlite::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let account: Option<i64> = tx
        .query_row(
            "SELECT id FROM users WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )
        .optional()?;
    let Some(user_id) = account else {
        return Ok(false);
    };
    throttle::lift_block(&tx, email)?;
    let unlocked = Event {
        kind: "unlock",
        user_id: Some(user_id),
        user_email: email,
        detail: "from the command line",
        ..Default::default()
    };
    audit::record(&tx, at, &unlocked)?;
    tx.commit()?;
    Ok(true)
}

/// Serves `router` until `shutdown` resolves; handlers can read the peer address. A connection whose
/// writes make no progress for `stall` is closed.
pub async fn serve<F>(
    listener: TcpListener,
    router: Router,
    stall: Duration,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        StallListener::new(listener, stall),
        router.into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Reads the settings table: 200 when the database answers, else 503 and one line on standard error.
async fn healthz(State(state): State<AppState>) -> Response {
    let read = state
        .db
        .call(|conn| {
            conn.query_row("SELECT COUNT(*) FROM settings", [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .await;
    match read {
        Ok(_) => Json(json!({ "status": "ok" })).into_response(),
        Err(err) => {
            report::failure("health check", &err);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
                .into_response()
        }
    }
}

/// Leads a signed-in person to their account. Otherwise leads to sign-up while no owner
/// exists, and to sign-in after that.
async fn root(State(state): State<AppState>, viewer: web::Viewer) -> Response {
    if viewer.user.is_some() {
        return web::redirect("/account");
    }
    match setup::owner_exists(&state.db).await {
        Ok(true) => web::redirect("/login"),
        Ok(false) => web::redirect("/setup"),
        Err(err) => web::internal_error("owner check", &err),
    }
}
