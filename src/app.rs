use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;

use crate::cimd::{CimdFetcher, UnavailableCimd};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, ConfigError};
use crate::db::{Db, DbError};

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
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub clock: Arc<dyn Clock>,
    pub cimd: Arc<dyn CimdFetcher>,
}

/// Validates the config, opens the database and returns the gateway.
pub async fn build(mut config: Config, deps: Deps) -> Result<Gateway, StartError> {
    config.validate()?;
    let db = Db::open(&config.database)?;
    let state = AppState {
        config,
        db,
        clock: deps.clock,
        cimd: deps.cimd,
    };
    let router = Router::new()
        .route("/healthz", get(healthz))
        .with_state(state);
    Ok(Gateway {
        router,
        setup_code: None,
    })
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
