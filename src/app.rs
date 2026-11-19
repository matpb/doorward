use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::clock::{Clock, SystemClock};
use crate::config::{Config, ConfigError};
use crate::db::{Db, DbError};

pub struct Deps {
    pub clock: Arc<dyn Clock>,
}

impl Deps {
    pub fn system() -> Deps {
        Deps {
            clock: Arc::new(SystemClock),
        }
    }
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
}

/// Validates the config, opens the database and returns the gateway router.
pub async fn build(mut config: Config, deps: Deps) -> Result<Router, StartError> {
    config.validate()?;
    let db = Db::open(&config.database)?;
    let state = AppState {
        config,
        db,
        clock: deps.clock,
    };
    Ok(Router::new()
        .route("/healthz", get(healthz))
        .with_state(state))
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
