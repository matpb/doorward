#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use doorward::clock::Clock;
use doorward::{Config, Deps, build};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct ManualClock {
    now: Mutex<OffsetDateTime>,
}

impl ManualClock {
    pub fn new(start: OffsetDateTime) -> Arc<ManualClock> {
        Arc::new(ManualClock {
            now: Mutex::new(start),
        })
    }

    pub fn set(&self, t: OffsetDateTime) {
        *self.now.lock().expect("lock") = t;
    }

    pub fn advance(&self, d: time::Duration) {
        *self.now.lock().expect("lock") += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().expect("lock")
    }
}

pub struct TestGateway {
    pub base: String,
    pub clock: Arc<ManualClock>,
    pub http: reqwest::Client,
    config: Config,
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    server: JoinHandle<()>,
    _dir: TempDir,
}

impl TestGateway {
    pub async fn start() -> TestGateway {
        let dir = tempfile::tempdir().expect("temp dir");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let config = Config {
            public_url: format!("http://127.0.0.1:{}", addr.port()),
            listen: addr,
            database: dir.path().join("doorward.db"),
            key_file: None,
            trusted_proxies: Vec::new(),
        };
        let clock = ManualClock::new(
            OffsetDateTime::parse(
                "2030-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("start time"),
        );
        let router = build_router(&config, &clock).await;
        let (stop, server) = spawn_server(listener, router);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client");
        TestGateway {
            base: config.public_url.clone(),
            clock,
            http,
            config,
            addr,
            stop: Some(stop),
            server,
            _dir: dir,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn db_path(&self) -> PathBuf {
        self.config.database.clone()
    }

    /// Stops serving, then serves again on the same database file and port.
    pub async fn restart(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        (&mut self.server).await.expect("server task");
        let listener = bind_with_retry(self.addr).await;
        let router = build_router(&self.config, &self.clock).await;
        let (stop, server) = spawn_server(listener, router);
        self.stop = Some(stop);
        self.server = server;
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn build_router(config: &Config, clock: &Arc<ManualClock>) -> Router {
    let deps = Deps {
        clock: clock.clone(),
    };
    build(config.clone(), deps).await.expect("build gateway")
}

fn spawn_server(listener: TcpListener, router: Router) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .expect("serve");
    });
    (stop, server)
}

async fn bind_with_retry(addr: SocketAddr) -> TcpListener {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => return listener,
            Err(err) if Instant::now() >= deadline => panic!("cannot rebind {addr}: {err}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}
