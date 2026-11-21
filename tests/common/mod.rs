#![allow(dead_code)]

pub mod admin;
pub mod binary;
pub mod cimd;
pub mod client;
pub mod mail;
pub mod mcp;
pub mod upstream;
pub mod world;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use cimd::FakeCimd;
use doorward::clock::Clock;
use doorward::{Config, Deps, Gateway, build, serve};
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
    cimd: Arc<FakeCimd>,
    setup_code: Option<String>,
    stop: Option<oneshot::Sender<()>>,
    server: JoinHandle<()>,
    _dir: TempDir,
}

impl TestGateway {
    pub async fn start() -> TestGateway {
        TestGateway::start_with(|_| {}).await
    }

    /// Starts a gateway; `edit` changes the default config before it is built.
    pub async fn start_with(edit: impl FnOnce(&mut Config)) -> TestGateway {
        let dir = tempfile::tempdir().expect("temp dir");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let mut config = Config {
            public_url: format!("http://127.0.0.1:{}", addr.port()),
            listen: addr,
            database: dir.path().join("doorward.db"),
            key_file: None,
            trusted_proxies: Vec::new(),
            shared_client_address: false,
            allowed_origins: Vec::new(),
            lifetimes: Default::default(),
            limits: Default::default(),
            mail: Default::default(),
        };
        edit(&mut config);
        let clock = ManualClock::new(
            OffsetDateTime::parse(
                "2030-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .expect("start time"),
        );
        let cimd = FakeCimd::new();
        let gateway = build_gateway(&config, &clock, &cimd).await;
        let (stop, server) =
            spawn_server(listener, gateway.router, config.limits.write_stall_seconds);
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
            cimd,
            setup_code: gateway.setup_code,
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

    /// The setup code of the latest build, present only while the instance has no owner.
    pub fn setup_code(&self) -> Option<String> {
        self.setup_code.clone()
    }

    pub fn cimd(&self) -> &FakeCimd {
        &self.cimd
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// A scripted browser with an empty cookie jar.
    pub fn client(&self) -> client::TestClient {
        client::TestClient::new(&self.base)
    }

    /// Stops serving, then serves again on the same database file and port.
    pub async fn restart(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        (&mut self.server).await.expect("server task");
        let listener = bind_with_retry(self.addr).await;
        let gateway = build_gateway(&self.config, &self.clock, &self.cimd).await;
        let (stop, server) = spawn_server(
            listener,
            gateway.router,
            self.config.limits.write_stall_seconds,
        );
        self.setup_code = gateway.setup_code;
        self.stop = Some(stop);
        self.server = server;
    }

    /// As `restart`, with `edit` applied to the configuration first.
    pub async fn restart_with(&mut self, edit: impl FnOnce(&mut Config)) {
        edit(&mut self.config);
        self.restart().await;
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn build_gateway(config: &Config, clock: &Arc<ManualClock>, cimd: &Arc<FakeCimd>) -> Gateway {
    let deps = Deps {
        clock: clock.clone(),
        cimd: cimd.clone(),
    };
    build(config.clone(), deps).await.expect("build gateway")
}

fn spawn_server(
    listener: TcpListener,
    router: Router,
    stall_seconds: u64,
) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve(
            listener,
            router,
            Duration::from_secs(stall_seconds),
            async {
                let _ = stopped.await;
            },
        )
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
