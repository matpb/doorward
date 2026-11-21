mod common;

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::admin::{self, ServerSpec};
use common::binary::{Run, free_port, write_file};
use common::client::{OAuthApp, TestClient};
use common::mcp::{McpClient, stalled_call};
use common::upstream::{FakeUpstream, Mode, UpstreamOptions};
use serde_json::json;
use tempfile::TempDir;

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct horse battery staple";
const CALLBACK: &str = "http://127.0.0.1:8765/callback";
/// One answer: just under the default limit of a single answer.
const ANSWER: usize = 4_000_000;
/// Calls sent at once, the default number of open MCP requests of one user.
const CALLS: usize = 64;
/// The budget under test, and the largest single answer, so one user's share is the whole budget.
const BUDGET: u64 = 33_554_432;
/// A budget no burst of this test reaches.
const NO_BUDGET: u64 = 8_589_934_592;
/// The most the peak resident memory of the gateway process may grow during the bursts, in KiB.
const CEILING_KIB: u64 = 262_144;
/// The default `limits.write_stall_seconds`, kept so that no stall ends during the measurement.
const WRITE_STALL: u64 = 30;
/// Raw clients that read only the status line of their answer, all sent in a row.
const READERS: usize = 200;
/// How long the stalled clients keep their sockets open before the peak is read.
const STALLED_FOR: Duration = Duration::from_secs(5);

/// How long the upstream may take to begin every answer.
const WAIT: Duration = Duration::from_secs(60);
/// How long the held halves stay in the gateway before the upstream sends the rest.
const HOLD: Duration = Duration::from_secs(2);

/// What the burst did: answers by status, and the growth of the process's peak resident memory.
struct Measured {
    whole: usize,
    busy: usize,
    other: usize,
    grown_kib: u64,
}

/// The real binary with `budget`, an owner and one server whose calls answer `ANSWER` bytes each.
struct Spawned {
    run: Run,
    config: String,
    base: String,
    _dir: TempDir,
}

impl Spawned {
    fn start(budget: u64, stall: u64) -> Spawned {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = free_port();
        let db = dir.path().join("doorward.db");
        let text = format!(
            "public_url = \"http://127.0.0.1:{port}\"\nlisten = \"127.0.0.1:{port}\"\n\
             database = '{}'\n\n[limits]\ntools_list_bytes = {BUDGET}\n\
             answer_memory_bytes = {budget}\nwrite_stall_seconds = {stall}\n",
            db.display()
        );
        let config = write_file(dir.path(), "doorward.toml", &text)
            .display()
            .to_string();
        let mut run = Run::spawn(&["--config", config.as_str()], &[]);
        run.wait_until_healthy(port);
        Spawned {
            run,
            config,
            base: format!("http://127.0.0.1:{port}"),
            _dir: dir,
        }
    }

    /// The process id of the binary, found by the config path on its command line.
    fn pid(&self) -> u32 {
        fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .find(|pid| {
                fs::read(Path::new("/proc").join(pid.to_string()).join("cmdline"))
                    .map(|line| String::from_utf8_lossy(&line).contains(&self.config))
                    .unwrap_or(false)
            })
            .expect("the gateway process is listed in /proc")
    }

    /// The peak resident memory of the binary so far, in KiB.
    fn peak_kib(&self) -> u64 {
        let status = fs::read_to_string(format!("/proc/{}/status", self.pid()))
            .expect("read the process status");
        status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kib| kib.parse().ok())
            .expect("the status holds VmHWM")
    }

    async fn owner(&self) -> TestClient {
        let code = self
            .run
            .stderr()
            .lines()
            .find_map(|line| line.strip_prefix("doorward setup code: "))
            .map(str::to_owned)
            .expect("the binary prints a setup code while no owner exists");
        let browser = TestClient::new(&self.base);
        let page = browser.setup_owner(&code, EMAIL, PASSWORD).await;
        assert_eq!(page.status, 303, "setup must make the owner");
        browser
    }
}

/// Sends `CALLS` calls at once through a gateway with `budget`; the upstream sends half of each answer,
/// waits until all have begun and `HOLD` has passed, then sends the rest.
async fn measure(budget: u64) -> Measured {
    let gateway = Spawned::start(budget, WRITE_STALL);
    let owner = gateway.owner().await;
    let upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let page = admin::refresh_tools(&owner, &id).await;
    assert_eq!(page.status, 303, "the tool list must be fetched");
    let owner_id = admin::user_id(&owner, EMAIL).await.expect("the owner");
    let page = admin::assign(&owner, &owner_id, &[id.as_str()]).await;
    assert_eq!(page.status, 303, "the owner must be assigned to demo");
    let registered = owner.register("Memory Probe", &[CALLBACK]).await;
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: CALLBACK.to_owned(),
    };
    let resource = format!("{}/demo", gateway.base);
    let tokens = owner.connect(&app, &resource).await;
    upstream.set_mode(Mode::HeldAnswer { bytes: ANSWER });
    let mcp = Arc::new(McpClient::stateless(&resource, Some(&tokens.access_token)));
    mcp.set_timeout(Duration::from_secs(120));

    let before = gateway.peak_kib();
    let mut measured = Measured {
        whole: 0,
        busy: 0,
        other: 0,
        grown_kib: 0,
    };
    let calls: Vec<_> = (0..CALLS)
        .map(|_| {
            let mcp = Arc::clone(&mcp);
            tokio::spawn(async move { mcp.call_tool("echo", json!({"text": "hi"})).await })
        })
        .collect();
    assert!(
        upstream.wait_held(CALLS, WAIT).await,
        "the upstream began {} of {CALLS} answers",
        upstream.held_begun()
    );
    tokio::time::sleep(HOLD).await;
    upstream.release();
    for call in calls {
        match call.await.expect("the call task").status {
            200 => measured.whole += 1,
            503 => measured.busy += 1,
            _ => measured.other += 1,
        }
    }
    measured.grown_kib = gateway.peak_kib().saturating_sub(before);
    measured
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_process_stays_under_its_ceiling_in_a_burst_of_large_answers() {
    let measured = measure(BUDGET).await;
    eprintln!(
        "with the budget: {} whole, {} busy, {} other, peak grew {} KiB",
        measured.whole, measured.busy, measured.other, measured.grown_kib
    );
    assert_eq!(measured.other, 0, "every call answers 200 or 503");
    assert!(measured.whole > 0, "some calls must be answered in full");
    assert!(measured.busy > 0, "the burst must reach the budget");
    assert!(
        measured.grown_kib < CEILING_KIB,
        "the peak grew {} KiB, the ceiling is {CEILING_KIB} KiB",
        measured.grown_kib
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_burst_passes_the_ceiling_when_no_budget_is_reached() {
    let measured = measure(NO_BUDGET).await;
    eprintln!(
        "without a budget: {} whole, {} busy, {} other, peak grew {} KiB",
        measured.whole, measured.busy, measured.other, measured.grown_kib
    );
    assert_eq!(measured.whole, CALLS, "every call must be answered in full");
    assert!(
        measured.grown_kib > CEILING_KIB,
        "the peak grew {} KiB, so this burst would not show a missing budget",
        measured.grown_kib
    );
}

/// Raw clients that read only the status line of a 4 MB answer each. The gateway holds what the clients
/// have not read, so its peak memory must not pass the ceiling even though every client is answered.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_readers_do_not_grow_the_process_past_the_ceiling() {
    let gateway = Spawned::start(BUDGET, WRITE_STALL);
    let owner = gateway.owner().await;
    let upstream = FakeUpstream::start(UpstreamOptions::default()).await;
    let url = upstream.url();
    let id = admin::add_server(
        &owner,
        &ServerSpec {
            name: "demo",
            slug: "demo",
            upstream_url: &url,
            secret: None,
            pass_resources: false,
            pass_prompts: false,
        },
    )
    .await;
    let page = admin::refresh_tools(&owner, &id).await;
    assert_eq!(page.status, 303, "the tool list must be fetched");
    let owner_id = admin::user_id(&owner, EMAIL).await.expect("the owner");
    let page = admin::assign(&owner, &owner_id, &[id.as_str()]).await;
    assert_eq!(page.status, 303, "the owner must be assigned to demo");
    let registered = owner.register("Memory Probe", &[CALLBACK]).await;
    let client_id = registered
        .json()
        .and_then(|json| json["client_id"].as_str().map(str::to_owned))
        .expect("registration answers with a client_id");
    let app = OAuthApp {
        client_id,
        redirect_uri: CALLBACK.to_owned(),
    };
    let resource = format!("{}/demo", gateway.base);
    let tokens = owner.connect(&app, &resource).await;
    upstream.set_mode(Mode::Oversized { bytes: ANSWER });
    let addr: SocketAddr = gateway
        .base
        .trim_start_matches("http://")
        .parse()
        .expect("the gateway address");

    let before = gateway.peak_kib();
    let mut sockets = Vec::new();
    let mut statuses = Vec::new();
    for n in 0..READERS {
        let (socket, line) =
            stalled_call(addr, "demo", &tokens.access_token, 1000 + n as u64).await;
        statuses.push(line);
        sockets.push(socket);
    }
    tokio::time::sleep(STALLED_FOR).await;
    let grown = gateway.peak_kib().saturating_sub(before);
    let count = |code: &str| statuses.iter().filter(|line| line.contains(code)).count();
    eprintln!(
        "stalled readers: {} answered 200, {} answered 503, {} other; peak grew {grown} KiB",
        count(" 200"),
        count(" 503"),
        statuses.len() - count(" 200") - count(" 503")
    );
    drop(sockets);
    assert_eq!(
        statuses.len(),
        READERS,
        "every client must get a status line"
    );
    assert!(count(" 503") > 0, "the budget must refuse some answers");
    assert!(
        grown < CEILING_KIB,
        "the peak grew {grown} KiB, the ceiling is {CEILING_KIB} KiB"
    );
}
