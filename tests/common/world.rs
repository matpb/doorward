use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use doorward::Config;

use super::TestGateway;
use super::admin::{self, ServerSpec};
use super::client::{OAuthApp, Page, TestClient, Tokens};
use super::mail::{MailCatcher, link_with_prefix};
use super::mcp::McpClient;
use super::upstream::{FakeUpstream, UpstreamOptions};

pub const OWNER_EMAIL: &str = "owner@example.com";
pub const PASSWORD: &str = "correct horse battery staple";
pub const FROM: &str = "gateway@example.com";
pub const APP_ID: &str = "https://client.example.com/app.json";
pub const APP_NAME: &str = "Example Client";
pub const APP_REDIRECT: &str = "http://127.0.0.1:53535/callback";
pub const SECRET_HEADER: &str = "x-upstream-secret";

pub struct World {
    pub gw: TestGateway,
    pub mail: MailCatcher,
    /// Signed in as the owner.
    pub owner: TestClient,
}

impl World {
    pub async fn start() -> World {
        World::start_with(|_| {}).await
    }

    /// Starts a gateway with `edit` applied to its config, then makes its owner.
    pub async fn start_with(edit: impl FnOnce(&mut Config)) -> World {
        let mail = MailCatcher::start().await;
        let gw = TestGateway::start_with(edit).await;
        let Some(code) = gw.setup_code() else {
            panic!("World: the gateway printed no setup code");
        };
        let owner = gw.client();
        let page = owner.setup_owner(&code, OWNER_EMAIL, PASSWORD).await;
        expect_status(&page, 303, "setup");
        let page = admin::mail_smtp(
            &owner,
            FROM,
            "127.0.0.1",
            mail.smtp_plain_port(),
            "mailer",
            "mail-password",
            "off",
        )
        .await;
        expect_status(&page, 303, "mail settings");
        gw.cimd().put(APP_ID, APP_NAME, &[APP_REDIRECT]);
        World { gw, mail, owner }
    }

    pub fn base(&self) -> &str {
        &self.gw.base
    }

    /// Restarts the gateway on the same database with `edit` applied to its configuration.
    pub async fn tighten(&mut self, edit: impl FnOnce(&mut Config)) {
        self.gw.restart_with(edit).await;
    }

    /// An anonymous browser.
    pub fn client(&self) -> TestClient {
        self.gw.client()
    }

    /// A user invited by the owner and signed in.
    pub async fn user(&self, email: &str) -> TestClient {
        self.invitee(email, "user").await
    }

    /// An admin invited by the owner and signed in.
    pub async fn admin(&self, email: &str) -> TestClient {
        self.invitee(email, "admin").await
    }

    pub async fn invite_link(&self, email: &str, role: &str) -> String {
        let page = admin::invite(&self.owner, email, role).await;
        expect_status(&page, 303, "invite");
        let message = self
            .mail
            .wait_to(email, Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("World: no mail to {email} arrived within 5 seconds"));
        let prefix = format!("{}/invite/", self.base());
        link_with_prefix(&message.text, &prefix).unwrap_or_else(|| {
            panic!(
                "World: the mail to {email} has no invitation link, text: {:?}",
                message.text
            )
        })
    }

    pub async fn user_id(&self, email: &str) -> String {
        admin::user_id(&self.owner, email)
            .await
            .unwrap_or_else(|| panic!("World: no user {email} on the users page"))
    }

    /// Starts an upstream behind the secret gate and adds it as a server with that secret.
    pub async fn upstream(
        &self,
        slug: &str,
        mut options: UpstreamOptions,
    ) -> (FakeUpstream, String) {
        if options.require_header.is_none() {
            options.require_header = Some((SECRET_HEADER.into(), secret_for(slug)));
        }
        self.add_upstream(slug, options, Some(secret_for(slug)))
            .await
    }

    /// Starts an upstream exactly as `options` says and adds it as a server without a secret.
    pub async fn open_upstream(
        &self,
        slug: &str,
        options: UpstreamOptions,
    ) -> (FakeUpstream, String) {
        self.add_upstream(slug, options, None).await
    }

    pub async fn grant(&self, email: &str, server_ids: &[&str]) {
        let user = self.user_id(email).await;
        let page = admin::assign(&self.owner, &user, server_ids).await;
        expect_status(&page, 303, "assign servers");
    }

    pub fn app(&self) -> OAuthApp {
        OAuthApp {
            client_id: APP_ID.into(),
            redirect_uri: APP_REDIRECT.into(),
        }
    }

    pub async fn token(&self, browser: &TestClient, slug: &str) -> Tokens {
        browser.connect(&self.app(), &self.resource(slug)).await
    }

    pub fn resource(&self, slug: &str) -> String {
        format!("{}/{slug}", self.base())
    }

    pub fn session_mcp(&self, slug: &str, tokens: &Tokens) -> McpClient {
        McpClient::session(&self.resource(slug), Some(&tokens.access_token))
    }

    pub fn stateless_mcp(&self, slug: &str, tokens: &Tokens) -> McpClient {
        McpClient::stateless(&self.resource(slug), Some(&tokens.access_token))
    }

    /// The database file, then its `-wal` and `-shm` files when they exist.
    pub fn stored_bytes(&self) -> Vec<u8> {
        let db = self.gw.db_path();
        let mut bytes = read_file(&db);
        for suffix in ["-wal", "-shm"] {
            let path = with_suffix(&db, suffix);
            if path.exists() {
                bytes.extend(read_file(&path));
            }
        }
        bytes
    }

    async fn invitee(&self, email: &str, role: &str) -> TestClient {
        let link = self.invite_link(email, role).await;
        let browser = self.gw.client();
        let page = browser.accept_invite(&link, PASSWORD).await;
        expect_status(&page, 303, "accept invitation");
        browser
    }

    async fn add_upstream(
        &self,
        slug: &str,
        options: UpstreamOptions,
        secret: Option<String>,
    ) -> (FakeUpstream, String) {
        let upstream = FakeUpstream::start(options).await;
        let url = upstream.url();
        let id = admin::add_server(
            &self.owner,
            &ServerSpec {
                name: slug,
                slug,
                upstream_url: &url,
                secret: secret.as_deref().map(|value| (SECRET_HEADER, value)),
                pass_resources: false,
                pass_prompts: false,
            },
        )
        .await;
        let page = admin::refresh_tools(&self.owner, &id).await;
        expect_status(&page, 303, "refresh tools");
        upstream.clear();
        (upstream, id)
    }
}

pub fn secret_for(slug: &str) -> String {
    format!("secret-{slug}")
}

/// Panics with the step, the status and the page kind unless the answer has the wanted status.
fn expect_status(page: &Page, want: u16, step: &str) {
    if page.status != want {
        panic!(
            "World: {step} answered {} (kind {:?}), expected {want}",
            page.status,
            page.kind()
        );
    }
}

fn read_file(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| panic!("World: cannot read {}: {err}", path.display()))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
