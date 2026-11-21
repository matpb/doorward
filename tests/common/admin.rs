use scraper::{ElementRef, Html, Selector};
use url::form_urlencoded::Serializer;

use super::client::{Page, TestClient};

pub struct ServerSpec<'a> {
    pub name: &'a str,
    pub slug: &'a str,
    pub upstream_url: &'a str,
    pub secret: Option<(&'a str, &'a str)>,
    pub pass_resources: bool,
    pub pass_prompts: bool,
}

fn server_fields<'a>(spec: &ServerSpec<'a>) -> Vec<(&'a str, &'a str)> {
    let mut fields = vec![
        ("name", spec.name),
        ("slug", spec.slug),
        ("upstream_url", spec.upstream_url),
    ];
    if let Some((name, value)) = spec.secret {
        fields.push(("secret_header_name", name));
        fields.push(("secret_header_value", value));
    }
    if spec.pass_resources {
        fields.push(("pass_resources", "on"));
    }
    if spec.pass_prompts {
        fields.push(("pass_prompts", "on"));
    }
    fields
}

fn server_path(id: &str) -> String {
    format!("/admin/servers/{id}")
}

fn attribute(element: ElementRef<'_>, name: &str) -> String {
    element.attr(name).unwrap_or("").to_string()
}

pub async fn add_server_page(c: &TestClient, spec: &ServerSpec<'_>) -> Page {
    c.submit("/admin/servers", "/admin/servers", &server_fields(spec))
        .await
}

pub async fn add_server(c: &TestClient, spec: &ServerSpec<'_>) -> String {
    let page = add_server_page(c, spec).await;
    page.location()
        .and_then(|location| location.strip_prefix("/admin/servers/").map(str::to_string))
        .unwrap_or_else(|| {
            panic!(
                "add_server answered {} with error {:?}",
                page.status,
                page.error()
            )
        })
}

pub async fn update_server(c: &TestClient, id: &str, spec: &ServerSpec<'_>) -> Page {
    let path = server_path(id);
    c.submit(&path, &path, &server_fields(spec)).await
}

pub async fn delete_server(c: &TestClient, id: &str) -> Page {
    let path = server_path(id);
    c.submit(&path, &format!("{path}/delete"), &[]).await
}

pub async fn refresh_tools(c: &TestClient, id: &str) -> Page {
    let path = server_path(id);
    c.submit(&path, &format!("{path}/refresh-tools"), &[]).await
}

pub async fn check_lockdown(c: &TestClient, id: &str) -> Page {
    let path = server_path(id);
    c.submit(&path, &format!("{path}/check-lockdown"), &[])
        .await
}

pub async fn server_id(c: &TestClient, slug: &str) -> Option<String> {
    let page = c.get("/admin/servers").await;
    page.attr(&format!(r#"[data-slug="{slug}"]"#), "data-server-id")
}

pub async fn user_id(c: &TestClient, email: &str) -> Option<String> {
    let page = c.get("/admin/users").await;
    page.attr(&format!(r#"[data-email="{email}"]"#), "data-user-id")
}

pub async fn invite(c: &TestClient, email: &str, role: &str) -> Page {
    c.submit(
        "/admin/invitations",
        "/admin/invitations",
        &[("email", email), ("role", role)],
    )
    .await
}

pub async fn assign(c: &TestClient, user_id: &str, server_ids: &[&str]) -> Page {
    let path = format!("/admin/users/{user_id}");
    let fields: Vec<(&str, &str)> = server_ids.iter().map(|id| ("server_id", *id)).collect();
    c.submit(&path, &format!("{path}/servers"), &fields).await
}

pub async fn set_role(c: &TestClient, user_id: &str, role: &str) -> Page {
    let path = format!("/admin/users/{user_id}");
    c.submit(&path, &format!("{path}/role"), &[("role", role)])
        .await
}

pub async fn user_action(c: &TestClient, user_id: &str, action: &str) -> Page {
    let path = format!("/admin/users/{user_id}");
    c.submit(&path, &format!("{path}/{action}"), &[]).await
}

pub async fn add_rule(
    c: &TestClient,
    subject: &str,
    effect: &str,
    scope: &str,
    server_id: Option<&str>,
    tool: Option<&str>,
) -> Page {
    let mut fields = vec![("subject", subject), ("effect", effect), ("scope", scope)];
    if let Some(server_id) = server_id {
        fields.push(("server_id", server_id));
    }
    if let Some(tool) = tool {
        fields.push(("tool", tool));
    }
    c.submit("/admin/rules", "/admin/rules", &fields).await
}

pub async fn rule_ids(c: &TestClient) -> Vec<String> {
    c.get("/admin/rules")
        .await
        .attrs("[data-rule-id]", "data-rule-id")
}

pub async fn delete_rule(c: &TestClient, rule_id: &str) -> Page {
    c.submit(
        "/admin/rules",
        &format!("/admin/rules/{rule_id}/delete"),
        &[],
    )
    .await
}

/// (server, tool, verdict) for each tool row; a missing attribute reads as "".
pub async fn effective_tools(c: &TestClient, user_id: &str) -> Vec<(String, String, String)> {
    let page = c.get(&format!("/admin/users/{user_id}")).await;
    let doc = Html::parse_document(&page.body);
    let selector = Selector::parse("[data-tool]").expect("static selector");
    doc.select(&selector)
        .map(|tool| {
            (
                attribute(tool, "data-server"),
                attribute(tool, "data-tool"),
                attribute(tool, "data-verdict"),
            )
        })
        .collect()
}

pub async fn add_redirect(c: &TestClient, scheme: &str, host: &str, path_prefix: &str) -> Page {
    c.submit(
        "/admin/redirects",
        "/admin/redirects",
        &[
            ("scheme", scheme),
            ("host", host),
            ("path_prefix", path_prefix),
        ],
    )
    .await
}

/// `security` is one of "off", "starttls" or "implicit", and is always sent as `smtp_tls`.
pub async fn mail_smtp(
    c: &TestClient,
    from: &str,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    security: &str,
) -> Page {
    let port = port.to_string();
    let fields = [
        ("provider", "smtp"),
        ("from", from),
        ("smtp_host", host),
        ("smtp_port", port.as_str()),
        ("smtp_username", username),
        ("smtp_password", password),
        ("smtp_tls", security),
    ];
    c.submit("/admin/mail", "/admin/mail", &fields).await
}

pub async fn mail_resend(c: &TestClient, from: &str, api_key: &str, base_url: &str) -> Page {
    c.submit(
        "/admin/mail",
        "/admin/mail",
        &[
            ("provider", "resend"),
            ("from", from),
            ("resend_api_key", api_key),
            ("resend_base_url", base_url),
        ],
    )
    .await
}

pub async fn mail_mailgun(
    c: &TestClient,
    from: &str,
    api_key: &str,
    domain: &str,
    base_url: &str,
) -> Page {
    c.submit(
        "/admin/mail",
        "/admin/mail",
        &[
            ("provider", "mailgun"),
            ("from", from),
            ("mailgun_api_key", api_key),
            ("mailgun_domain", domain),
            ("mailgun_base_url", base_url),
        ],
    )
    .await
}

pub async fn mail_test(c: &TestClient, to: &str) -> Page {
    c.submit("/admin/mail", "/admin/mail/test", &[("to", to)])
        .await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRow {
    pub kind: String,
    pub user: String,
    pub server: String,
    pub tool: String,
    pub decision: String,
    pub outcome: String,
}

pub async fn activity(
    c: &TestClient,
    user: Option<&str>,
    server: Option<&str>,
) -> Vec<ActivityRow> {
    activity_with_details(c, user, server)
        .await
        .into_iter()
        .map(|(row, _)| row)
        .collect()
}

/// The most activity pages the helper reads before it gives up.
const ACTIVITY_PAGE_LIMIT: usize = 200;

/// The activity rows, each with the text of its detail paragraph (empty when the row has none).
/// Every page is read, following the older link, until a page has none.
pub async fn activity_with_details(
    c: &TestClient,
    user: Option<&str>,
    server: Option<&str>,
) -> Vec<(ActivityRow, String)> {
    let mut query = Serializer::new(String::new());
    if let Some(user) = user {
        query.append_pair("user", user);
    }
    if let Some(server) = server {
        query.append_pair("server", server);
    }
    let query = query.finish();
    let mut target = if query.is_empty() {
        "/admin/activity".to_string()
    } else {
        format!("/admin/activity?{query}")
    };
    let selector = Selector::parse("li[data-kind], tr[data-kind]").expect("static selector");
    let detail = Selector::parse("p.detail").expect("static selector");
    let older = Selector::parse(r#"a[data-page-link="older"]"#).expect("static selector");
    let mut rows = Vec::new();
    for _ in 0..ACTIVITY_PAGE_LIMIT {
        let page = c.get(&target).await;
        let doc = Html::parse_document(&page.body);
        rows.extend(doc.select(&selector).map(|row| {
            let row_detail = row
                .select(&detail)
                .next()
                .map(|paragraph| paragraph.text().collect::<String>())
                .unwrap_or_default();
            let entry = ActivityRow {
                kind: attribute(row, "data-kind"),
                user: attribute(row, "data-user"),
                server: attribute(row, "data-server"),
                tool: attribute(row, "data-tool"),
                decision: attribute(row, "data-decision"),
                outcome: attribute(row, "data-outcome"),
            };
            (entry, row_detail)
        }));
        let next = doc
            .select(&older)
            .next()
            .and_then(|link| link.value().attr("href"));
        match next {
            Some(href) => target = href.to_string(),
            None => return rows,
        }
    }
    panic!(
        "activity_with_details: the activity has more than {ACTIVITY_PAGE_LIMIT} pages, the helper stops there"
    );
}

pub async fn invitation_id(c: &TestClient, email: &str) -> Option<String> {
    let page = c.get("/admin/invitations").await;
    page.attr(&format!(r#"[data-email="{email}"]"#), "data-invitation-id")
}

pub async fn revoke_invitation(c: &TestClient, invitation_id: &str) -> Page {
    c.submit(
        "/admin/invitations",
        &format!("/admin/invitations/{invitation_id}/revoke"),
        &[],
    )
    .await
}

pub async fn assign_users(c: &TestClient, server_id: &str, user_ids: &[&str]) -> Page {
    let path = server_path(server_id);
    let fields: Vec<(&str, &str)> = user_ids.iter().map(|id| ("user_id", *id)).collect();
    c.submit(&path, &format!("{path}/users"), &fields).await
}

/// The server ids whose checkbox is checked on the user's page.
pub async fn assigned_server_ids(c: &TestClient, user_id: &str) -> Vec<String> {
    let page = c.get(&format!("/admin/users/{user_id}")).await;
    page.attrs(r#"input[name="server_id"][checked]"#, "value")
}

/// The user ids whose checkbox is checked on the server's page.
pub async fn assigned_user_ids(c: &TestClient, server_id: &str) -> Vec<String> {
    let page = c.get(&server_path(server_id)).await;
    page.attrs(r#"input[name="user_id"][checked]"#, "value")
}

pub async fn catalog_tools(c: &TestClient, server_id: &str) -> Vec<String> {
    let page = c.get(&server_path(server_id)).await;
    page.attrs("[data-catalog-tool]", "data-catalog-tool")
}

pub async fn lockdown(c: &TestClient, server_id: &str) -> Option<String> {
    let page = c.get(&server_path(server_id)).await;
    page.attr("main", "data-lockdown")
}

pub async fn redirect_id(c: &TestClient, host: &str) -> Option<String> {
    let page = c.get("/admin/redirects").await;
    page.attr(&format!(r#"[data-host="{host}"]"#), "data-redirect-id")
}

/// `action` is "disable" or "enable".
pub async fn redirect_action(c: &TestClient, redirect_id: &str, action: &str) -> Page {
    c.submit(
        "/admin/redirects",
        &format!("/admin/redirects/{redirect_id}/{action}"),
        &[],
    )
    .await
}
