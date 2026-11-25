mod common;

use common::admin;
use common::client::{Page, TestClient};
use common::upstream::UpstreamOptions;
use common::world::{OWNER_EMAIL, World};
use rusqlite::{Connection, params};
use scraper::{Html, Selector};

const BOB: &str = "bob@example.com";
const ADA: &str = "ada@example.com";
const GRACE: &str = "grace@example.com";
/// The page every dashboard form is read from: it exists for an admin whatever dashboards there are.
const LIST: &str = "/admin/dashboards";
const NOT_A_SHAPE: &str = "This shape does not fit this grouping: over time, a line, bars or a table; by user, server, tool or client, ranked or a table; with no grouping, a number.";

/// The Usage dashboard of a fresh database: title, metric, group, shape, period, top count, width.
const USAGE: [(&str, &str, &str, &str, &str, &str, &str); 10] = [
    (
        "Tool calls over time",
        "calls",
        "time",
        "bars",
        "30d",
        "",
        "full",
    ),
    (
        "Active users over time",
        "active_users",
        "time",
        "line",
        "30d",
        "",
        "half",
    ),
    (
        "Tool calls refused over time",
        "refused",
        "time",
        "line",
        "30d",
        "",
        "half",
    ),
    (
        "Most active users",
        "calls",
        "user",
        "ranked",
        "30d",
        "10",
        "half",
    ),
    (
        "Servers by use",
        "calls",
        "server",
        "ranked",
        "30d",
        "10",
        "half",
    ),
    (
        "Tools by use",
        "calls",
        "tool",
        "ranked",
        "30d",
        "20",
        "half",
    ),
    (
        "Unused tools",
        "unused_tools",
        "none",
        "table",
        "30d",
        "",
        "half",
    ),
    (
        "Slowest tools p95",
        "duration_p95",
        "tool",
        "ranked",
        "30d",
        "10",
        "half",
    ),
    (
        "Calls by client",
        "calls",
        "client",
        "ranked",
        "30d",
        "10",
        "half",
    ),
    (
        "Failed calls by server",
        "failed",
        "server",
        "ranked",
        "30d",
        "10",
        "full",
    ),
];

/// A chart as the builder form posts it. Empty server, user and tool are no filter.
#[derive(Clone)]
struct Chart {
    title: String,
    metric: String,
    group_by: String,
    shape: String,
    period: String,
    server_id: String,
    user_id: String,
    tool: String,
    top_n: String,
    width: String,
}

impl Chart {
    fn new(title: &str, metric: &str, group_by: &str, shape: &str) -> Chart {
        Chart {
            title: title.to_owned(),
            metric: metric.to_owned(),
            group_by: group_by.to_owned(),
            shape: shape.to_owned(),
            period: "30d".to_owned(),
            server_id: String::new(),
            user_id: String::new(),
            tool: String::new(),
            top_n: "10".to_owned(),
            width: "half".to_owned(),
        }
    }

    fn pairs(&self) -> Vec<(&str, &str)> {
        vec![
            ("title", self.title.as_str()),
            ("metric", self.metric.as_str()),
            ("group_by", self.group_by.as_str()),
            ("shape", self.shape.as_str()),
            ("period", self.period.as_str()),
            ("server_id", self.server_id.as_str()),
            ("user_id", self.user_id.as_str()),
            ("tool", self.tool.as_str()),
            ("top_n", self.top_n.as_str()),
            ("width", self.width.as_str()),
        ]
    }
}

fn open(w: &World) -> Connection {
    Connection::open(w.gw.db_path()).expect("the gateway database opens")
}

fn count(w: &World, sql: &str) -> i64 {
    open(w)
        .query_row(sql, [], |row| row.get(0))
        .expect("a count")
}

fn dashboard_id(w: &World, name: &str) -> i64 {
    open(w)
        .query_row(
            "SELECT id FROM dashboards WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )
        .unwrap_or_else(|err| panic!("a dashboard named {name}: {err}"))
}

/// The id of the chart with `title`.
fn chart_id_of(w: &World, title: &str) -> i64 {
    open(w)
        .query_row(
            "SELECT id FROM charts WHERE title = ?1",
            params![title],
            |row| row.get(0),
        )
        .unwrap_or_else(|err| panic!("a chart titled {title}: {err}"))
}

/// The titles of a dashboard's charts in position order.
fn chart_titles(w: &World, name: &str) -> Vec<String> {
    let conn = open(w);
    let mut statement = conn
        .prepare(
            "SELECT charts.title FROM charts JOIN dashboards ON dashboards.id = charts.dashboard_id \
             WHERE dashboards.name = ?1 ORDER BY charts.position, charts.id",
        )
        .expect("the titles query");
    statement
        .query_map(params![name], |row| row.get(0))
        .expect("the titles")
        .map(|row| row.expect("a title"))
        .collect()
}

/// The dashboard names in position order.
fn dashboard_names(w: &World) -> Vec<String> {
    let conn = open(w);
    let mut statement = conn
        .prepare("SELECT name FROM dashboards ORDER BY position, id")
        .expect("the names query");
    statement
        .query_map([], |row| row.get(0))
        .expect("the names")
        .map(|row| row.expect("a name"))
        .collect()
}

/// The owner and detail of the dashboard and chart admin_change rows, oldest first. The harness's own
/// setup writes other admin changes, which are left out.
fn admin_changes(w: &World) -> Vec<(String, String)> {
    let conn = open(w);
    let mut statement = conn
        .prepare("SELECT user_email, detail FROM activity WHERE kind = 'admin_change' ORDER BY id")
        .expect("the activity query");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("the activity rows")
        .map(|row| row.expect("a row"))
        .filter(|(_, detail): &(String, String)| {
            detail.contains("dashboard") || detail.contains("chart")
        })
        .collect()
}

/// Posts to `action`, taking the csrf token from the dashboards list.
async fn post(c: &TestClient, action: &str, fields: &[(&str, &str)]) -> Page {
    c.submit(LIST, action, fields).await
}

async fn create(c: &TestClient, name: &str) -> Page {
    post(c, LIST, &[("name", name)]).await
}

async fn rename(c: &TestClient, id: i64, name: &str) -> Page {
    post(c, &format!("/admin/dashboards/{id}"), &[("name", name)]).await
}

async fn add_chart(c: &TestClient, id: i64, chart: &Chart) -> Page {
    post(c, &format!("/admin/dashboards/{id}/charts"), &chart.pairs()).await
}

async fn update_chart(c: &TestClient, id: i64, chart_id: i64, chart: &Chart) -> Page {
    post(
        c,
        &format!("/admin/dashboards/{id}/charts/{chart_id}"),
        &chart.pairs(),
    )
    .await
}

async fn delete_chart(c: &TestClient, id: i64, chart_id: i64) -> Page {
    post(
        c,
        &format!("/admin/dashboards/{id}/charts/{chart_id}/delete"),
        &[],
    )
    .await
}

async fn move_chart(c: &TestClient, id: i64, chart_id: i64, direction: &str) -> Page {
    post(
        c,
        &format!("/admin/dashboards/{id}/charts/{chart_id}/move"),
        &[("direction", direction)],
    )
    .await
}

async fn move_dashboard(c: &TestClient, id: i64, direction: &str) -> Page {
    post(
        c,
        &format!("/admin/dashboards/{id}/move"),
        &[("direction", direction)],
    )
    .await
}

async fn delete_dashboard(c: &TestClient, id: i64) -> Page {
    post(c, &format!("/admin/dashboards/{id}/delete"), &[]).await
}

/// The text of the first element matching `css`.
fn element_text(page: &Page, css: &str) -> Option<String> {
    let doc = Html::parse_document(&page.body);
    let selector = Selector::parse(css).expect("a selector");
    doc.select(&selector)
        .next()
        .map(|element| element.text().collect::<String>())
}

/// The value attribute of the one element matching `css`; None when it has none.
fn value_of(page: &Page, css: &str) -> Option<String> {
    let doc = Html::parse_document(&page.body);
    let selector = Selector::parse(css).expect("a selector");
    let found: Vec<_> = doc.select(&selector).collect();
    assert_eq!(found.len(), 1, "{css} must match one element");
    found[0].value().attr("value").map(str::to_owned)
}

/// The values of the options of `css` that carry the selected attribute.
fn selected(page: &Page, css: &str) -> Vec<String> {
    let doc = Html::parse_document(&page.body);
    let selector = Selector::parse(&format!("{css} option[selected]")).expect("a selector");
    doc.select(&selector)
        .map(|option| option.value().attr("value").unwrap_or("").to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_is_redirected_and_a_plain_user_is_forbidden_on_every_route() {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let gets = [
        "/admin/dashboards".to_owned(),
        "/admin/dashboards/1".to_owned(),
        "/admin/dashboards/1?chart=1".to_owned(),
    ];
    let posts: [(&str, &[(&str, &str)]); 8] = [
        ("/admin/dashboards", &[("name", "Ops")]),
        ("/admin/dashboards/1", &[("name", "Ops")]),
        ("/admin/dashboards/1/delete", &[]),
        ("/admin/dashboards/1/charts", &[("title", "Ops")]),
        ("/admin/dashboards/1/charts/1", &[("title", "Ops")]),
        ("/admin/dashboards/1/charts/1/delete", &[]),
        (
            "/admin/dashboards/1/charts/1/move",
            &[("direction", "down")],
        ),
        ("/admin/dashboards/1/move", &[("direction", "down")]),
    ];
    let anonymous = w.client();
    for path in &gets {
        let page = anonymous.get(path).await;
        assert_eq!(page.status, 303, "anonymous GET {path} must redirect");
        assert_eq!(page.location().as_deref(), Some("/login"), "{path}");
        let page = bob.get(path).await;
        assert_eq!(
            page.status, 403,
            "a plain user's GET {path} must be forbidden"
        );
    }
    for (path, fields) in posts {
        let page = anonymous.post(path, fields).await;
        assert_eq!(page.status, 303, "anonymous POST {path} must redirect");
        assert_eq!(page.location().as_deref(), Some("/login"), "{path}");
        let page = bob.post(path, fields).await;
        assert_eq!(
            page.status, 403,
            "a plain user's POST {path} must be forbidden"
        );
    }
    assert_eq!(dashboard_names(&w), vec!["Usage".to_owned()]);
    assert_eq!(count(&w, "SELECT COUNT(*) FROM charts"), 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_without_the_csrf_token_is_refused_and_stores_nothing() {
    let w = World::start().await;
    let refused = w.owner.post("/admin/dashboards", &[("name", "Ops")]).await;
    assert_eq!(
        refused.status, 403,
        "a post with no csrf token must be refused"
    );
    let refused = w
        .owner
        .post("/admin/dashboards/1/charts", &[("title", "Ops")])
        .await;
    assert_eq!(
        refused.status, 403,
        "a chart post with no csrf token must be refused"
    );
    assert_eq!(dashboard_names(&w), vec!["Usage".to_owned()]);
    assert_eq!(count(&w, "SELECT COUNT(*) FROM charts"), 10);
    assert!(admin_changes(&w).is_empty(), "a refused post writes no row");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_and_the_owner_create_rename_reorder_add_change_and_delete() {
    let w = World::start().await;
    let ada = w.admin(ADA).await;
    assert_eq!(
        create(&ada, "Ops").await.status,
        303,
        "an admin's create answers 303"
    );
    let id = dashboard_id(&w, "Ops");
    assert_eq!(rename(&w.owner, id, "Ops Team").await.status, 303);
    assert_eq!(
        add_chart(
            &ada,
            id,
            &Chart::new("Errors", "failed", "server", "ranked")
        )
        .await
        .status,
        303
    );
    let errors = chart_id_of(&w, "Errors");
    assert_eq!(
        update_chart(
            &w.owner,
            id,
            errors,
            &Chart::new("Failures", "failed", "server", "ranked")
        )
        .await
        .status,
        303
    );
    assert_eq!(chart_titles(&w, "Ops Team"), vec!["Failures".to_owned()]);
    assert_eq!(move_dashboard(&ada, id, "up").await.status, 303);
    assert_eq!(
        dashboard_names(&w),
        vec!["Ops Team".to_owned(), "Usage".to_owned()],
        "moving up puts the dashboard first"
    );
    assert_eq!(delete_dashboard(&w.owner, id).await.status, 303);
    assert_eq!(dashboard_names(&w), vec!["Usage".to_owned()]);
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE dashboard_id = 1"),
        10,
        "deleting another dashboard leaves the Usage charts"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_admin_sees_and_edits_a_dashboard_made_by_one_admin() {
    let w = World::start().await;
    let ada = w.admin(ADA).await;
    let grace = w.admin(GRACE).await;
    create(&ada, "Shared").await;
    let id = dashboard_id(&w, "Shared");
    let list = grace.get(LIST).await;
    assert_eq!(list.status, 200, "another admin can open the list");
    assert!(
        list.body.contains("Shared"),
        "the list shows the other admin's dashboard"
    );
    assert_eq!(rename(&grace, id, "Shared by all").await.status, 303);
    assert_eq!(
        dashboard_names(&w),
        vec!["Usage".to_owned(), "Shared by all".to_owned()]
    );
    let calls = Chart::new("Calls", "calls", "none", "number");
    assert_eq!(add_chart(&grace, id, &calls).await.status, 303);
    assert_eq!(chart_titles(&w, "Shared by all"), vec!["Calls".to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_change_writes_its_admin_change_row() {
    let w = World::start().await;
    let owner = &w.owner;
    create(owner, "Ops").await;
    let id = dashboard_id(&w, "Ops");
    rename(owner, id, "Ops Team").await;
    add_chart(
        owner,
        id,
        &Chart::new("Errors", "failed", "server", "ranked"),
    )
    .await;
    add_chart(owner, id, &Chart::new("Calls", "calls", "server", "ranked")).await;
    move_chart(owner, id, chart_id_of(&w, "Calls"), "up").await;
    update_chart(
        owner,
        id,
        chart_id_of(&w, "Calls"),
        &Chart::new("Calls by server", "calls", "server", "ranked"),
    )
    .await;
    delete_chart(owner, id, chart_id_of(&w, "Errors")).await;
    move_dashboard(owner, id, "up").await;
    delete_dashboard(owner, id).await;
    let rows = admin_changes(&w);
    assert!(
        rows.iter().all(|(who, _)| who == OWNER_EMAIL),
        "the owner made every change: {rows:?}"
    );
    let details: Vec<String> = rows.into_iter().map(|(_, detail)| detail).collect();
    assert_eq!(
        details,
        vec![
            "created dashboard Ops".to_owned(),
            "renamed dashboard Ops to Ops Team".to_owned(),
            "added chart Errors to dashboard Ops Team".to_owned(),
            "added chart Calls to dashboard Ops Team".to_owned(),
            "moved chart Calls up on dashboard Ops Team".to_owned(),
            "changed chart Calls by server on dashboard Ops Team".to_owned(),
            "deleted chart Errors from dashboard Ops Team".to_owned(),
            "moved dashboard Ops Team up".to_owned(),
            "deleted dashboard Ops Team".to_owned(),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_name_is_trimmed_unique_and_1_to_80_characters() {
    let w = World::start().await;
    let owner = &w.owner;
    assert_eq!(create(owner, "  Ops  ").await.status, 303);
    assert_eq!(
        dashboard_names(&w),
        vec!["Usage".to_owned(), "Ops".to_owned()]
    );

    let page = create(owner, "Ops").await;
    assert_eq!(page.status, 400, "a taken name must be refused with 400");
    assert_eq!(
        element_text(&page, "p.field-error#dashboard-name-error").as_deref(),
        Some("A dashboard with that name already exists.")
    );
    assert_eq!(
        value_of(&page, "input#dashboard-name").as_deref(),
        Some("Ops")
    );

    let long = "n".repeat(81);
    for name in ["", "   ", long.as_str()] {
        let page = create(owner, name).await;
        assert_eq!(
            page.status, 400,
            "the name {name:?} must be refused with 400"
        );
        assert_eq!(
            element_text(&page, "p.field-error#dashboard-name-error").as_deref(),
            Some("A dashboard needs a name of 1 to 80 characters.")
        );
    }
    assert_eq!(
        create(owner, &"n".repeat(80)).await.status,
        303,
        "80 characters are allowed"
    );
    assert_eq!(
        dashboard_names(&w).len(),
        3,
        "only the accepted names are stored"
    );

    let page = rename(owner, dashboard_id(&w, "Ops"), "Usage").await;
    assert_eq!(
        page.status, 400,
        "a rename onto a taken name must be refused"
    );
    assert_eq!(dashboard_names(&w).len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_limits_are_20_dashboards_and_24_charts_per_dashboard() {
    let w = World::start().await;
    let owner = &w.owner;
    for index in 2..=20 {
        assert_eq!(create(owner, &format!("Board {index}")).await.status, 303);
    }
    assert_eq!(
        dashboard_names(&w).len(),
        20,
        "the twentieth dashboard is stored"
    );
    let page = create(owner, "One too many").await;
    assert_eq!(page.status, 400, "a twenty-first dashboard must be refused");
    assert_eq!(
        element_text(&page, "div.notice[data-notice=\"error\"] p").as_deref(),
        Some(
            "The dashboard was not added. There are 20 dashboards already, the most there can be."
        )
    );
    assert_eq!(dashboard_names(&w).len(), 20);

    for index in 11..=24 {
        let chart = Chart::new(&format!("Chart {index}"), "calls", "none", "number");
        assert_eq!(add_chart(owner, 1, &chart).await.status, 303);
    }
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE dashboard_id = 1"),
        24
    );
    let page = add_chart(owner, 1, &Chart::new("Chart 25", "calls", "none", "number")).await;
    assert_eq!(page.status, 400, "a twenty-fifth chart must be refused");
    assert_eq!(
        element_text(&page, "div.notice[data-notice=\"error\"] p").as_deref(),
        Some(
            "The chart was not added. This dashboard has 24 charts already, the most it can hold."
        )
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE dashboard_id = 1"),
        24
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_invalid_chart_combination_and_value_is_refused_and_stores_nothing() {
    let w = World::start().await;
    let owner = &w.owner;
    let base = || Chart::new("x", "calls", "none", "number");
    let cases: Vec<(&str, Chart, &str, &str)> = vec![
        (
            "chart-title",
            Chart {
                title: String::new(),
                ..base()
            },
            "A chart needs a title of 1 to 80 characters.",
            "an empty title",
        ),
        (
            "chart-title",
            Chart {
                title: "   ".into(),
                ..base()
            },
            "A chart needs a title of 1 to 80 characters.",
            "a blank title",
        ),
        (
            "chart-title",
            Chart {
                title: "c".repeat(81),
                ..base()
            },
            "A chart needs a title of 1 to 80 characters.",
            "a title of 81 characters",
        ),
        (
            "chart-metric",
            Chart {
                metric: "bogus".into(),
                ..base()
            },
            "Choose a metric from the list.",
            "an unknown metric",
        ),
        (
            "chart-group-by",
            Chart {
                group_by: "week".into(),
                ..base()
            },
            "Choose a grouping from the list.",
            "an unknown grouping",
        ),
        (
            "chart-shape",
            Chart {
                shape: "pie".into(),
                ..base()
            },
            "Choose a shape from the list.",
            "an unknown shape",
        ),
        (
            "chart-period",
            Chart {
                period: "1y".into(),
                ..base()
            },
            "Choose a period from the list.",
            "an unknown period",
        ),
        (
            "chart-period",
            Chart {
                period: "all".into(),
                ..base()
            },
            "Choose a period from the list.",
            "all time as a chart period",
        ),
        (
            "chart-width",
            Chart {
                width: "wide".into(),
                ..base()
            },
            "Choose a width from the list.",
            "an unknown width",
        ),
        (
            "chart-server",
            Chart {
                server_id: "999".into(),
                ..Chart::new("x", "calls", "server", "ranked")
            },
            "Choose a server that exists, or any server.",
            "a server that does not exist",
        ),
        (
            "chart-server",
            Chart {
                server_id: "demo".into(),
                ..Chart::new("x", "calls", "server", "ranked")
            },
            "Choose a server that exists, or any server.",
            "a server that is not an id",
        ),
        (
            "chart-user",
            Chart {
                user_id: "999".into(),
                ..base()
            },
            "Choose a user that exists, or any user.",
            "a user that does not exist",
        ),
        (
            "chart-tool",
            Chart {
                tool: "t".repeat(129),
                ..base()
            },
            "A tool name is 1 to 128 characters.",
            "a tool name of 129 characters",
        ),
        (
            "chart-top",
            Chart {
                top_n: "7".into(),
                ..Chart::new("x", "calls", "user", "ranked")
            },
            "A ranked chart needs a top count of 5, 10, 20 or 50.",
            "a top count of 7",
        ),
        (
            "chart-top",
            Chart {
                top_n: String::new(),
                ..Chart::new("x", "calls", "tool", "ranked")
            },
            "A ranked chart needs a top count of 5, 10, 20 or 50.",
            "a ranked chart with no top count",
        ),
        (
            "chart-shape",
            Chart::new("x", "calls", "time", "ranked"),
            NOT_A_SHAPE,
            "time as ranked",
        ),
        (
            "chart-shape",
            Chart::new("x", "calls", "user", "bars"),
            NOT_A_SHAPE,
            "users as bars",
        ),
        (
            "chart-shape",
            Chart::new("x", "calls", "none", "ranked"),
            NOT_A_SHAPE,
            "no group as ranked",
        ),
        (
            "chart-shape",
            Chart::new("x", "calls", "none", "table"),
            NOT_A_SHAPE,
            "no group as a table",
        ),
        (
            "chart-group-by",
            Chart::new("x", "unused_tools", "time", "table"),
            "Unused tools has no grouping: choose none.",
            "unused tools over time",
        ),
        (
            "chart-shape",
            Chart::new("x", "unused_tools", "none", "number"),
            "Unused tools is shown as a table.",
            "unused tools as a number",
        ),
    ];
    for (field, chart, message, what) in &cases {
        let page = add_chart(owner, 1, chart).await;
        assert_eq!(page.status, 400, "{what} must be refused with 400");
        assert_eq!(
            element_text(&page, &format!("p.field-error#{field}-error")).as_deref(),
            Some(*message),
            "{what} must name its field with its message"
        );
        assert_eq!(
            count(&w, "SELECT COUNT(*) FROM charts"),
            10,
            "{what} must store nothing"
        );
    }
    assert!(
        admin_changes(&w).is_empty(),
        "a refused chart writes no row"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_chart_form_comes_back_filled_with_the_field_error() {
    let w = World::start().await;
    let chart = Chart {
        title: String::new(),
        metric: "failed".into(),
        group_by: "server".into(),
        shape: "ranked".into(),
        ..Chart::new("x", "calls", "none", "number")
    };
    let page = add_chart(&w.owner, 1, &chart).await;
    assert_eq!(page.status, 400);
    assert_eq!(value_of(&page, "input#chart-title").as_deref(), Some(""));
    assert_eq!(
        selected(&page, "select#chart-metric"),
        vec!["failed".to_owned()]
    );
    assert_eq!(
        selected(&page, "select#chart-group-by"),
        vec!["server".to_owned()]
    );
    assert_eq!(
        selected(&page, "select#chart-shape"),
        vec!["ranked".to_owned()]
    );
    assert_eq!(
        page.attr("input#chart-title", "aria-invalid").as_deref(),
        Some("true")
    );
    assert_eq!(
        page.attr("input#chart-title", "aria-describedby")
            .as_deref(),
        Some("chart-title-error")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chart_filtered_to_a_deleted_server_or_user_is_removed_with_it() {
    let w = World::start().await;
    let owner = &w.owner;
    let (_upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    let _bob = w.user(BOB).await;
    let bob_id = w.user_id(BOB).await;
    let by_server = Chart {
        server_id: demo.clone(),
        ..Chart::new("By server", "calls", "tool", "ranked")
    };
    let by_user = Chart {
        user_id: bob_id.clone(),
        ..Chart::new("By user", "calls", "tool", "ranked")
    };
    add_chart(owner, 1, &by_server).await;
    add_chart(owner, 1, &by_user).await;
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE dashboard_id = 1"),
        12
    );

    assert_eq!(admin::delete_server(owner, &demo).await.status, 303);
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE title = 'By server'"),
        0,
        "a chart filtered to the deleted server is removed"
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE title = 'By user'"),
        1
    );

    assert_eq!(
        admin::user_action(owner, &bob_id, "delete").await.status,
        303
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE title = 'By user'"),
        0,
        "a chart filtered to the deleted user is removed"
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE dashboard_id = 1"),
        10,
        "the unfiltered charts stay"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_seeded_usage_dashboard_has_its_ten_charts_on_a_fresh_database() {
    let w = World::start().await;
    assert_eq!(dashboard_names(&w), vec!["Usage".to_owned()]);
    let conn = open(&w);
    let mut statement = conn
        .prepare(
            "SELECT title, metric, group_by, shape, period, CAST(COALESCE(top_n, '') AS TEXT), width \
             FROM charts WHERE dashboard_id = 1 ORDER BY position",
        )
        .expect("the charts query");
    let rows: Vec<[String; 7]> = statement
        .query_map([], |row| {
            Ok([
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ])
        })
        .expect("the charts")
        .map(|row| row.expect("a chart"))
        .collect();
    let expected: Vec<[String; 7]> = USAGE
        .iter()
        .map(|(title, metric, group, shape, period, top, width)| {
            [title, metric, group, shape, period, top, width].map(|text| (*text).to_owned())
        })
        .collect();
    assert_eq!(
        rows, expected,
        "the Usage charts are the ten of statement 96"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_edit_link_shows_the_form_filled_with_that_chart() {
    let w = World::start().await;
    let owner = &w.owner;
    let chart_id = chart_id_of(&w, "Calls by client");
    let page = owner
        .get(&format!("/admin/dashboards/1?chart={chart_id}#chart"))
        .await;
    assert_eq!(page.status, 200);
    assert_eq!(
        element_text(&page, "section#chart h2").as_deref(),
        Some("Edit Calls by client")
    );
    assert_eq!(
        value_of(&page, "input#chart-title").as_deref(),
        Some("Calls by client")
    );
    assert_eq!(
        selected(&page, "select#chart-metric"),
        vec!["calls".to_owned()]
    );
    assert_eq!(
        selected(&page, "select#chart-group-by"),
        vec!["client".to_owned()]
    );
    assert_eq!(
        selected(&page, "select#chart-shape"),
        vec!["ranked".to_owned()]
    );
    assert_eq!(selected(&page, "select#chart-top"), vec!["10".to_owned()]);

    let page = owner.get("/admin/dashboards/1").await;
    assert_eq!(
        element_text(&page, "section#chart h2").as_deref(),
        Some("Add a chart")
    );
    assert_eq!(value_of(&page, "input#chart-title").as_deref(), Some(""));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_delete_dashboard_action_sits_in_a_confirm_disclosure() {
    let w = World::start().await;
    let page = w.owner.get("/admin/dashboards/1").await;
    assert_eq!(
        page.count("details.confirm[data-confirm]:not(.row-confirm)"),
        1,
        "the dashboard's delete sits in one confirm disclosure"
    );
    let doc = Html::parse_document(&page.body);
    let selector = Selector::parse("details.confirm:not(.row-confirm) form").expect("a selector");
    let actions: Vec<String> = doc
        .select(&selector)
        .filter_map(|form| form.value().attr("action").map(str::to_owned))
        .collect();
    assert_eq!(
        actions,
        vec!["/admin/dashboards/1/delete".to_owned()],
        "the disclosure holds the dashboard's delete form"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_dashboards_and_charts_are_not_found() {
    let w = World::start().await;
    let owner = &w.owner;
    assert_eq!(owner.get("/admin/dashboards/999").await.status, 404);
    assert_eq!(owner.get("/admin/dashboards/abc").await.status, 404);
    let page = add_chart(owner, 999, &Chart::new("x", "calls", "none", "number")).await;
    assert_eq!(
        page.status, 404,
        "a chart added to an unknown dashboard is not found"
    );
    let page = update_chart(owner, 1, 999, &Chart::new("x", "calls", "none", "number")).await;
    assert_eq!(page.status, 404, "an unknown chart is not found");
    assert_eq!(count(&w, "SELECT COUNT(*) FROM charts"), 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_a_chart_swaps_it_with_its_neighbour_and_stops_at_the_ends() {
    let w = World::start().await;
    let owner = &w.owner;
    let first = chart_id_of(&w, "Tool calls over time");
    let second = chart_id_of(&w, "Active users over time");
    let before = chart_titles(&w, "Usage");
    assert_eq!(move_chart(owner, 1, first, "up").await.status, 303);
    assert_eq!(
        chart_titles(&w, "Usage"),
        before,
        "the first chart stays first"
    );
    move_chart(owner, 1, first, "down").await;
    assert_eq!(chart_titles(&w, "Usage")[0], "Active users over time");
    assert_eq!(chart_titles(&w, "Usage")[1], "Tool calls over time");
    move_chart(owner, 1, second, "up").await;
    assert_eq!(
        chart_titles(&w, "Usage")[0],
        "Active users over time",
        "the first chart stays first"
    );
    assert_eq!(
        chart_titles(&w, "Usage").len(),
        10,
        "no chart is lost or copied"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dashboard_moves_past_its_neighbour_and_a_chart_can_be_deleted() {
    let w = World::start().await;
    let owner = &w.owner;
    create(owner, "Second").await;
    let second = dashboard_id(&w, "Second");
    move_dashboard(owner, second, "up").await;
    assert_eq!(
        dashboard_names(&w),
        vec!["Second".to_owned(), "Usage".to_owned()]
    );
    move_dashboard(owner, second, "up").await;
    assert_eq!(
        dashboard_names(&w),
        vec!["Second".to_owned(), "Usage".to_owned()],
        "the first dashboard stays first"
    );
    delete_chart(owner, 1, chart_id_of(&w, "Unused tools")).await;
    assert_eq!(
        count(
            &w,
            "SELECT COUNT(*) FROM charts WHERE title = 'Unused tools'"
        ),
        0
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts WHERE dashboard_id = 1"),
        9
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_chart_sits_in_a_confirm_disclosure_and_still_needs_its_csrf_post() {
    let w = World::start().await;
    let page = w.owner.get("/admin/dashboards/1").await;
    let id = dashboard_id(&w, "Usage");
    let first = chart_id_of(&w, "Tool calls over time");
    let doc = Html::parse_document(&page.body);
    let disclosures =
        Selector::parse("details.confirm.row-confirm[data-confirm]").expect("a selector");
    let summary = Selector::parse("summary").expect("a selector");
    let form = Selector::parse("form").expect("a selector");
    let input = Selector::parse(r#"input[name="csrf"]"#).expect("a selector");
    let action = format!("/admin/dashboards/{id}/charts/{first}/delete");
    let found: Vec<_> = doc
        .select(&disclosures)
        .filter(|details| {
            details
                .select(&summary)
                .next()
                .is_some_and(|s| s.text().collect::<String>() == "Delete chart")
        })
        .collect();
    assert_eq!(
        found.len(),
        10,
        "each of the ten charts has a Delete chart disclosure"
    );
    let target = found
        .iter()
        .find(|details| {
            details
                .select(&form)
                .any(|f| f.value().attr("action") == Some(action.as_str()))
        })
        .expect("the first chart's disclosure holds its delete form");
    let token = target
        .select(&input)
        .next()
        .and_then(|field| field.value().attr("value"))
        .expect("the delete form carries a csrf token");
    assert!(!token.is_empty(), "the csrf token is not empty");
    assert!(
        target.value().attr("open").is_none(),
        "the disclosure is closed on the page"
    );
    let before = count(&w, "SELECT COUNT(*) FROM charts");
    let refused = w.owner.post(&action, &[]).await;
    assert_eq!(
        refused.status, 403,
        "a delete without its csrf token is refused"
    );
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM charts"),
        before,
        "nothing is deleted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tab_longer_than_28_characters_carries_its_full_name_in_title() {
    let w = World::start().await;
    let owner = &w.owner;
    let long = "Production database, by person and by tool, last 30 days";
    assert!(
        long.chars().count() > 28,
        "the name is longer than 28 characters"
    );
    let created = create(owner, long).await;
    assert_eq!(created.status, 303, "the long dashboard is created");
    let page = owner.get("/admin").await;
    assert_eq!(page.status, 200, "the Overview answers 200");
    let doc = Html::parse_document(&page.body);
    let tabs = Selector::parse("nav.tabs li a").expect("a selector");
    let titles: Vec<(String, Option<String>)> = doc
        .select(&tabs)
        .map(|a| {
            (
                a.text().collect::<String>(),
                a.value().attr("title").map(str::to_owned),
            )
        })
        .collect();
    let (_, title) = titles
        .iter()
        .find(|(text, _)| text.contains("Production database"))
        .expect("the long tab is on the strip");
    assert_eq!(
        title.as_deref(),
        Some(long),
        "the long tab's title is the whole name"
    );
    let (_, short) = titles
        .iter()
        .find(|(text, _)| text == "Usage")
        .expect("the Usage tab is on the strip");
    assert_eq!(
        short.as_deref(),
        None,
        "a name of 28 characters or fewer has no title"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overview_dashboard_header_links_to_its_edit_page() {
    let w = World::start().await;
    let page = w.owner.get("/admin?dashboard=1").await;
    assert_eq!(
        page.attr(".dash-edit a", "href").as_deref(),
        Some("/admin/dashboards/1"),
        "Edit dashboard opens the dashboard's edit page"
    );
    assert_eq!(
        page.text(".dash-edit a").as_deref(),
        Some("Edit dashboard"),
        "the header link reads Edit dashboard"
    );
}

/// The parts of a page's main in document order: the chart table as "charts", else each section's id.
fn section_ids(page: &Page) -> Vec<String> {
    let doc = Html::parse_document(&page.body);
    let selector = Selector::parse("main > *").expect("a selector");
    doc.select(&selector)
        .filter_map(|child| {
            if child
                .value()
                .has_class("chartlist", scraper::CaseSensitivity::CaseSensitive)
            {
                Some("charts".to_owned())
            } else {
                child.value().attr("id").map(str::to_owned)
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_edit_page_orders_charts_builder_name_and_delete_and_says_its_place() {
    let w = World::start().await;
    let page = w.owner.get("/admin/dashboards/1").await;
    assert_eq!(
        section_ids(&page),
        vec!["charts", "chart", "rename", "delete"],
        "the edit page reads the chart table, the builder, Name, then Delete"
    );
    assert_eq!(
        page.texts("p.meta span"),
        vec![
            "10 of 24 charts".to_string(),
            "Opens first on Overview".to_string()
        ],
        "the header gives the count and that the dashboard opens first"
    );
    let second = w.owner.submit(LIST, LIST, &[("name", "Second")]).await;
    assert_eq!(second.status, 303, "a second dashboard is created");
    let page = w.owner.get("/admin/dashboards/2").await;
    assert_eq!(
        page.texts("p.meta span"),
        vec!["0 of 24 charts".to_string()],
        "a dashboard that is not first does not say it opens first"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_chart_list_is_a_table_whose_counts_read_as_the_chart_caption() {
    let w = World::start().await;
    let page = w.owner.get("/admin/dashboards/1").await;
    assert_eq!(
        page.texts("table.chartlist thead th"),
        vec![
            "Chart".to_string(),
            "Counts".to_string(),
            "Shown as".to_string(),
            String::new(),
        ],
        "the chart list is a table with its columns under the header"
    );
    let rows = page.count("table.chartlist tbody tr");
    assert_eq!(rows, 10, "every chart of the usage dashboard is a row");
    let first = page
        .texts("table.chartlist tbody tr td:nth-child(2)")
        .into_iter()
        .next()
        .expect("the first row has a counts cell");
    assert_eq!(
        first, "Tool calls let through per day, last 30 days.",
        "the counts cell is the caption the Overview shows under the title"
    );
    assert_eq!(
        page.texts("table.chartlist tbody tr td.half")
            .into_iter()
            .next()
            .as_deref(),
        Some("Bars, full"),
        "shape and width stay in Shown as"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edited_row_says_editing_and_its_link_opens_the_form_in_view() {
    let w = World::start().await;
    let chart_id = chart_id_of(&w, "Calls by client");
    let page = w
        .owner
        .get(&format!("/admin/dashboards/1?chart={chart_id}#chart"))
        .await;
    assert_eq!(
        page.text(&format!(r#"tr[data-chart-id="{chart_id}"] span.editing"#))
            .as_deref(),
        Some("Editing"),
        "the edited row reads Editing where its actions were"
    );
    assert_eq!(
        page.count(&format!(
            r#"tr[data-chart-id="{chart_id}"] div.row-actions"#
        )),
        0,
        "the edited row has none of its three actions"
    );
    assert_eq!(
        page.count(r#"tr[data-chart-id] span.editing"#),
        1,
        "only the edited row reads Editing"
    );
    let plain = w.owner.get("/admin/dashboards/1").await;
    assert_eq!(
        plain
            .attr(&format!(r#"tr[data-chart-id="{chart_id}"] a.name"#), "href")
            .as_deref(),
        Some(format!("/admin/dashboards/1?chart={chart_id}#chart").as_str()),
        "the chart's link carries the #chart anchor to the form"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_builder_reads_as_the_design_and_offers_the_tools_of_the_chosen_server() {
    let w = World::start().await;
    let (_up, id) = w
        .upstream(
            "demo",
            UpstreamOptions {
                tools: vec!["alpha".into(), "beta".into()],
                ..Default::default()
            },
        )
        .await;
    let page = w.owner.get("/admin/dashboards/1").await;
    assert_eq!(
        page.attrs(
            "section#chart form.builder [id^='chart-']:is(input, select)",
            "id"
        ),
        vec![
            "chart-title",
            "chart-metric",
            "chart-period",
            "chart-group-by",
            "chart-shape",
            "chart-top",
            "chart-width",
            "chart-server",
            "chart-user",
            "chart-tool",
        ],
        "the builder reads Title; Metric, Period; Group by, Shape; Rows, Width; then the scope filters"
    );
    assert_eq!(
        page.texts("section#chart fieldset legend"),
        vec!["Count only".to_string()],
        "the three scope filters sit in a Count only group"
    );
    assert_eq!(
        page.text("section#chart fieldset p.muted").as_deref(),
        Some("Leave all three empty to count everything.")
    );
    assert_eq!(
        page.text("section#chart p.hint#chart-metric-hint")
            .as_deref(),
        Some("Unused tools is always a table that is not grouped.")
    );
    assert_eq!(
        page.count("datalist#chart-tools option"),
        0,
        "with no server chosen the tool field has no list"
    );

    let refreshed = admin::refresh_tools(&w.owner, &id).await;
    assert_eq!(
        refreshed.status, 303,
        "refreshing the tools must answer 303"
    );
    let chart_id = chart_id_of(&w, "Calls by client");
    let page = w
        .owner
        .get(&format!("/admin/dashboards/1?chart={chart_id}#chart"))
        .await;
    assert_eq!(
        page.count("datalist#chart-tools option"),
        0,
        "the chart has no server, so no tool is offered"
    );
    let added = w
        .owner
        .submit(
            LIST,
            "/admin/dashboards/1/charts",
            &[
                ("title", "Filtered"),
                ("metric", "calls"),
                ("group_by", "tool"),
                ("shape", "ranked"),
                ("period", "30d"),
                ("server_id", &id.to_string()),
                ("user_id", ""),
                ("tool", ""),
                ("top_n", "10"),
                ("width", "half"),
            ],
        )
        .await;
    assert_eq!(added.status, 303, "the filtered chart is added");
    let filtered = chart_id_of(&w, "Filtered");
    let page = w
        .owner
        .get(&format!("/admin/dashboards/1?chart={filtered}#chart"))
        .await;
    assert_eq!(
        page.attrs("datalist#chart-tools option", "value"),
        vec!["alpha".to_string(), "beta".to_string()],
        "with a server chosen the tool field offers that server's tools"
    );
}
