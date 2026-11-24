//! The dashboards pages: the list, one dashboard's edit page with its chart forms, the handlers that
//! change them, and the dashboard section of the Overview.

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use crate::admin::panel_nav;
use crate::admin::users::parse_id;
use crate::app::AppState;
use crate::db::DbError;
use crate::servers::{self, ServerRef};
use crate::web::{
    MainData, VerifiedForm, Viewer, forbidden, form_page_with, internal_error, not_found, redirect,
    ui,
};

use super::figure;
use super::model::{
    CHART_LIMIT, ChartSpec, Checked, DASHBOARD_LIMIT, Draft, GroupBy, Metric, Period, Shape,
    TOP_COUNTS, Width, check_chart, check_name, field_of,
};
use super::query::{self, Series};
use super::store::{self, Board, Change, Direction, Stored};

/// The page of one refused form: its lead, its refusal, and the form as it was posted.
struct Refusal {
    lead: &'static str,
    message: &'static str,
    form: Form,
}

/// What a refused form held: a dashboard name, or a chart and the chart it edits when there is one.
enum Form {
    Name(String),
    Chart(Box<Draft>, Option<i64>),
}

/// The Dashboards page: the dashboards in order, each with its chart count, and the create form.
pub async fn get_list(viewer: Viewer, State(state): State<AppState>) -> Response {
    match state.db.call(|conn| list_in(conn)).await {
        Ok(rows) => list_page(&viewer, StatusCode::OK, &rows, None),
        Err(err) => internal_error("dashboards page", &err),
    }
}

/// The dashboards with their chart counts, in their order.
fn list_in(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<(Board, usize)>> {
    store::boards_in(conn)?
        .into_iter()
        .map(|board| {
            let charts = store::charts_in(conn, board.id)?.len();
            Ok((board, charts))
        })
        .collect()
}

/// Creates a dashboard. A refused name answers 400 with the form again and stores nothing.
pub async fn post_create(State(state): State<AppState>, form: VerifiedForm) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let posted = form.fields.get("name").to_owned();
    let name = match check_name(&posted) {
        Ok(name) => name,
        Err(message) => {
            return refused_list(
                &state,
                &form.viewer,
                Refusal {
                    lead: "The dashboard was not added.",
                    message,
                    form: Form::Name(posted),
                },
            )
            .await;
        }
    };
    let at = state.clock.now().unix_timestamp();
    let created = state
        .db
        .call(move |conn| store::create_board(conn, &actor, &name, at))
        .await;
    match created {
        Ok(Change::Done(id)) => redirect(&format!("/admin/dashboards/{id}")),
        Ok(Change::Refused(message)) => {
            refused_list(
                &state,
                &form.viewer,
                Refusal {
                    lead: "The dashboard was not added.",
                    message,
                    form: Form::Name(posted),
                },
            )
            .await
        }
        Ok(Change::Missing) => not_found(),
        Err(err) => internal_error("dashboard create", &err),
    }
}

async fn refused_list(state: &AppState, viewer: &Viewer, refusal: Refusal) -> Response {
    match state.db.call(|conn| list_in(conn)).await {
        Ok(rows) => list_page(viewer, StatusCode::BAD_REQUEST, &rows, Some(&refusal)),
        Err(err) => internal_error("dashboards page", &err),
    }
}

/// The edit page of one dashboard. `?chart=<id>` fills the chart form with that chart; without it the
/// form adds a chart.
pub async fn get_board(
    viewer: Viewer,
    State(state): State<AppState>,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let chart = first_value(query.as_deref(), "chart").map(|text| parse_id(&text));
    if chart == Some(None) {
        return not_found();
    }
    let chart = chart.flatten();
    let loaded = state.db.call(move |conn| board_in(conn, id, chart)).await;
    match loaded {
        Ok(Some(view)) => match (chart, view.chart_missing) {
            (Some(_), true) => not_found(),
            _ => board_page(&viewer, StatusCode::OK, &view, None),
        },
        Ok(None) => not_found(),
        Err(err) => internal_error("dashboard page", &err),
    }
}

/// The first value of a key in a raw query string.
pub(super) fn first_value(query: Option<&str>, key: &str) -> Option<String> {
    form_urlencoded::parse(query?.as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// What the edit page shows: the dashboard, its charts, the choices of its filters, and the chart form.
struct BoardView {
    board: Board,
    charts: Vec<Stored>,
    servers: Vec<ServerRef>,
    users: Vec<(i64, String)>,
    editing: Option<(i64, Draft)>,
    chart_missing: bool,
}

/// The dashboard with the chart its query names, when it names one.
fn board_in(
    conn: &rusqlite::Connection,
    id: i64,
    chart: Option<i64>,
) -> rusqlite::Result<Option<BoardView>> {
    let Some(board) = store::board_in(conn, id)? else {
        return Ok(None);
    };
    let charts = store::charts_in(conn, id)?;
    let picked = chart.and_then(|chart| charts.iter().find(|stored| stored.id == chart));
    let editing = picked.map(|stored| (stored.id, draft_of(stored)));
    Ok(Some(BoardView {
        board,
        servers: servers::list(conn)?,
        users: users_in(conn)?,
        chart_missing: chart.is_some() && picked.is_none(),
        charts,
        editing,
    }))
}

fn users_in(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut statement = conn.prepare("SELECT id, email FROM users ORDER BY email")?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

/// A stored chart as the builder form shows it.
fn draft_of(stored: &Stored) -> Draft {
    let spec = &stored.spec;
    Draft {
        title: stored.title.clone(),
        metric: spec.metric.as_str().to_owned(),
        group_by: spec.group_by.as_str().to_owned(),
        shape: spec.shape.as_str().to_owned(),
        period: spec.period.as_str().to_owned(),
        server_id: spec.server_id.map_or_else(String::new, |id| id.to_string()),
        user_id: spec.user_id.map_or_else(String::new, |id| id.to_string()),
        tool: spec.tool.clone().unwrap_or_default(),
        top_n: spec.top_n.unwrap_or(TOP_COUNTS[1]).to_string(),
        width: spec.width.as_str().to_owned(),
    }
}

/// The form of a new chart before anyone types in it.
fn new_draft() -> Draft {
    Draft {
        title: String::new(),
        metric: Metric::Calls.as_str().to_owned(),
        group_by: GroupBy::Time.as_str().to_owned(),
        shape: Shape::Bars.as_str().to_owned(),
        period: Period::D30.as_str().to_owned(),
        server_id: String::new(),
        user_id: String::new(),
        tool: String::new(),
        top_n: TOP_COUNTS[1].to_string(),
        width: Width::Half.as_str().to_owned(),
    }
}

/// Renames a dashboard. A refused name answers 400 with the edit page and the name as posted.
pub async fn post_rename(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let posted = form.fields.get("name").to_owned();
    let at = state.clock.now().unix_timestamp();
    let refusal = match check_name(&posted) {
        Ok(name) => {
            match state
                .db
                .call(move |conn| store::rename_board(conn, &actor, id, &name, at))
                .await
            {
                Ok(Change::Done(())) => return redirect(&format!("/admin/dashboards/{id}")),
                Ok(Change::Refused(message)) => message,
                Ok(Change::Missing) => return not_found(),
                Err(err) => return internal_error("dashboard rename", &err),
            }
        }
        Err(message) => message,
    };
    refused_board(
        &state,
        &form.viewer,
        id,
        Refusal {
            lead: "The dashboard was not renamed.",
            message: refusal,
            form: Form::Name(posted),
        },
    )
    .await
}

/// Deletes a dashboard with its charts and returns to the list.
pub async fn post_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| store::delete_board(conn, &actor, id, at))
        .await
    {
        Ok(Change::Done(())) => redirect("/admin/dashboards"),
        Ok(_) => not_found(),
        Err(err) => internal_error("dashboard delete", &err),
    }
}

/// Moves a dashboard up or down the order. An unknown direction changes nothing.
pub async fn post_move(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let Some(direction) = Direction::parse(form.fields.get("direction")) else {
        return redirect("/admin/dashboards");
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| store::move_board(conn, &actor, id, direction, at))
        .await
    {
        Ok(Change::Done(())) => redirect("/admin/dashboards"),
        Ok(_) => not_found(),
        Err(err) => internal_error("dashboard move", &err),
    }
}

/// Adds a chart to a dashboard. A refused chart answers 400 with the form filled and stores nothing.
pub async fn post_chart_add(
    State(state): State<AppState>,
    Path(id): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    save_chart(&state, form, id, None).await
}

/// Changes one chart of a dashboard. A refused chart answers 400 with the form filled and stores nothing.
pub async fn post_chart_update(
    State(state): State<AppState>,
    Path((id, chart)): Path<(String, String)>,
    form: VerifiedForm,
) -> Response {
    let (Some(id), Some(chart)) = (parse_id(&id), parse_id(&chart)) else {
        return not_found();
    };
    save_chart(&state, form, id, Some(chart)).await
}

/// One transaction's worth of chart save: the posted chart is checked, then added or changed.
async fn save_chart(
    state: &AppState,
    form: VerifiedForm,
    board: i64,
    chart: Option<i64>,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let draft = draft_of_post(&form);
    let lead = if chart.is_some() {
        "The chart was not saved."
    } else {
        "The chart was not added."
    };
    let checked = match check_chart(&draft) {
        Ok(checked) => checked,
        Err(message) => {
            return refused_board(
                state,
                &form.viewer,
                board,
                Refusal {
                    lead,
                    message,
                    form: Form::Chart(Box::new(draft), chart),
                },
            )
            .await;
        }
    };
    let at = state.clock.now().unix_timestamp();
    let outcome = state
        .db
        .call(move |conn| save_in(conn, &actor, board, chart, &checked, at))
        .await;
    match outcome {
        Ok(Change::Done(())) => redirect(&format!("/admin/dashboards/{board}")),
        Ok(Change::Refused(message)) => {
            refused_board(
                state,
                &form.viewer,
                board,
                Refusal {
                    lead,
                    message,
                    form: Form::Chart(Box::new(draft), chart),
                },
            )
            .await
        }
        Ok(Change::Missing) => not_found(),
        Err(err) => internal_error("chart save", &err),
    }
}

/// The chart fields of a posted form, as text.
fn draft_of_post(form: &VerifiedForm) -> Draft {
    let field = |name: &str| form.fields.get(name).to_owned();
    Draft {
        title: field("title"),
        metric: field("metric"),
        group_by: field("group_by"),
        shape: field("shape"),
        period: field("period"),
        server_id: field("server_id"),
        user_id: field("user_id"),
        tool: field("tool"),
        top_n: field("top_n"),
        width: field("width"),
    }
}

fn save_in(
    conn: &mut rusqlite::Connection,
    actor: &crate::web::SessionUser,
    board: i64,
    chart: Option<i64>,
    checked: &Checked,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    match chart {
        Some(chart) => store::update_chart(conn, actor, board, chart, checked, at),
        None => store::add_chart(conn, actor, board, checked, at),
    }
}

/// Deletes one chart of a dashboard.
pub async fn post_chart_delete(
    State(state): State<AppState>,
    Path((id, chart)): Path<(String, String)>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let (Some(id), Some(chart)) = (parse_id(&id), parse_id(&chart)) else {
        return not_found();
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| store::delete_chart(conn, &actor, id, chart, at))
        .await
    {
        Ok(Change::Done(())) => redirect(&format!("/admin/dashboards/{id}")),
        Ok(_) => not_found(),
        Err(err) => internal_error("chart delete", &err),
    }
}

/// Moves a chart one place up or down its dashboard. An unknown direction changes nothing.
pub async fn post_chart_move(
    State(state): State<AppState>,
    Path((id, chart)): Path<(String, String)>,
    form: VerifiedForm,
) -> Response {
    let Some(actor) = form.viewer.user.clone() else {
        return forbidden();
    };
    let (Some(id), Some(chart)) = (parse_id(&id), parse_id(&chart)) else {
        return not_found();
    };
    let back = redirect(&format!("/admin/dashboards/{id}"));
    let Some(direction) = Direction::parse(form.fields.get("direction")) else {
        return back;
    };
    let at = state.clock.now().unix_timestamp();
    match state
        .db
        .call(move |conn| store::move_chart(conn, &actor, id, chart, direction, at))
        .await
    {
        Ok(Change::Done(())) => back,
        Ok(_) => not_found(),
        Err(err) => internal_error("chart move", &err),
    }
}

async fn refused_board(state: &AppState, viewer: &Viewer, id: i64, refusal: Refusal) -> Response {
    match state.db.call(move |conn| board_in(conn, id, None)).await {
        Ok(Some(view)) => board_page(viewer, StatusCode::BAD_REQUEST, &view, Some(&refusal)),
        Ok(None) => not_found(),
        Err(err) => internal_error("dashboard page", &err),
    }
}

/// The page shell for the list, with its rows and any refusal.
fn list_page(
    viewer: &Viewer,
    status: StatusCode,
    rows: &[(Board, usize)],
    refusal: Option<&Refusal>,
) -> Response {
    let data = MainData {
        nav: panel_nav(viewer, "/admin"),
        ..MainData::default()
    };
    form_page_with(viewer, status, "dashboards", "Dashboards", &data, |csrf| {
        list_body(csrf, rows, refusal)
    })
}

fn list_body(csrf: &str, rows: &[(Board, usize)], refusal: Option<&Refusal>) -> Markup {
    let name = match refusal.map(|refusal| &refusal.form) {
        Some(Form::Name(name)) => ui::sent_back(name, ui::SENT_BACK_LIMIT),
        _ => String::new(),
    };
    let error = refusal.and_then(|refusal| error_for(refusal, "dashboard-name"));
    let full = i64::try_from(rows.len()).is_ok_and(|count| count >= DASHBOARD_LIMIT);
    let last = rows.len().saturating_sub(1);
    html! {
        div.page-head {
            p.crumb { a href="/admin" { "Overview" } }
            h1 { "Dashboards" }
            p.lede { "Every admin sees and edits the same dashboards. They are tabs on Overview, in this order." }
            @if !full {
                div.head-actions {
                    a.button data-kind="secondary" href="#add" { "Add a dashboard" }
                }
            }
        }
        @if let Some(refusal) = refusal {
            (refusal_notice(refusal))
        }
        @if rows.is_empty() {
            div.empty {
                h2 { "No dashboard yet." }
                p { "Add the first one below. It becomes a tab on Overview." }
            }
        } @else {
            table.list.dashboards {
                thead {
                    tr {
                        th scope="col" { "Dashboard" }
                        th scope="col" class="c-num num" { "Charts" }
                        th scope="col" class="c-note" { span.sr-only { "Place" } }
                        th scope="col" class="c-act" aria-label="Actions" {}
                    }
                }
                tbody {
                    @for (index, (board, charts)) in rows.iter().enumerate() {
                        tr data-dashboard-id=(board.id) {
                            td.lead { a.name href=(format!("/admin/dashboards/{}", board.id)) { (board.name) } }
                            td.num.half { (charts) span.unit { " charts" } }
                            td.half {
                                @if index == 0 {
                                    "Opens first on Overview"
                                }
                            }
                            td.act.several {
                                (move_pair(csrf, &format!("/admin/dashboards/{}/move", board.id), index == 0, index == last))
                            }
                        }
                    }
                }
            }
        }
        @if full {
            p.notice data-tone="warn" { (format!("{DASHBOARD_LIMIT} of {DASHBOARD_LIMIT} dashboards exist. Delete one to add another.")) }
        } @else {
            section.part id="add" aria-labelledby="add-title" {
                div.part-head {
                    h2 id="add-title" { "Add a dashboard" }
                    p { "It starts empty and becomes the last tab. " span.nowrap { (rows.len()) " of " (DASHBOARD_LIMIT) } " dashboards exist." }
                }
                div.part-body {
                    form.flow method="post" action="/admin/dashboards" {
                        input type="hidden" name="csrf" value=(csrf);
                        div.fields {
                            (name_field("dashboard-name", &name, error))
                        }
                        div.form-actions {
                            button type="submit" data-kind="primary" { "Add dashboard" }
                        }
                    }
                }
            }
        }
    }
}

/// The page shell for one dashboard, with its name, its charts, the chart form and the delete.
fn board_page(
    viewer: &Viewer,
    status: StatusCode,
    view: &BoardView,
    refusal: Option<&Refusal>,
) -> Response {
    let data = MainData {
        nav: panel_nav(viewer, "/admin"),
        ..MainData::default()
    };
    let title = view.board.name.clone();
    form_page_with(viewer, status, "dashboard", &title, &data, |csrf| {
        board_body(csrf, view, refusal)
    })
}

fn board_body(csrf: &str, view: &BoardView, refusal: Option<&Refusal>) -> Markup {
    let board = &view.board;
    let base = format!("/admin/dashboards/{}", board.id);
    let name_refusal = refusal.and_then(|refusal| match &refusal.form {
        Form::Name(name) => Some((name.as_str(), refusal)),
        Form::Chart(..) => None,
    });
    let name_value = match name_refusal {
        Some((name, _)) => ui::sent_back(name, ui::SENT_BACK_LIMIT),
        None => board.name.clone(),
    };
    let name_error = refusal.and_then(|refusal| error_for(refusal, "dashboard-name"));
    let (chart_draft, chart_edit) = match (refusal.map(|refusal| &refusal.form), &view.editing) {
        (Some(Form::Chart(draft, edit)), _) => ((**draft).clone(), *edit),
        (_, Some((id, draft))) => (draft.clone(), Some(*id)),
        _ => (new_draft(), None),
    };
    html! {
        div.page-head {
            p.crumb { a href="/admin/dashboards" { "Dashboards" } }
            h1 { (board.name) }
            p.meta {
                span { (view.charts.len()) " of " (CHART_LIMIT) " charts" }
            }
            div.head-actions {
                a.button data-kind="secondary" href=(format!("/admin?dashboard={}", board.id)) { "Open on Overview" }
            }
        }
        @if let Some(refusal) = refusal {
            (refusal_notice(refusal))
        }
        section.part id="rename" aria-labelledby="rename-title" {
            div.part-head {
                h2 id="rename-title" { "Name" }
                p { "A name of 1 to 80 characters, unique among the dashboards." }
            }
            div.part-body {
                form.flow method="post" action=(base) {
                    input type="hidden" name="csrf" value=(csrf);
                    (name_field("dashboard-name", &name_value, name_error))
                    div.form-actions {
                        button type="submit" data-kind="secondary" { "Save name" }
                    }
                }
            }
        }
        section.part id="charts" aria-labelledby="charts-title" {
            div.part-head {
                h2 id="charts-title" { "Charts" }
                p { "Up to 24 charts. Move one up or down to change its place." }
            }
            div.part-body {
                @if view.charts.is_empty() {
                    div.empty {
                        h2 { "This dashboard has no chart yet." }
                        p { "Add the first one below." }
                    }
                } @else {
                    table.list.chartlist {
                        thead {
                            tr {
                                th scope="col" class="c-title" { "Chart" }
                                th scope="col" { "Counts" }
                                th scope="col" class="c-shown" { "Shown as" }
                                th scope="col" class="c-act" aria-label="Actions" {}
                            }
                        }
                        tbody {
                            @let last = view.charts.len().saturating_sub(1);
                            @for (index, chart) in view.charts.iter().enumerate() {
                                tr data-chart-id=(chart.id) {
                                    td.lead { a.name href=(format!("{base}?chart={}#chart", chart.id)) { (chart.title) } }
                                    td { (chart_words(&chart.spec)) }
                                    td.half { (shown_as(&chart.spec)) }
                                    td.act.several {
                                        div.row-actions {
                                            form method="post" action=(format!("{base}/charts/{}/move", chart.id)) {
                                                input type="hidden" name="csrf" value=(csrf);
                                                button.row-action type="submit" name="direction" value="up" data-kind="secondary" disabled[index == 0] { "Move up" }
                                                button.row-action type="submit" name="direction" value="down" data-kind="secondary" disabled[index == last] { "Move down" }
                                            }
                                            details.confirm.row-confirm data-confirm {
                                                summary { "Delete chart" }
                                                div.confirm-body {
                                                    p { "Removes “" (chart.title) "” from this dashboard. This cannot be undone." }
                                                    form method="post" action=(format!("{base}/charts/{}/delete", chart.id)) {
                                                        input type="hidden" name="csrf" value=(csrf);
                                                        button type="submit" data-kind="danger" { "Delete chart" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        (chart_form(csrf, &base, &view.servers, &view.users, chart_edit, &chart_draft, refusal))
        section.part id="delete" aria-labelledby="delete-title" {
            div.part-head {
                h2 id="delete-title" { "Delete" }
                p { "Removes the dashboard and its charts from every admin's view." }
            }
            div.part-body {
                details.confirm data-confirm {
                    summary {
                        span.confirm-open { "Delete this dashboard " span.chevron aria-hidden="true" {} }
                        " "
                        span.confirm-note { "This cannot be undone." }
                    }
                    div.confirm-body {
                        p { "This cannot be undone." }
                        form method="post" action=(format!("{base}/delete")) {
                            input type="hidden" name="csrf" value=(csrf);
                            button type="submit" data-kind="danger" { "Delete dashboard" }
                        }
                    }
                }
            }
        }
    }
}

/// The shape and width of a chart in words, such as `Bars, full`.
fn shown_as(spec: &ChartSpec) -> String {
    format!("{}, {}", spec.shape.label(), spec.width.as_str())
}

/// One line of what a chart shows, in words.
fn chart_words(spec: &ChartSpec) -> String {
    let grouping = match spec.group_by {
        GroupBy::Nothing => String::new(),
        group => format!(", by {}", group.label().to_lowercase()),
    };
    format!(
        "{}{}, {}, {}, {}",
        spec.metric.label(),
        grouping,
        spec.shape.label().to_lowercase(),
        spec.period.label().to_lowercase(),
        spec.width.as_str()
    )
}

/// The add or edit form of one chart, each field with its label, its hint and its refusal.
fn chart_form(
    csrf: &str,
    base: &str,
    servers: &[ServerRef],
    users: &[(i64, String)],
    edit: Option<i64>,
    draft: &Draft,
    refusal: Option<&Refusal>,
) -> Markup {
    let action = match edit {
        Some(chart) => format!("{base}/charts/{chart}"),
        None => format!("{base}/charts"),
    };
    let heading = if edit.is_some() {
        "Edit a chart"
    } else {
        "Add a chart"
    };
    let submit = if edit.is_some() {
        "Save chart"
    } else {
        "Add chart"
    };
    let error = |field: &str| refusal.and_then(|refusal| error_for(refusal, field));
    let title_note = ui::note_under(error("chart-title"), Some("1 to 80 characters."));
    let title_described = title_note.describer("chart-title");
    let tool_note = ui::note_under(
        error("chart-tool"),
        Some("The exact tool name. Empty means every tool."),
    );
    let tool_described = tool_note.describer("chart-tool");
    let top_note = ui::note_under(
        error("chart-top"),
        Some("For ranked lists and category tables: 5, 10, 20 or 50."),
    );
    let top_described = top_note.describer("chart-top");
    html! {
        section.part id="chart" aria-labelledby="chart-title-heading" {
            div.part-head {
                h2 id="chart-title-heading" { (heading) }
                p { "What the chart counts, how it is grouped and drawn, and the period it covers." }
            }
            div.part-body {
                form.flow method="post" action=(action) {
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields data-cols="2" {
                        (ui::field("chart-title", "Title", false, html! {
                            input id="chart-title" name="title" type="text" value=(draft.title) aria-invalid=[ui::invalid(error("chart-title"))] aria-describedby=[title_described.as_deref()];
                        }, title_note))
                        (ui::field("chart-metric", "Metric", false, html! {
                            select id="chart-metric" name="metric" aria-invalid=[ui::invalid(error("chart-metric"))] {
                                @for metric in Metric::ALL {
                                    option value=(metric.as_str()) selected[draft.metric == metric.as_str()] { (metric.label()) }
                                }
                            }
                        }, ui::note_under(error("chart-metric"), None)))
                    }
                    div.fields data-cols="2" {
                        (ui::field("chart-group-by", "Group by", false, html! {
                            select id="chart-group-by" name="group_by" aria-invalid=[ui::invalid(error("chart-group-by"))] {
                                @for group in GroupBy::ALL {
                                    option value=(group.as_str()) selected[draft.group_by == group.as_str()] { (group.label()) }
                                }
                            }
                        }, ui::note_under(error("chart-group-by"), None)))
                        (ui::field("chart-shape", "Shape", false, html! {
                            select id="chart-shape" name="shape" aria-invalid=[ui::invalid(error("chart-shape"))] {
                                @for shape in Shape::ALL {
                                    option value=(shape.as_str()) selected[draft.shape == shape.as_str()] { (shape.label()) }
                                }
                            }
                        }, ui::note_under(error("chart-shape"), None)))
                    }
                    div.fields data-cols="2" {
                        (ui::field("chart-period", "Period", false, html! {
                            select id="chart-period" name="period" aria-invalid=[ui::invalid(error("chart-period"))] {
                                @for period in Period::ALL {
                                    option value=(period.as_str()) selected[draft.period == period.as_str()] { (period.label()) }
                                }
                            }
                        }, ui::note_under(error("chart-period"), None)))
                        (ui::field("chart-width", "Width", false, html! {
                            select id="chart-width" name="width" aria-invalid=[ui::invalid(error("chart-width"))] {
                                @for width in Width::ALL {
                                    option value=(width.as_str()) selected[draft.width == width.as_str()] { (width.label()) }
                                }
                            }
                        }, ui::note_under(error("chart-width"), None)))
                    }
                    div.fields data-cols="2" {
                        (ui::field("chart-server", "Server", false, html! {
                            select id="chart-server" name="server_id" aria-invalid=[ui::invalid(error("chart-server"))] {
                                option value="" selected[draft.server_id.is_empty()] { "Any server" }
                                @for server in servers {
                                    option value=(server.id) selected[draft.server_id == server.id.to_string()] { (server.slug) ", " (server.name) }
                                }
                            }
                        }, ui::note_under(error("chart-server"), None)))
                        (ui::field("chart-user", "User", false, html! {
                            select id="chart-user" name="user_id" aria-invalid=[ui::invalid(error("chart-user"))] {
                                option value="" selected[draft.user_id.is_empty()] { "Any user" }
                                @for (id, email) in users {
                                    option value=(id) selected[draft.user_id == id.to_string()] { (email) }
                                }
                            }
                        }, ui::note_under(error("chart-user"), None)))
                    }
                    div.fields data-cols="2" {
                        (ui::field("chart-tool", "Tool", true, html! {
                            input id="chart-tool" name="tool" type="text" value=(draft.tool) aria-invalid=[ui::invalid(error("chart-tool"))] aria-describedby=[tool_described.as_deref()];
                        }, tool_note))
                        (ui::field("chart-top", "Top", true, html! {
                            select id="chart-top" name="top_n" aria-invalid=[ui::invalid(error("chart-top"))] aria-describedby=[top_described.as_deref()] {
                                @for count in TOP_COUNTS {
                                    option value=(count) selected[draft.top_n == count.to_string()] { (count) }
                                }
                            }
                        }, top_note))
                    }
                    div.form-actions {
                        button type="submit" data-kind="primary" { (submit) }
                        @if edit.is_some() {
                            a.button data-kind="secondary" href=(format!("{base}#chart")) { "Cancel" }
                        }
                    }
                }
            }
        }
    }
}

/// The field of a refused form that shows the refusal, when the refusal is about one field.
fn error_for<'a>(refusal: &'a Refusal, field: &str) -> Option<&'a str> {
    (field_of(refusal.message) == Some(field)).then_some(refusal.message)
}

/// The notice above a refused form: its lead, its refusal, and a link to the field it is about.
fn refusal_notice(refusal: &Refusal) -> Markup {
    let field = field_of(refusal.message).map(|id| (id, field_name(id)));
    ui::refused(Some(refusal.lead), refusal.message, field)
}

/// The words a notice uses for a field.
fn field_name(id: &str) -> &'static str {
    match id {
        "dashboard-name" => "name",
        "chart-title" => "title",
        "chart-metric" => "metric",
        "chart-group-by" => "grouping",
        "chart-shape" => "shape",
        "chart-period" => "period",
        "chart-width" => "width",
        "chart-server" => "server",
        "chart-user" => "user",
        "chart-tool" => "tool",
        _ => "top count",
    }
}

/// A name field: its label, its input and its hint or refusal.
fn name_field(id: &str, value: &str, error: Option<&str>) -> Markup {
    let note = ui::note_under(error, Some("1 to 80 characters."));
    let described = note.describer(id);
    ui::field(
        id,
        "Name",
        false,
        html! {
            input id=(id) name="name" type="text" value=(value) aria-invalid=[ui::invalid(error)] aria-describedby=[described.as_deref()];
        },
        note,
    )
}

/// The Move up and Move down buttons of one row, in one form; the end of the list cannot move.
fn move_pair(csrf: &str, action: &str, first: bool, last: bool) -> Markup {
    html! {
        div.row-actions {
            form method="post" action=(action) {
                input type="hidden" name="csrf" value=(csrf);
                button.row-action type="submit" name="direction" value="up" data-kind="secondary" disabled[first] { "Move up" }
                button.row-action type="submit" name="direction" value="down" data-kind="secondary" disabled[last] { "Move down" }
            }
        }
    }
}

/// The dashboards of the Overview: tabs for each, the period switch, the edit link and the selected
/// dashboard's charts, each with its figure. The first dashboard shows when the query names none.
pub async fn overview(state: &AppState, query: Option<&str>) -> Result<Markup, DbError> {
    let wanted = first_value(query, "dashboard").and_then(|text| parse_id(&text));
    let period = first_value(query, "period").and_then(|text| Period::parse(&text));
    let now = state.clock.now().unix_timestamp();
    let view = state
        .db
        .call(move |conn| {
            let boards = store::boards_in(conn)?;
            let chosen = wanted
                .and_then(|id| boards.iter().position(|board| board.id == id))
                .or((!boards.is_empty()).then_some(0));
            let mut charts = Vec::new();
            if let Some(index) = chosen {
                for stored in store::charts_in(conn, boards[index].id)? {
                    let shown = period.unwrap_or(stored.spec.period);
                    let series = query::series(conn, &stored.spec, shown, now)?;
                    charts.push(Shown {
                        stored,
                        period: shown,
                        series,
                    });
                }
            }
            Ok(Overview {
                selected: chosen.map(|index| boards[index].id),
                boards,
                charts,
                period,
            })
        })
        .await?;
    Ok(overview_markup(&view))
}

/// A chart of the selected dashboard with its period and the numbers it shows.
struct Shown {
    stored: Stored,
    period: Period,
    series: Series,
}

/// The Overview's dashboards as the page shows them.
struct Overview {
    boards: Vec<Board>,
    selected: Option<i64>,
    charts: Vec<Shown>,
    period: Option<Period>,
}

fn overview_markup(view: &Overview) -> Markup {
    let chosen = view
        .selected
        .and_then(|id| view.boards.iter().find(|board| board.id == id));
    html! {
        section.dash aria-labelledby="dash-title" {
            @if view.boards.is_empty() {
                div.empty {
                    h2 id="dash-title" { "No dashboard yet." }
                    p { "A dashboard is a page of charts drawn from Activity. " a href="/admin/dashboards#add" { "Add a dashboard" } "." }
                }
            } @else if let Some(board) = chosen {
                div.dash-head {
                    @if view.boards.len() > 1 {
                        h2.sr-only id="dash-title" { "Dashboard: " (board.name) }
                        nav.tabs aria-label="Dashboards" {
                            ul {
                                @for tab in &view.boards {
                                    @let current = view.selected == Some(tab.id);
                                    li {
                                        a href=(overview_href(Some(tab.id), view.period))
                                            aria-current=[current.then_some("page")]
                                            title=[(tab.name.chars().count() > 28).then_some(tab.name.as_str())] {
                                            @if current {
                                                span.tab-mark aria-hidden="true" {}
                                            }
                                            span.tab-label { (tab.name) }
                                        }
                                    }
                                }
                            }
                        }
                    } @else {
                        h2.dash-title id="dash-title" { (board.name) }
                    }
                    nav.period aria-label="Period of every chart" {
                        ul {
                            li {
                                a href=(overview_href(Some(board.id), None)) aria-current=[view.period.is_none().then_some("true")] {
                                    @if view.period.is_none() {
                                        span.period-mark aria-hidden="true" {}
                                    }
                                    "Per chart"
                                }
                            }
                            @for (period, label) in [(Period::H24, "24h"), (Period::D7, "7d"), (Period::D30, "30d"), (Period::D90, "90d")] {
                                li {
                                    a href=(overview_href(Some(board.id), Some(period))) aria-current=[(view.period == Some(period)).then_some("true")] {
                                        @if view.period == Some(period) {
                                            span.period-mark aria-hidden="true" {}
                                        }
                                        (label)
                                    }
                                }
                            }
                        }
                    }
                    p.dash-edit {
                        a href=(format!("/admin/dashboards/{}", board.id)) { "Edit dashboard" }
                    }
                }
                @if view.charts.is_empty() {
                    div.empty {
                        h2 { "This dashboard has no chart yet." }
                        p { a href=(format!("/admin/dashboards/{}#chart", board.id)) { "Add a chart" } "." }
                    }
                } @else {
                    div.charts {
                        @for shown in &view.charts {
                            (figure::chart_section(shown.stored.id, &shown.stored.spec, &shown.stored.title, shown.period, &shown.series))
                        }
                    }
                }
            }
        }
    }
}

/// The Overview's path with the dashboard and the period switch as query keys.
fn overview_href(dashboard: Option<i64>, period: Option<Period>) -> String {
    let mut query = Vec::new();
    if let Some(id) = dashboard {
        query.push(format!("dashboard={id}"));
    }
    if let Some(period) = period {
        query.push(format!("period={}", period.as_str()));
    }
    if query.is_empty() {
        "/admin".to_owned()
    } else {
        format!("/admin?{}", query.join("&"))
    }
}
