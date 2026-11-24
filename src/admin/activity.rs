//! The activity page: the rows that match the filters, one page at a time, with the filter form, the
//! active filters and the export link, and the newest rows the overview shows.

mod export;
pub(super) mod filters;

pub(super) use export::get_export;

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use form_urlencoded::Serializer;
use maud::{Markup, html};
use rusqlite::types::Value;
use rusqlite::{Connection, params_from_iter};
use time::OffsetDateTime;
use time::format_description;
use time::format_description::well_known::Rfc3339;

use crate::app::AppState;
use crate::db::{Db, DbError};
use crate::web::ui::{self, breakable, email, thousands, time_cell};
use crate::web::{MainData, Viewer, internal_error, page_with};

use super::panel_nav;
use filters::{Criteria, EVENTS, Filters, PERIODS, criteria, parse_day};

/// Rows on one page of the activity page.
const PAGE_SIZE: i64 = 50;
/// The day, month, year and UTC time of a row, as the page reads them.
const PLAIN_TIME: &str =
    "[day padding:none] [month repr:short] [year] [hour repr:24]:[minute]:[second] UTC";

/// One activity row as the page shows it: the RFC 3339 time, and the same time in plain words.
struct Row {
    time: String,
    plain: String,
    kind: String,
    user_email: String,
    server_slug: String,
    tool: String,
    decision: String,
    outcome: String,
    detail: String,
    duration_ms: Option<i64>,
}

/// What the activity page shows: one page of the matching rows, how many rows match in all, and
/// the choices of both filters.
struct Listing {
    rows: Vec<Row>,
    total: i64,
    users: Vec<UserOption>,
    servers: Vec<ServerOption>,
}

/// A user the user filter offers.
struct UserOption {
    id: i64,
    email: String,
}

/// A server the server filter offers.
struct ServerOption {
    id: i64,
    name: String,
    slug: String,
}

/// The activity page for the filters of its query string.
pub async fn get_activity(
    viewer: Viewer,
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Response {
    let filters = Filters::of(raw.as_deref());
    let number = page_number(filters.page.as_deref());
    let offset = offset_of(number);
    let now = state.clock.now().unix_timestamp();
    let scope_filters = filters.clone();
    let listing = state
        .db
        .call(move |conn| {
            let scope = criteria(&scope_filters, now);
            Ok(Listing {
                rows: rows_in(conn, &scope, PAGE_SIZE, offset)?,
                total: count_in(conn, &scope)?,
                users: users_in(conn)?,
                servers: servers_in(conn)?,
            })
        })
        .await;
    match listing {
        Ok(listing) => activity_page(&viewer, &filters, number, &listing),
        Err(err) => internal_error("activity page", &err),
    }
}

/// The page a query asks for, from 1. A missing, empty, zero, negative or non-numeric value is page
/// 1; digits too large for u64 are the largest u64.
pub(super) fn page_number(text: Option<&str>) -> u64 {
    let number = match text {
        None => 0,
        Some(text) => match text.parse::<u64>() {
            Ok(number) => number,
            Err(_) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
                u64::MAX
            }
            Err(_) => 0,
        },
    };
    number.max(1)
}

/// The rows before a page, saturated at the largest i64 so that no page overflows.
pub(super) fn offset_of(number: u64) -> i64 {
    let rows = number
        .saturating_sub(1)
        .saturating_mul(PAGE_SIZE.unsigned_abs());
    i64::try_from(rows).unwrap_or(i64::MAX)
}

/// Every user, ordered by email.
fn users_in(conn: &Connection) -> rusqlite::Result<Vec<UserOption>> {
    let mut statement = conn.prepare("SELECT id, email FROM users ORDER BY email")?;
    let rows = statement.query_map([], |row| {
        Ok(UserOption {
            id: row.get(0)?,
            email: row.get(1)?,
        })
    })?;
    rows.collect()
}

/// Every server, ordered by slug.
fn servers_in(conn: &Connection) -> rusqlite::Result<Vec<ServerOption>> {
    let mut statement = conn.prepare("SELECT id, name, slug FROM servers ORDER BY slug")?;
    let rows = statement.query_map([], |row| {
        Ok(ServerOption {
            id: row.get(0)?,
            name: row.get(1)?,
            slug: row.get(2)?,
        })
    })?;
    rows.collect()
}

/// The rows that match the scope, newest first, from `offset`, at most `limit` of them.
fn rows_in(
    conn: &Connection,
    scope: &Criteria,
    limit: i64,
    offset: i64,
) -> rusqlite::Result<Vec<Row>> {
    let sql = format!(
        "SELECT at, kind, user_email, server_slug, tool, decision, outcome, detail, duration_ms \
         FROM activity{} ORDER BY at DESC, id DESC LIMIT ? OFFSET ?",
        scope.clause()
    );
    let mut statement = conn.prepare_cached(&sql)?;
    let mut values = scope.values().to_vec();
    values.extend([Value::Integer(limit), Value::Integer(offset)]);
    let rows = statement.query_map(params_from_iter(values), |row| {
        let at: i64 = row.get(0)?;
        Ok(Row {
            time: rfc3339(at)?,
            plain: plain_time(at)?,
            kind: row.get(1)?,
            user_email: row.get(2)?,
            server_slug: row.get(3)?,
            tool: row.get(4)?,
            decision: row.get(5)?,
            outcome: row.get(6)?,
            detail: row.get(7)?,
            duration_ms: row.get(8)?,
        })
    })?;
    rows.collect()
}

/// How many rows match the scope, in all.
fn count_in(conn: &Connection, scope: &Criteria) -> rusqlite::Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM activity{}", scope.clause());
    conn.query_row(&sql, params_from_iter(scope.values()), |row| row.get(0))
}

/// The UTC time of a unix timestamp as RFC 3339.
pub(super) fn rfc3339(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    when.format(&Rfc3339).map_err(invalid_time)
}

/// The UTC time of a unix timestamp in plain words, such as `20 Nov 2026 19:25:09 UTC`.
pub(super) fn plain_time(at: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(at).map_err(invalid_time)?;
    let format = format_description::parse_borrowed::<2>(PLAIN_TIME).map_err(invalid_time)?;
    when.format(&format).map_err(invalid_time)
}

/// The day part of `plain_time`, split as `ui::time_cell` splits it: `20 Nov 2026`.
pub(super) fn day_of(at: i64) -> rusqlite::Result<String> {
    let plain = plain_time(at)?;
    let words = plain.strip_suffix(" UTC").unwrap_or(&plain);
    Ok(words
        .rsplit_once(' ')
        .map_or(words, |(day, _)| day)
        .to_owned())
}

fn invalid_time<E>(err: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

/// The field errors of a custom period: the first day and the last day, each when it is not a date.
fn day_errors(filters: &Filters) -> (Option<&'static str>, Option<&'static str>) {
    if !filters.is_custom() {
        return (None, None);
    }
    let first = parse_day(filters.from.as_deref())
        .is_none()
        .then_some("Enter the first day as YYYY-MM-DD.");
    let last = parse_day(filters.to.as_deref())
        .is_none()
        .then_some("Enter the last day as YYYY-MM-DD.");
    (first, last)
}

/// The value of a filter that no choice of its select names, so the select can still show it.
fn unlisted<'a>(value: Option<&'a str>, choices: &[(&str, &str)]) -> Option<&'a str> {
    value.filter(|value| !choices.iter().any(|(key, _)| key == value))
}

/// The filter form, a closed `details` that the stylesheet opens from 640 px. Its controls are in the
/// order of the form: Search, Tool, Client, Period, From and To, Event, User, Server.
fn filter_form(
    filters: &Filters,
    users: &[UserOption],
    servers: &[ServerOption],
    count: usize,
) -> Markup {
    let (first_error, last_error) = day_errors(filters);
    let first_note = ui::note_under(first_error, Some("UTC, both days included."));
    let first_described = first_note.describer("filter-from");
    let last_note = ui::note_under(last_error, None);
    let last_described = last_note.describer("filter-to");
    let period = html! {
        select id="filter-period" name="period" {
            @for (key, label) in PERIODS {
                option value=(key) selected[filters.period.as_deref() == Some(key)] { (label) }
            }
            @if let Some(other) = unlisted(filters.period.as_deref(), &PERIODS) {
                option value=(other) selected { (other) " (matches nothing)" }
            }
        }
    };
    let from = html! {
        input id="filter-from" type="date" name="from" value=[filters.from.as_deref()]
            aria-describedby=[first_described] aria-invalid=[ui::invalid(first_error)];
    };
    let to = html! {
        input id="filter-to" type="date" name="to" value=[filters.to.as_deref()]
            aria-describedby=[last_described] aria-invalid=[ui::invalid(last_error)];
    };
    let event = html! {
        select id="filter-event" name="event" {
            option value="" { "Any event" }
            @for (key, label) in EVENTS {
                option value=(key) selected[filters.event.as_deref() == Some(key)] { (label) }
            }
            @if let Some(other) = unlisted(filters.event.as_deref(), &EVENTS) {
                option value=(other) selected { (other) " (matches nothing)" }
            }
        }
    };
    let user = html! {
        select id="filter-user" name="user" {
            option value="" { "Any user" }
            @for choice in users {
                option value=(choice.id) selected[filters.user_id() == Some(choice.id)] {
                    (choice.email)
                }
            }
        }
    };
    let server = html! {
        select id="filter-server" name="server" {
            option value="" { "Any server" }
            @for choice in servers {
                option value=(choice.id) selected[filters.server_id() == Some(choice.id)] {
                    (choice.slug) ", " (choice.name)
                }
            }
        }
    };
    let tool = html! {
        input.mono id="filter-tool" type="text" name="tool" value=[filters.tool.as_deref()];
    };
    let client = html! {
        input id="filter-client" type="text" name="client" value=[filters.client.as_deref()];
    };
    let search = html! {
        input id="filter-q" type="search" name="q" value=[filters.q.as_deref()]
            aria-describedby="filter-q-hint";
    };
    let search_note =
        ui::Note::HintMarkup(html! { "Looks in user, server, tool, client and detail." });
    html! {
        details.filter-panel data-filter-panel {
            summary {
                span.filter-open {
                    "Filters"
                    @if count > 0 {
                        " " span.count { (count) " set" }
                    }
                    span.chevron aria-hidden="true" {}
                }
            }
            form.filterbar method="get" action="/admin/activity" data-form="activity-filter" {
                (ui::field_in("f-q", "filter-q", "Search", search, search_note))
                (ui::field_in("f-tool", "filter-tool", "Tool", tool, ui::Note::None))
                (ui::field_in("f-client", "filter-client", "Client", client, ui::Note::None))
                (ui::field_in("f-period", "filter-period", "Period", period, ui::Note::None))
                div.dates {
                    (ui::field_in("f-from", "filter-from", "From", from, first_note))
                    (ui::field_in("f-to", "filter-to", "To", to, last_note))
                }
                (ui::field_in("f-event", "filter-event", "Event", event, ui::Note::None))
                (ui::field_in("f-user", "filter-user", "User", user, ui::Note::None))
                (ui::field_in("f-server", "filter-server", "Server", server, ui::Note::None))
                div.field.field-go {
                    button type="submit" data-kind="secondary" { "Filter" }
                }
            }
        }
    }
}

/// One active filter: its key, the label it shows, its value, and the filters its Remove link drops.
struct Chip {
    key: &'static str,
    label: &'static str,
    value: Markup,
    drop: &'static [&'static str],
}

/// The period in words, as the list of active filters shows it.
fn period_text(filters: &Filters) -> String {
    match filters.period.as_deref() {
        Some("24h") => "last 24 hours".to_owned(),
        Some("7d") => "last 7 days".to_owned(),
        Some("30d") => "last 30 days".to_owned(),
        Some("90d") => "last 90 days".to_owned(),
        Some("custom") => format!(
            "{} to {}",
            filters.from.as_deref().unwrap_or("no first day"),
            filters.to.as_deref().unwrap_or("no last day")
        ),
        Some(other) => other.to_owned(),
        None => "all time".to_owned(),
    }
}

/// The active filters in the order of the form. A user and a server show their email and their slug
/// when the id names one, and the value as typed otherwise.
fn chips(filters: &Filters, users: &[UserOption], servers: &[ServerOption]) -> Vec<Chip> {
    let mut chips = Vec::new();
    if filters.period_is_set() {
        chips.push(Chip {
            key: "period",
            label: "Period",
            value: html! { (period_text(filters)) },
            drop: &["period", "from", "to"],
        });
    }
    if let Some(event) = filters.event.as_deref() {
        let label = EVENTS
            .iter()
            .find(|(key, _)| *key == event)
            .map_or(event, |(_, label)| *label);
        chips.push(Chip {
            key: "event",
            label: "Event",
            value: html! { (label) },
            drop: &["event"],
        });
    }
    if let Some(user) = filters.user.as_deref() {
        let value = match filters
            .user_id()
            .and_then(|id| users.iter().find(|choice| choice.id == id))
        {
            Some(choice) => email(&choice.email),
            None => html! { (user) },
        };
        chips.push(Chip {
            key: "user",
            label: "User",
            value,
            drop: &["user"],
        });
    }
    if let Some(server) = filters.server.as_deref() {
        let slug = filters
            .server_id()
            .and_then(|id| servers.iter().find(|choice| choice.id == id))
            .map_or(server, |choice| choice.slug.as_str());
        chips.push(Chip {
            key: "server",
            label: "Server",
            value: html! { code { (slug) } },
            drop: &["server"],
        });
    }
    if let Some(tool) = filters.tool.as_deref() {
        chips.push(Chip {
            key: "tool",
            label: "Tool",
            value: html! { code { (breakable(tool)) } },
            drop: &["tool"],
        });
    }
    if let Some(client) = filters.client.as_deref() {
        chips.push(Chip {
            key: "client",
            label: "Client",
            value: html! { (client) },
            drop: &["client"],
        });
    }
    if let Some(q) = filters.q.as_deref() {
        chips.push(Chip {
            key: "q",
            label: "Search",
            value: html! { "“" (q) "”" },
            drop: &["q"],
        });
    }
    chips
}

/// The active filters, each a link that removes it, then Clear filters; nothing when no filter
/// narrows the rows.
fn active_filters(filters: &Filters, chips: &[Chip]) -> Markup {
    html! {
        @if !chips.is_empty() {
            ul #active-filters.chips aria-label="Filters that are set" {
                @for chip in chips {
                    li data-filter=(chip.key) {
                        a.chip href=(target("/admin/activity", &query_without(filters, chip.drop))) {
                            span.chip-key { (chip.label) }
                            span.chip-value { (chip.value) }
                            span.chip-x aria-hidden="true" { "×" }
                            span.sr-only { " Remove this filter" }
                        }
                    }
                }
                li {
                    a #clear-filters.chips-clear href="/admin/activity" { "Clear filters" }
                }
            }
        }
    }
}

/// The path with its query string, when the query is not empty.
fn target(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

/// The query string of the set filters, without the keys in `drop`.
fn query_without(filters: &Filters, drop: &[&str]) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in filters.pairs() {
        if !drop.contains(&key) {
            serializer.append_pair(key, value);
        }
    }
    serializer.finish()
}

/// The pager's query: `user` and `server` as the form submits them, empty when unset, then the other
/// set filters, then the page.
fn pager_query(filters: &Filters, page: u64) -> String {
    let mut serializer = Serializer::new(String::new());
    serializer.append_pair("user", filters.user.as_deref().unwrap_or(""));
    serializer.append_pair("server", filters.server.as_deref().unwrap_or(""));
    for (key, value) in filters.pairs() {
        if key != "user" && key != "server" {
            serializer.append_pair(key, value);
        }
    }
    serializer.append_pair("page", &page.to_string());
    serializer.finish()
}

/// The label of a row in plain words, and the tone of its marker when the row needs one.
pub(super) fn label_of(
    kind: &str,
    decision: &str,
    outcome: &str,
) -> (String, Option<&'static str>) {
    let (label, tone) = match kind {
        "tool_call" if decision == "deny" => ("Tool call refused", Some("bad")),
        "tool_call" if outcome == "ok" => ("Tool call", None),
        "tool_call" => ("Tool call failed", Some("bad")),
        "login" => ("Sign-in", None),
        "login_failed" => ("Sign-in refused", Some("bad")),
        "client_connected" => ("Client connected", None),
        "client_disconnected" => ("Client disconnected", None),
        "admin_change" => ("Admin change", None),
        "invitation" => ("Invitation", None),
        "mail_failed" => ("Mail not sent", Some("bad")),
        "owner_created" => ("Owner created", None),
        "reset" => ("Password reset", None),
        "password_change" => ("Password changed", None),
        "redirect_blocked" => ("Redirect blocked", Some("bad")),
        "tool_appeared" => ("New tool listed", None),
        "unlock" => ("Gateway unlocked", None),
        "value_set" => ("Credential stored", None),
        "value_removed" => ("Credential removed", None),
        "values_dropped" => ("Credentials deleted", None),
        _ => return (unknown_label(kind), None),
    };
    (label.to_owned(), tone)
}

/// A kind no label names: its underscores become spaces and its first letter is upper case.
fn unknown_label(kind: &str) -> String {
    let spaced = kind.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The stored detail as markup, its words joined by single spaces. A number and the word after it
/// sit in a `nowrap` span. Its text is the detail itself.
fn detail_markup(detail: &str) -> Markup {
    html! {
        @for (index, (word, joined)) in word_groups(detail).into_iter().enumerate() {
            @if index > 0 {
                " "
            }
            @if let Some(next) = joined {
                span.nowrap { (word_markup(word)) " " (word_markup(next)) }
            } @else {
                (word_markup(word))
            }
        }
    }
}

/// Each word of a detail with the word it joins: a number joins the non-empty word after it, once,
/// and that word joins nothing more.
fn word_groups(detail: &str) -> Vec<(&str, Option<&str>)> {
    let mut words = detail.split(' ').peekable();
    let mut groups = Vec::new();
    while let Some(word) = words.next() {
        let joined = match words.peek() {
            Some(next) if is_number(word) && !next.is_empty() => words.next(),
            _ => None,
        };
        groups.push((word, joined));
    }
    groups
}

/// A word made only of ASCII digits.
fn is_number(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_digit())
}

/// One word: an address through `email`; any other word through `breakable`, in `span.whole` when
/// it has a break point. Escaped text never holds a `<wbr>`, so the markup shows the break points.
fn word_markup(word: &str) -> Markup {
    if is_address(word) {
        return email(word);
    }
    let text = breakable(word);
    if text.clone().into_string().contains("<wbr>") {
        html! { span.whole { (text) } }
    } else {
        text
    }
}

/// A word with exactly one `@`, text on both sides of it, and no `/` or whitespace.
fn is_address(word: &str) -> bool {
    let Some((local, domain)) = word.split_once('@') else {
        return false;
    };
    [local, domain].into_iter().all(|part| {
        !part.is_empty() && !part.contains(['@', '/']) && !part.chars().any(char::is_whitespace)
    })
}

/// One row of the activity table: its label and detail, user, server and tool, decision,
/// duration and time. An empty user, server, tool or duration leaves its cell empty.
fn table_row(row: &Row) -> Markup {
    let (label, tone) = label_of(&row.kind, &row.decision, &row.outcome);
    let decision = [row.decision.as_str(), row.outcome.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    let duration = row
        .duration_ms
        .map_or_else(String::new, |ms| format!("{} ms", thousands(ms)));
    html! {
        tr data-kind=(row.kind) data-user=(row.user_email) data-server=(row.server_slug)
            data-tool=(row.tool) data-decision=(row.decision) data-outcome=(row.outcome)
            data-time=(row.time) data-duration-ms=[row.duration_ms] {
            td.what {
                span.event data-label data-tone=[tone] { (label) }
                @if !row.detail.is_empty() {
                    span.detail { (detail_markup(&row.detail)) }
                }
            }
            td.user {
                @if !row.user_email.is_empty() {
                    (email(&row.user_email))
                }
            }
            td.where {
                @if !row.server_slug.is_empty() {
                    code { (row.server_slug) }
                }
                @if !row.tool.is_empty() {
                    code { (breakable(&row.tool)) }
                }
            }
            td.decision { (decision) }
            td.duration.num { (duration) }
            td.when { (time_cell(&row.time, &row.plain, true)) }
        }
    }
}

/// The activity table with its column heads, one row per entry, newest first.
fn activity_table(rows: &[Row]) -> Markup {
    html! {
        table.list.activity {
            thead {
                tr {
                    th scope="col" { "Event" }
                    th scope="col" class="c-user" { "User" }
                    th scope="col" class="c-where" { "Server and tool" }
                    th scope="col" class="c-decision" { "Decision" }
                    th scope="col" class="c-duration duration num" { "Duration" }
                    th scope="col" class="c-time" { "Time (UTC)" }
                }
            }
            tbody {
                @for row in rows {
                    (table_row(row))
                }
            }
        }
    }
}

/// The newest `limit` rows of the activity log as the overview's table, or a sentence when there
/// are none.
pub(super) async fn latest(db: &Db, limit: i64) -> Result<Markup, DbError> {
    let rows = db
        .call(move |conn| rows_in(conn, &Criteria::default(), limit, 0))
        .await?;
    Ok(html! {
        @if rows.is_empty() {
            p.muted { "No activity yet." }
        } @else {
            (activity_table(&rows))
        }
    })
}

/// The page the newer link names: the one before this, or the last page with rows when this page
/// lies past the end.
fn newer_page(number: u64, total: i64) -> u64 {
    let last = u64::try_from(total)
        .unwrap_or(0)
        .div_ceil(PAGE_SIZE.unsigned_abs());
    if total > 0 && number > last {
        last
    } else {
        number.saturating_sub(1)
    }
}

/// The links to the pages before and after this one. Each keeps every filter and sets the page.
fn pager(filters: &Filters, number: u64, total: i64, older: bool) -> Markup {
    let link = |target_page: u64| target("/admin/activity", &pager_query(filters, target_page));
    let newer = number > 1;
    html! {
        @if newer || older {
            nav.pager aria-label="Pages" {
                @if newer {
                    a.button data-kind="secondary" data-page-link="newer" href=(link(newer_page(number, total))) { "Newer" }
                }
                @if older {
                    a.button data-kind="secondary" data-page-link="older" href=(link(number.saturating_add(1))) { "Older" }
                }
            }
        }
    }
}

fn activity_page(viewer: &Viewer, filters: &Filters, number: u64, listing: &Listing) -> Response {
    let rows = &listing.rows;
    let chips = chips(filters, &listing.users, &listing.servers);
    let offset = offset_of(number);
    let end = offset.saturating_add(i64::try_from(rows.len()).unwrap_or(i64::MAX));
    let older = end < listing.total;
    let export = target("/admin/activity.csv", &query_without(filters, &[]));
    let data = MainData {
        nav: panel_nav(viewer, "/admin/activity"),
        ..MainData::default()
    };
    page_with(
        StatusCode::OK,
        "activity",
        "Activity",
        &data,
        html! {
            div.page-head {
                h1 { "Activity" }
            }
            (filter_form(filters, &listing.users, &listing.servers, chips.len()))
            div.results data-results {
                @if !rows.is_empty() {
                    p.range data-range {
                        (format!("Rows {} to {} of {}", offset.saturating_add(1), end, listing.total))
                    }
                }
                (active_filters(filters, &chips))
                a #export-csv.export href=(export) data-export { "Export all as CSV" }
            }
            @if rows.is_empty() {
                div.empty {
                    h2 { "No activity matches these filters." }
                    p { "Remove one of them above, or " a href="/admin/activity" { "clear the filters" } "." }
                }
            } @else {
                (activity_table(rows))
            }
            (pager(filters, number, listing.total, older))
        },
    )
}

#[cfg(test)]
mod tests {
    use scraper::Html;

    use super::*;

    /// The markup of a detail, and the text a reader sees in it.
    fn shown(detail: &str) -> (String, String) {
        let markup = detail_markup(detail).into_string();
        let text = Html::parse_fragment(&markup)
            .root_element()
            .text()
            .collect::<String>();
        (markup, text)
    }

    #[test]
    fn an_address_in_a_detail_is_an_email_span() {
        let (markup, text) = shown("invited bob@example.com as user");
        assert_eq!(
            markup,
            r#"invited <span class="email"><span>bob</span><wbr><span>@example<wbr>.com</span></span> as user"#
        );
        assert_eq!(text, "invited bob@example.com as user");
    }

    #[test]
    fn a_url_with_an_at_in_its_path_is_not_an_email() {
        let (markup, text) = shown("see https://example.com/a@b now");
        assert_eq!(
            markup,
            r#"see <span class="whole">https://<wbr>example<wbr>.com/<wbr>a<wbr>@b</span> now"#
        );
        assert!(!markup.contains("span class=\"email\""));
        assert_eq!(text, "see https://example.com/a@b now");
    }

    #[test]
    fn two_addresses_are_two_email_spans_with_a_space_between() {
        let (markup, text) = shown("a@example.com b@example.org");
        assert_eq!(
            markup,
            r#"<span class="email"><span>a</span><wbr><span>@example<wbr>.com</span></span> <span class="email"><span>b</span><wbr><span>@example<wbr>.org</span></span>"#
        );
        assert_eq!(text, "a@example.com b@example.org");
    }

    #[test]
    fn markup_characters_are_escaped_and_the_text_is_unchanged() {
        let (markup, text) = shown("<i>a&b</i> c@example.net");
        assert_eq!(
            markup,
            r#"<span class="whole">&lt;i&gt;a&amp;<wbr>b&lt;/<wbr>i&gt;</span> <span class="email"><span>c</span><wbr><span>@example<wbr>.net</span></span>"#
        );
        assert_eq!(text, "<i>a&b</i> c@example.net");
    }

    #[test]
    fn a_detail_with_no_space_is_one_word() {
        let (markup, text) = shown("bob@example.com");
        assert_eq!(
            markup,
            r#"<span class="email"><span>bob</span><wbr><span>@example<wbr>.com</span></span>"#
        );
        assert_eq!(text, "bob@example.com");
        let (markup, text) = shown("create_pull_request");
        assert_eq!(
            markup,
            r#"<span class="whole">create_<wbr>pull_<wbr>request</span>"#
        );
        assert_eq!(text, "create_pull_request");
    }

    #[test]
    fn markup_inside_an_address_shaped_word_is_escaped() {
        let (markup, text) = shown("onerror=1>@<b>");
        assert_eq!(
            markup,
            r#"<span class="email"><span>onerror=<wbr>1&gt;</span><wbr><span>@&lt;b&gt;</span></span>"#
        );
        assert!(
            !markup.contains("<b>"),
            "no raw tag may reach the page: {markup}"
        );
        assert_eq!(text, "onerror=1>@<b>");
    }

    #[test]
    fn a_word_is_an_address_only_with_text_on_both_sides_of_one_at() {
        for word in ["@example.com", "bob@", "a@b@example.com", "a/b@example.com"] {
            let (markup, text) = shown(word);
            assert!(
                !markup.contains("span class=\"email\""),
                "{word} must not be an address, got {markup}"
            );
            assert_eq!(text, word);
        }
    }

    #[test]
    fn a_number_joins_the_word_after_it_in_a_nowrap_span() {
        let (markup, text) = shown("assignments of github set to 6 users");
        assert_eq!(
            markup,
            r#"assignments of github set to <span class="nowrap">6 users</span>"#
        );
        assert_eq!(text, "assignments of github set to 6 users");
    }

    #[test]
    fn a_number_as_the_last_word_has_no_span() {
        let (markup, text) = shown("assignments of 6");
        assert_eq!(markup, "assignments of 6");
        assert_eq!(text, "assignments of 6");
    }

    #[test]
    fn two_numbers_in_a_row_join_once_and_the_third_word_stands_alone() {
        let (markup, text) = shown("1 2 servers");
        assert_eq!(markup, r#"<span class="nowrap">1 2</span> servers"#);
        assert_eq!(text, "1 2 servers");
    }

    #[test]
    fn a_number_before_an_address_joins_the_address() {
        let (markup, text) = shown("set 3 bob@example.com");
        assert_eq!(
            markup,
            r#"set <span class="nowrap">3 <span class="email"><span>bob</span><wbr><span>@example<wbr>.com</span></span></span>"#
        );
        assert_eq!(text, "set 3 bob@example.com");
    }

    #[test]
    fn the_word_after_a_number_still_breaks_as_an_identifier() {
        let (markup, text) = shown("set 3 create_pull_request");
        assert_eq!(
            markup,
            r#"set <span class="nowrap">3 <span class="whole">create_<wbr>pull_<wbr>request</span></span>"#
        );
        assert_eq!(text, "set 3 create_pull_request");
    }

    #[test]
    fn a_word_that_is_not_only_digits_or_an_empty_word_does_not_join() {
        for detail in ["v1 servers", "3a servers", "3  servers", "servers 3"] {
            let (markup, text) = shown(detail);
            assert!(
                !markup.contains("nowrap"),
                "{detail} must not join its words, got {markup}"
            );
            assert_eq!(text, detail);
        }
    }
}
