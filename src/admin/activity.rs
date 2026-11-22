//! The activity page: the rows that match the user and server filters, one page at a time, and the
//! newest rows the overview shows.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use form_urlencoded::Serializer;
use maud::{Markup, html};
use rusqlite::{Connection, params};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description;
use time::format_description::well_known::Rfc3339;

use crate::app::AppState;
use crate::db::{Db, DbError};
use crate::web::ui::{breakable, email, time_cell};
use crate::web::{MainData, Viewer, internal_error, page_with};

use super::panel_nav;

/// Rows on one page of the activity page.
const PAGE_SIZE: i64 = 50;
/// The day, month, year and UTC time of a row, as the page reads them.
const PLAIN_TIME: &str =
    "[day padding:none] [month repr:short] [year] [hour repr:24]:[minute]:[second] UTC";

#[derive(Deserialize)]
pub struct ActivityQuery {
    user: Option<String>,
    server: Option<String>,
    page: Option<String>,
}

/// A filter from the query: absent or empty, an id, or a value that matches no row.
#[derive(Clone, Copy)]
enum Filter {
    Any,
    Id(i64),
    Nothing,
}

impl Filter {
    fn of(text: Option<&str>) -> Filter {
        match text {
            None | Some("") => Filter::Any,
            Some(text) => text.parse::<i64>().map_or(Filter::Nothing, Filter::Id),
        }
    }

    fn id(self) -> Option<i64> {
        match self {
            Filter::Id(id) => Some(id),
            Filter::Any | Filter::Nothing => None,
        }
    }
}

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

pub async fn get_activity(
    viewer: Viewer,
    State(state): State<AppState>,
    Query(query): Query<ActivityQuery>,
) -> Response {
    let user = Filter::of(query.user.as_deref());
    let server = Filter::of(query.server.as_deref());
    let number = page_number(query.page.as_deref());
    let offset = offset_of(number);
    let listing = state
        .db
        .call(move |conn| {
            let (rows, total) = match (user, server) {
                (Filter::Nothing, _) | (_, Filter::Nothing) => (Vec::new(), 0),
                (user, server) => (
                    rows_in(conn, user.id(), server.id(), PAGE_SIZE, offset)?,
                    count_in(conn, user.id(), server.id())?,
                ),
            };
            Ok(Listing {
                rows,
                total,
                users: users_in(conn)?,
                servers: servers_in(conn)?,
            })
        })
        .await;
    match listing {
        Ok(listing) => activity_page(&viewer, &query, number, &listing),
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

/// The rows that match the filters, newest first, from `offset`, at most `limit` of them.
fn rows_in(
    conn: &Connection,
    user: Option<i64>,
    server: Option<i64>,
    limit: i64,
    offset: i64,
) -> rusqlite::Result<Vec<Row>> {
    let mut statement = conn.prepare(
        "SELECT at, kind, user_email, server_slug, tool, decision, outcome, detail, duration_ms \
         FROM activity WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR server_id = ?2) \
         ORDER BY at DESC, id DESC LIMIT ?3 OFFSET ?4",
    )?;
    let rows = statement.query_map(params![user, server, limit, offset], |row| {
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

/// How many rows match the filters, in all.
fn count_in(conn: &Connection, user: Option<i64>, server: Option<i64>) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM activity \
         WHERE (?1 IS NULL OR user_id = ?1) AND (?2 IS NULL OR server_id = ?2)",
        params![user, server],
        |row| row.get(0),
    )
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

/// The filter form. Each select marks the option of the current filter as selected.
fn filter_form(
    user: Filter,
    server: Filter,
    users: &[UserOption],
    servers: &[ServerOption],
) -> Markup {
    html! {
        form.filters method="get" action="/admin/activity" data-form="activity-filter" {
            label for="filter-user" { "User" }
            select id="filter-user" name="user" {
                option value="" { "Any user" }
                @for choice in users {
                    option value=(choice.id) selected[user.id() == Some(choice.id)] {
                        (choice.email)
                    }
                }
            }
            label for="filter-server" { "Server" }
            select id="filter-server" name="server" {
                option value="" { "Any server" }
                @for choice in servers {
                    option value=(choice.id) selected[server.id() == Some(choice.id)] {
                        (choice.name) " (" (choice.slug) ")"
                    }
                }
            }
            button type="submit" data-kind="secondary" { "Filter" }
        }
    }
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
        .map_or_else(String::new, |ms| format!("{ms} ms"));
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
        .call(move |conn| rows_in(conn, None, None, limit, 0))
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

/// The links to the pages before and after this one. Each keeps the filters as the filter form
/// submits them, with the page number.
fn pager(query: &ActivityQuery, number: u64, total: i64, older: bool) -> Markup {
    let user = query.user.as_deref().unwrap_or("");
    let server = query.server.as_deref().unwrap_or("");
    let link = |target: u64| {
        let query = Serializer::new(String::new())
            .append_pair("user", user)
            .append_pair("server", server)
            .append_pair("page", &target.to_string())
            .finish();
        format!("/admin/activity?{query}")
    };
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

fn activity_page(
    viewer: &Viewer,
    query: &ActivityQuery,
    number: u64,
    listing: &Listing,
) -> Response {
    let user = Filter::of(query.user.as_deref());
    let server = Filter::of(query.server.as_deref());
    let rows = &listing.rows;
    let offset = offset_of(number);
    let end = offset.saturating_add(i64::try_from(rows.len()).unwrap_or(i64::MAX));
    let older = end < listing.total;
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
            div.toolbar {
                (filter_form(user, server, &listing.users, &listing.servers))
                @if !rows.is_empty() {
                    p.range data-range {
                        (format!("Rows {} to {} of {}", offset.saturating_add(1), end, listing.total))
                    }
                }
            }
            @if rows.is_empty() {
                p.muted { "No activity matches." }
            } @else {
                (activity_table(rows))
            }
            (pager(query, number, listing.total, older))
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
