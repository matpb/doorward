//! The per-user tool switches: the account page's `Your tools` section and the post that sets them.

use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::app::AppState;
use crate::audit::{self, Event};
use crate::db::DbError;
use crate::policy::{self, Refusal};
use crate::proxy::catalog;
use crate::servers::valid_slug;
use crate::web::{VerifiedForm, Viewer, internal_error, not_found, page, redirect, ui};

/// One allowed tool of a server: its name, whether it is on, and the byte length of its definition.
pub struct Row {
    pub name: String,
    pub on: bool,
    pub bytes: usize,
}

/// One assigned server's block in `Your tools`. `listed` is false while the server has no stored list.
pub struct Block {
    pub slug: String,
    pub name: String,
    pub listed: bool,
    pub rows: Vec<Row>,
}

impl Block {
    /// The bytes of the tools left on: what a client is sent.
    pub fn sent(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.on)
            .map(|row| row.bytes)
            .sum()
    }

    /// The bytes of every tool the user may use.
    pub fn all(&self) -> usize {
        self.rows.iter().map(|row| row.bytes).sum()
    }
}

/// The stored tools of the server in catalog order, each with the byte length of its definition.
fn sizes(conn: &Connection, server: i64) -> rusqlite::Result<Vec<(String, usize)>> {
    let mut statement = conn.prepare(
        "SELECT name, length(CAST(definition AS BLOB)) FROM tool_catalog WHERE server_id = ?1 \
         ORDER BY position",
    )?;
    let rows = statement.query_map(params![server], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    rows.map(|row| row.map(|(name, bytes)| (name, usize::try_from(bytes).unwrap_or(usize::MAX))))
        .collect()
}

/// A size as the page shows it: `{n} B` under 1000 bytes, else one-decimal KB with 1 KB = 1024 B.
pub fn size_text(bytes: usize) -> String {
    if bytes < 1000 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

/// The share `on` is of `all`, rounded to the nearest whole number with halves up; 100 when `all` is 0.
pub fn percent(on: usize, all: usize) -> usize {
    if all == 0 {
        100
    } else {
        (200 * on + all) / (2 * all)
    }
}

/// The blocks of the servers the viewer is assigned to; none for a viewer who is not signed in.
pub async fn blocks_for(state: &AppState, viewer: &Viewer) -> Result<Vec<Block>, DbError> {
    let Some(user) = viewer.user.as_ref() else {
        return Ok(Vec::new());
    };
    let id = user.id;
    state.db.call(move |conn| blocks_in(conn, id)).await
}

/// Each server the user is assigned to, by slug, with the rows of its allowed tools in catalog order.
fn blocks_in(conn: &Connection, user: i64) -> rusqlite::Result<Vec<Block>> {
    let mut statement = conn.prepare(
        "SELECT s.id, s.slug, s.name, s.catalog_at IS NOT NULL FROM user_servers us \
         JOIN servers s ON s.id = us.server_id WHERE us.user_id = ?1 ORDER BY s.slug",
    )?;
    let servers: Vec<(i64, String, String, bool)> = statement
        .query_map(params![user], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut blocks = Vec::with_capacity(servers.len());
    for (server, slug, name, listed) in servers {
        let access = policy::access(conn, user, server)?;
        let rows = sizes(conn, server)?
            .into_iter()
            .filter_map(|(tool, bytes)| {
                let on = match access.refusal(user, server, &tool) {
                    None => true,
                    Some(Refusal::SwitchedOff) => false,
                    Some(Refusal::Rule(_)) => return None,
                };
                Some(Row {
                    name: tool,
                    on,
                    bytes,
                })
            })
            .collect();
        blocks.push(Block {
            slug,
            name,
            listed,
            rows,
        });
    }
    Ok(blocks)
}

/// The server a `saved` query names: its first value, as the account page reads it.
pub fn saved_query(raw: Option<&str>) -> Option<String> {
    form_urlencoded::parse(raw.unwrap_or("").as_bytes())
        .find(|(key, _)| key == "saved")
        .map(|(_, value)| value.into_owned())
}

/// The `Your tools` section: the reconnect sentence, then one block per assigned server. `saved` is the
/// server a save has just reported: its block holds the notice and its list is open.
pub fn section(csrf: &str, blocks: &[Block], saved: Option<&str>) -> Markup {
    html! {
        section #tools.part data-section="tools" aria-labelledby="tools-title" {
            div.part-head {
                h2 id="tools-title" { "Your tools" }
                p { "Switch off the tools you do not use. A tool that is off is left out of your client's tool list and takes no room in the model's context." }
                p.muted { "A client picks up a change when it reconnects or refreshes its tools." }
            }
            div.part-body {
                @for block in blocks {
                    (server_tools(csrf, block, saved == Some(block.slug.as_str())))
                }
            }
        }
    }
}

/// One server's block: the heading with its count, the sentence and rule, then the list in a disclosure.
/// A server with no stored list shows its note instead. A mixed list's foot asks before All on or All off.
fn server_tools(csrf: &str, block: &Block, saved: bool) -> Markup {
    let title = format!("tools-{}-title", block.slug);
    let (sent, all) = (block.sent(), block.all());
    let total = block.rows.len();
    let on = block.rows.iter().filter(|row| row.on).count();
    let mixed = on > 0 && on < total;
    let largest = block.rows.iter().map(|row| row.bytes).max().unwrap_or(0);
    html! {
        section.flow.narrow data-server=(block.slug) aria-labelledby=(title) {
            @if saved {
                (ui::notice("ok", html! { p { (saved_text(&block.name, on, total)) } }))
            }
            h3 id=(title) {
                span.block-name { (block.name) }
                @if block.listed {
                    " "
                    span.count { (format!("{on} of {} on", block.rows.len())) }
                }
            }
            @if block.listed {
                p.sending {
                    "Sending "
                    strong data-sending { (format!("{} of {} ({}%)", size_text(sent), size_text(all), percent(sent, all))) }
                }
                svg.sending-bar width="100%" height="4" aria-hidden="true" {
                    rect width=(sent_share(sent, all)) height="4" {}
                }
                details.toolbox open[saved] {
                    summary {
                        span.toolbox-open { "Choose tools" span.chevron aria-hidden="true" {} }
                    }
                    form.tools-form method="post" action=(format!("/account/tools/{}", block.slug)) {
                        input type="hidden" name="csrf" value=(csrf);
                        @for row in &block.rows {
                            input type="hidden" name="shown" value=(row.name);
                        }
                        div.tool-cols aria-hidden="true" { span { "On" } span { "Tool" } span { "Size" } }
                        ul.tool-list aria-labelledby=(title) {
                            @for (index, row) in block.rows.iter().enumerate() {
                                (tool_row(&block.slug, index + 1, row, largest))
                            }
                        }
                        div.tools-foot data-bulk=[mixed.then_some("ask")] {
                            button type="submit" name="set" value="chosen" data-kind="secondary" { "Save" }
                            span.tools-unsaved hidden[true] { "Not saved yet:" }
                            div.row-actions {
                                @if mixed {
                                    @for (value, label, word, all_off) in [("all-on", "All on", "on", false), ("all-off", "All off", "off", true)] {
                                        details.confirm.row-confirm name=(format!("tools-{}-all", block.slug)) data-confirm {
                                            summary { (label) }
                                            div.confirm-body {
                                                p { "Switches all " (total) " tools " (word) ". " span.whole { (choices(on, total - on, all_off)) } }
                                                button type="submit" name="set" value=(value) data-kind="secondary" { (label) }
                                            }
                                        }
                                    }
                                } @else {
                                    button.row-action type="submit" name="set" value="all-on" data-kind="secondary" { "All on" }
                                    button.row-action type="submit" name="set" value="all-off" data-kind="secondary" { "All off" }
                                }
                            }
                        }
                    }
                }
            } @else {
                p.muted { "No tools listed yet. Connect a client to this server once." }
            }
        }
    }
}

/// The notice after a save: all off or all on when the state it left says so, else the plain line.
fn saved_text(name: &str, on: usize, total: usize) -> String {
    if total > 0 && on == 0 {
        format!("All {total} {name} tools are off.")
    } else if total > 0 && on == total {
        format!("All {total} {name} tools are on.")
    } else {
        format!("Tools saved for {name}.")
    }
}

/// The second sentence of a question: the count of the tools its word moves, singular for one.
fn choices(on: usize, off: usize, all_off: bool) -> String {
    if all_off {
        if on == 1 {
            "The 1 you have on goes off.".to_owned()
        } else {
            format!("The {on} you have on go off.")
        }
    } else if off == 1 {
        "The 1 you switched off comes back on.".to_owned()
    } else {
        format!("The {off} you switched off come back on.")
    }
}

/// One tool's row: its box, name, size and bar, as siblings in that order. `n` is its place in the list.
fn tool_row(slug: &str, n: usize, row: &Row, largest: usize) -> Markup {
    let id = format!("tool-{slug}-{n}");
    let size_id = format!("{id}-size");
    html! {
        li.tool data-tool=(row.name) data-state=(if row.on { "on" } else { "off" }) {
            input type="checkbox" name="on" value=(row.name) id=(id) checked[row.on] aria-describedby=(size_id);
            label for=(id) { code { (ui::breakable_tool(&row.name)) } }
            span.tool-size id=(size_id) data-size { (size_text(row.bytes)) }
            svg.tool-bar width="100%" height="2" aria-hidden="true" {
                @if let Some(share) = tool_share(row.bytes, largest) {
                    rect width=(share) height="2" {}
                }
            }
        }
    }
}

/// The width of a tool's bar: its bytes over the largest tool's, in per cent to three decimals. A tool under
/// 2 per cent draws no bar, and no tool has a bar when none has bytes.
fn tool_share(bytes: usize, largest: usize) -> Option<String> {
    if largest == 0 {
        return None;
    }
    let share = bytes as f64 * 100.0 / largest as f64;
    (share >= 2.0).then(|| format!("{share:.3}%"))
}

/// The width of the server's rule: the bytes on over all bytes, in per cent to three decimals; zero is `0%`.
fn sent_share(on: usize, all: usize) -> String {
    if on == 0 || all == 0 {
        "0%".to_owned()
    } else {
        format!("{:.3}%", on as f64 * 100.0 / all as f64)
    }
}

/// What the `set` of a post asks for.
#[derive(Clone, Copy)]
enum Set {
    Chosen,
    AllOn,
    AllOff,
}

impl Set {
    fn parse(text: &str) -> Option<Set> {
        match text {
            "chosen" => Some(Set::Chosen),
            "all-on" => Some(Set::AllOn),
            "all-off" => Some(Set::AllOff),
            _ => None,
        }
    }
}

/// What a post did.
enum Outcome {
    Saved,
    Missing,
}

/// Sets the signed-in user's switches on one of their servers, then answers 303 to the account page that reports it.
pub async fn post_tools(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    form: VerifiedForm,
) -> Response {
    let Some(user) = form.viewer.user.clone() else {
        return redirect("/login");
    };
    let Some(set) = Set::parse(form.fields.get("set")) else {
        return not_valid();
    };
    if !valid_slug(&slug) {
        return not_found();
    }
    let location = format!("/account?saved={slug}#tools");
    let on: HashSet<String> = form
        .fields
        .all("on")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let shown: HashSet<String> = form
        .fields
        .all("shown")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let now = state.clock.now().unix_timestamp();
    let (user_id, email) = (user.id, user.email.clone());
    let outcome = state
        .db
        .call(move |conn| save_in(conn, (user_id, &email), slug, set, &shown, &on, now))
        .await;
    match outcome {
        Ok(Outcome::Saved) => redirect(&location),
        Ok(Outcome::Missing) => not_found(),
        Err(err) => internal_error("tool switches", &err),
    }
}

/// The most switches kept for tools the catalog no longer lists, per user and server; the newest are kept.
const UNLISTED_KEPT: usize = 1000;

/// Deletes the pair's switches of tools the catalog no longer lists, but the UNLISTED_KEPT newest of them.
const PRUNE: &str = "DELETE FROM tool_switches WHERE user_id = ?1 AND server_id = ?2 \
     AND tool NOT IN (SELECT name FROM tool_catalog WHERE server_id = ?2) \
     AND tool NOT IN (SELECT tool FROM tool_switches WHERE user_id = ?1 AND server_id = ?2 \
     AND tool NOT IN (SELECT name FROM tool_catalog WHERE server_id = ?2) \
     ORDER BY set_at DESC, tool LIMIT ?3)";

/// One transaction: `chosen` changes the allowed tools `shown` names, `all-off` every allowed tool, and
/// `all-on` every row of the pair. Names outside the catalog or denied by a rule are never written.
fn save_in(
    conn: &mut Connection,
    (user, email): (i64, &str),
    slug: String,
    set: Set,
    shown: &HashSet<String>,
    on: &HashSet<String>,
    now: i64,
) -> rusqlite::Result<Outcome> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let server: Option<i64> = tx
        .query_row(
            "SELECT s.id FROM servers s JOIN user_servers us ON us.server_id = s.id \
             WHERE s.slug = ?1 AND us.user_id = ?2",
            params![slug, user],
            |row| row.get(0),
        )
        .optional()?;
    let Some(server) = server else {
        return Ok(Outcome::Missing);
    };
    let access = policy::access(&tx, user, server)?;
    let mut changed = 0usize;
    if matches!(set, Set::AllOn) {
        changed += tx.execute(
            "DELETE FROM tool_switches WHERE user_id = ?1 AND server_id = ?2",
            params![user, server],
        )?;
    }
    let (mut off, mut all) = (0usize, 0usize);
    for tool in catalog::names(&tx, server)? {
        if matches!(access.refusal(user, server, &tool), Some(Refusal::Rule(_))) {
            continue;
        }
        all += 1;
        let switched_off = match set {
            Set::Chosen if shown.contains(&tool) => !on.contains(&tool),
            Set::Chosen => {
                off += usize::from(access.off.contains(&tool));
                continue;
            }
            Set::AllOn => false,
            Set::AllOff => true,
        };
        if switched_off {
            off += 1;
            changed += tx
                .prepare_cached(
                    "INSERT INTO tool_switches (user_id, server_id, tool, set_at) VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (user_id, server_id, tool) DO NOTHING",
                )?
                .execute(params![user, server, tool, now])?;
        } else if !matches!(set, Set::AllOn) {
            changed += tx
                .prepare_cached(
                    "DELETE FROM tool_switches WHERE user_id = ?1 AND server_id = ?2 AND tool = ?3",
                )?
                .execute(params![user, server, tool])?;
        }
    }
    changed += tx
        .prepare_cached(PRUNE)?
        .execute(params![user, server, UNLISTED_KEPT as i64])?;
    if changed > 0 {
        let detail = format!("{off} of {all} off");
        let event = Event {
            kind: "tool_switches",
            user_id: Some(user),
            user_email: email,
            server_id: Some(server),
            server_slug: &slug,
            detail: &detail,
            ..Default::default()
        };
        audit::record_switches(&tx, now, &event)?;
    }
    tx.commit()?;
    Ok(Outcome::Saved)
}

/// The 400 page of a post whose `set` is not one of the three answers.
fn not_valid() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "error",
        "Request not valid",
        html! {
            h1 { "This request is not valid" }
            p.lede { "Go back to your account, reload the page and send the form again." }
            p.back { a href="/account" { "Go to your account" } }
        },
    )
}
