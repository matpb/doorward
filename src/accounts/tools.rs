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

/// A size as the page shows it: `{n} B` under 1024 bytes, else one-decimal KB with 1 KB = 1024 B.
pub fn size_text(bytes: usize) -> String {
    if bytes < 1024 {
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
        let rows = catalog::definitions(conn, server)?
            .into_iter()
            .filter_map(|(tool, definition)| {
                let on = match access.refusal(user, server, &tool) {
                    None => true,
                    Some(Refusal::SwitchedOff) => false,
                    Some(Refusal::Rule(_)) => return None,
                };
                Some(Row {
                    name: tool,
                    on,
                    bytes: definition.len(),
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

/// The `Your tools` section: one block per assigned server, with the reconnect sentence.
pub fn section(csrf: &str, blocks: &[Block]) -> Markup {
    html! {
        section #tools.part data-section="tools" aria-labelledby="tools-title" {
            div.part-head {
                h2 id="tools-title" { "Your tools" }
                p.muted { "A client picks up a change when it reconnects or refreshes its tools." }
            }
            div.part-body {
                @for block in blocks {
                    (server_tools(csrf, block))
                }
            }
        }
    }
}

/// One server's block: its tools with a switch each and the summary, or the note when it has no list.
fn server_tools(csrf: &str, block: &Block) -> Markup {
    let name_id = format!("tools-{}-title", block.slug);
    let (sent, all) = (block.sent(), block.all());
    html! {
        section.flow.narrow data-server=(block.slug) aria-labelledby=(name_id) {
            h3 id=(name_id) {
                span.block-name { (block.name) }
            }
            @if block.listed {
                form.flow method="post" action=(format!("/account/tools/{}", block.slug)) {
                    input type="hidden" name="csrf" value=(csrf);
                    table.tools {
                        thead {
                            tr {
                                th scope="col" { "Tool" }
                                th scope="col" class="c-size" { "Size" }
                            }
                        }
                        tbody {
                            @for (index, row) in block.rows.iter().enumerate() {
                                tr data-tool=(row.name) data-state=(if row.on { "on" } else { "off" }) {
                                    td.lead {
                                        (ui::check(
                                            &format!("tool-{}-{index}", block.slug),
                                            "on",
                                            Some(&row.name),
                                            row.on,
                                            html! { code { (ui::breakable(&row.name)) } },
                                            None,
                                        ))
                                    }
                                    td.half data-size { (size_text(row.bytes)) }
                                }
                            }
                        }
                    }
                    p data-sending {
                        (format!("{} of {} ({}%)", size_text(sent), size_text(all), percent(sent, all)))
                    }
                    div.form-actions {
                        button type="submit" name="set" value="chosen" data-kind="primary" { "Save" }
                        button type="submit" name="set" value="all-on" data-kind="secondary" { "All on" }
                        button type="submit" name="set" value="all-off" data-kind="secondary" { "All off" }
                    }
                }
            } @else {
                p.muted { "No tools listed yet. Connect a client to this server once." }
            }
        }
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

/// Sets the signed-in user's switches on one of their servers, then answers 303 to the section.
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
    let on: HashSet<String> = form
        .fields
        .all("on")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let now = state.clock.now().unix_timestamp();
    let (user_id, email) = (user.id, user.email.clone());
    let outcome = state
        .db
        .call(move |conn| save_in(conn, (user_id, &email), slug, set, &on, now))
        .await;
    match outcome {
        Ok(Outcome::Saved) => redirect("/account#tools"),
        Ok(Outcome::Missing) => not_found(),
        Err(err) => internal_error("tool switches", &err),
    }
}

/// One transaction: each allowed catalog tool is switched on or off as `set` says, and one activity row
/// counts the tools off. Names outside the catalog, and names the rules deny, are never written.
fn save_in(
    conn: &mut Connection,
    (user, email): (i64, &str),
    slug: String,
    set: Set,
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
    let (mut off, mut all) = (0usize, 0usize);
    for tool in catalog::names(&tx, server)? {
        if matches!(access.refusal(user, server, &tool), Some(Refusal::Rule(_))) {
            continue;
        }
        all += 1;
        let switched_off = match set {
            Set::Chosen => !on.contains(&tool),
            Set::AllOn => false,
            Set::AllOff => true,
        };
        if switched_off {
            off += 1;
            tx.execute(
                "INSERT INTO tool_switches (user_id, server_id, tool, set_at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT (user_id, server_id, tool) DO NOTHING",
                params![user, server, tool, now],
            )?;
        } else {
            tx.execute(
                "DELETE FROM tool_switches WHERE user_id = ?1 AND server_id = ?2 AND tool = ?3",
                params![user, server, tool],
            )?;
        }
    }
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
    audit::record(&tx, now, &event)?;
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
