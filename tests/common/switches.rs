//! Reads and posts of the per-user tool switches of statements 99 to 105.

use rusqlite::params;

use super::admin;
use super::client::{Page, TestClient};
use super::values::{account_csrf, live_db};
use super::world::World;

/// One tool row of a server block in `Your tools`, in the order the page lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRow {
    pub name: String,
    pub state: String,
    pub checked: bool,
    pub size: String,
}

fn id_of(text: &str) -> i64 {
    text.parse()
        .unwrap_or_else(|_| panic!("{text} is not a numeric id"))
}

/// Every row of tool_switches as (user id, server id, tool); panics when the table cannot be read.
pub fn stored_rows(w: &World) -> Vec<(i64, i64, String)> {
    let conn = live_db(w);
    let mut statement = conn
        .prepare(
            "SELECT user_id, server_id, tool FROM tool_switches ORDER BY user_id, server_id, tool",
        )
        .expect("tool_switches must exist and be readable");
    statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("tool_switches must be readable")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("tool_switches rows must be readable")
}

/// The tools the user switched off on the server, by name, read from tool_switches.
pub fn switched_off(w: &World, user_id: &str, server_id: &str) -> Vec<String> {
    let (user, server) = (id_of(user_id), id_of(server_id));
    stored_rows(w)
        .into_iter()
        .filter(|(row_user, row_server, _)| *row_user == user && *row_server == server)
        .map(|(_, _, tool)| tool)
        .collect()
}

/// The stored catalog of the server in catalog order, as (name, definition) read from tool_catalog.
pub fn stored_definitions(w: &World, server_id: &str) -> Vec<(String, String)> {
    let conn = live_db(w);
    let mut statement = conn
        .prepare("SELECT name, definition FROM tool_catalog WHERE server_id = ?1 ORDER BY position")
        .expect("tool_catalog must be readable");
    statement
        .query_map(params![id_of(server_id)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("tool_catalog must be readable")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("tool_catalog rows must be readable")
}

/// A size as the page shows it: `{n} B` below 1024 bytes, else one-decimal KB with 1 KB = 1024 B.
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

/// Posts the switch form of `slug` as the browser, with its csrf token, `set` and the `on` names.
pub async fn post_switches(browser: &TestClient, slug: &str, set: &str, on: &[&str]) -> Page {
    let csrf = account_csrf(browser).await;
    let mut fields = vec![("csrf", csrf.as_str()), ("set", set)];
    fields.extend(on.iter().map(|name| ("on", *name)));
    browser
        .post(&format!("/account/tools/{slug}"), &fields)
        .await
}

/// The rows of the server's block in `Your tools`, read from the browser's account page.
pub async fn tool_rows(browser: &TestClient, slug: &str) -> Vec<ToolRow> {
    let page = browser.get("/account").await;
    let rows = format!(r#"section#tools [data-server="{slug}"] [data-tool]"#);
    let names = page.attrs(&rows, "data-tool");
    let states = page.attrs(&rows, "data-state");
    let sizes = page.texts(&format!(
        r#"section#tools [data-server="{slug}"] [data-size]"#
    ));
    let checked = page.attrs(
        &format!(r#"section#tools [data-server="{slug}"] input[name="on"][checked]"#),
        "value",
    );
    names
        .into_iter()
        .enumerate()
        .map(|(index, name)| ToolRow {
            checked: checked.contains(&name),
            state: states.get(index).cloned().unwrap_or_default(),
            size: sizes.get(index).cloned().unwrap_or_default(),
            name,
        })
        .collect()
}

/// Adds a deny rule for `tool` on `server_id` for `subject` (a user id or `everyone`); returns its id.
pub async fn deny_tool(w: &World, subject: &str, server_id: &str, tool: &str) -> String {
    let before = admin::rule_ids(&w.owner).await;
    let page = admin::add_rule(
        &w.owner,
        subject,
        "deny",
        "tool",
        Some(server_id),
        Some(tool),
    )
    .await;
    assert_eq!(
        page.status, 303,
        "the deny rule for {tool} must be accepted"
    );
    admin::rule_ids(&w.owner)
        .await
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the new rule must be listed")
}
