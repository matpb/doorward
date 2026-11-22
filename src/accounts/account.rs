use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use super::values::{self, Part, ServerView, ValueState};
use crate::app::AppState;
use crate::oauth::connected::{self, Connected};
use crate::web::ui::{self, Note};
use crate::web::{MainData, Nav, Viewer, form_page_with, internal_error, redirect};

pub async fn get_account(
    State(state): State<AppState>,
    viewer: Viewer,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    let clients = match connected::list(&state.db, user.id, now).await {
        Ok(clients) => clients,
        Err(err) => return internal_error("connected clients", &err),
    };
    match values::part_for(&state, &viewer).await {
        Ok(mut part) => {
            part.saved = values::saved_slug(&part, raw.as_deref());
            account_page_with(&viewer, StatusCode::OK, None, &clients, &part)
        }
        Err(err) => internal_error("stored values", &err),
    }
}

/// The account page with the connected `clients`, the credentials `part`, and an error line when
/// `error` is given. Anonymous viewers go to sign-in.
pub fn account_page_with(
    viewer: &Viewer,
    status: StatusCode,
    error: Option<&str>,
    clients: &[Connected],
    part: &Part,
) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let nav = if viewer.is_admin() {
        Nav::Panel {
            current: "/account",
            owner: viewer.is_owner(),
        }
    } else {
        Nav::Account
    };
    let data = MainData {
        nav,
        ..MainData::default()
    };
    form_page_with(viewer, status, "account", "Your account", &data, |csrf| {
        account_body_with(csrf, &user.email, error, clients, part)
    })
}

#[cfg(test)]
fn account_body(csrf: &str, email: &str, error: Option<&str>, clients: &[Connected]) -> Markup {
    account_body_with(csrf, email, error, clients, &Part::default())
}

fn account_body_with(
    csrf: &str,
    email: &str,
    error: Option<&str>,
    clients: &[Connected],
    part: &Part,
) -> Markup {
    let new_note = Note::Hint("12 to 256 characters.");
    let new_described = new_note.describer("new_password");
    html! {
        div.page-head {
            h1 { "Your account" }
            p.lede { "Signed in as " (ui::email(email)) }
            div.head-actions {
                form method="post" action="/logout" {
                    input type="hidden" name="csrf" value=(csrf);
                    button type="submit" data-kind="secondary" { "Sign out" }
                }
            }
        }
        section.block aria-labelledby="clients-title" {
            div.block-head {
                h2 id="clients-title" { "Connected clients" }
            }
            @if clients.is_empty() {
                p.muted { "No client is connected to your account." }
            } @else {
                table.list.clients {
                    thead {
                        tr {
                            th scope="col" { "Client" }
                            th scope="col" class="c-server" { "Server" }
                            th scope="col" class="c-act" aria-label="Actions" {}
                        }
                    }
                    tbody {
                        @for row in clients {
                            tr data-family=(row.public_id) data-client-name=(row.client_name) data-server=(row.server) {
                                td.lead.strong { (row.client_name) }
                                td.half {
                                    "on "
                                    @if row.server == connected::ALL_SERVERS {
                                        (row.server)
                                    } @else {
                                        span.whole { code { (row.server) } }
                                    }
                                }
                                td.act {
                                    form method="post" action=(format!("/account/clients/{}/disconnect", row.public_id)) {
                                        input type="hidden" name="csrf" value=(csrf);
                                        button.row-action type="submit" data-kind="danger" { "Disconnect" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        @if !part.servers.is_empty() || !part.retired.is_empty() {
            (credentials_part(csrf, email, part))
        }
        section.part aria-labelledby="password-title" {
            div.part-head {
                h2 id="password-title" { "Change password" }
                p { "Enter the current password, then the new one." }
            }
            div.part-body {
                form.flow method="post" action="/account/password" {
                    input type="hidden" name="csrf" value=(csrf);
                    @if let Some(message) = error {
                        (ui::refused(Some("The password was not changed."), message, None))
                    }
                    div.fields data-cols="2" {
                        (ui::field(
                            "current_password",
                            "Current password",
                            false,
                            html! { input id="current_password" name="current_password" type="password" autocomplete="current-password" required; },
                            Note::None,
                        ))
                        (ui::field(
                            "new_password",
                            "New password",
                            false,
                            html! {
                                input id="new_password" name="new_password" type="password" autocomplete="new-password" required
                                    aria-describedby=[new_described.as_deref()];
                            },
                            new_note,
                        ))
                    }
                    div.form-actions {
                        button type="submit" data-kind="secondary" { "Change password" }
                    }
                }
            }
        }
    }
}

/// The credentials part: one block per server, each with its state; a form when the session opens the key.
fn credentials_part(csrf: &str, email: &str, part: &Part) -> Markup {
    html! {
        section.part aria-labelledby="values-title" {
            div.part-head {
                h2 id="values-title" { "Your credentials" }
                p { "What a server needs from you, such as an API token." }
                p.muted data-values-reset-note { "If you reset a forgotten password, these credentials are deleted and you enter them again." }
            }
            @if part.locked {
                div.part-body.flow data-values-locked {
                    div.locked-list {
                        @for server in &part.servers {
                            (server_name(server))
                        }
                    }
                    @for (slug, name) in &part.retired {
                        (retired_values(csrf, slug, name))
                    }
                    p { (values::LOCKED_PART) }
                    form.form-actions method="post" action="/logout" {
                        input type="hidden" name="csrf" value=(csrf);
                        button type="submit" data-kind="secondary" { "Sign out and sign in again" }
                    }
                }
            } @else if !part.servers.is_empty() || !part.retired.is_empty() {
                div.part-body {
                    @for server in &part.servers {
                        (server_values(csrf, email, server, part))
                    }
                    @for (slug, name) in &part.retired {
                        (retired_values(csrf, slug, name))
                    }
                }
            }
        }
    }
}

/// A server that no longer uses stored credentials while the user still holds some: its head as the other
/// blocks have it, and a closed disclosure whose one button deletes them.
fn retired_values(csrf: &str, slug: &str, name: &str) -> Markup {
    let name_id = format!("values-{slug}-title");
    html! {
        section.flow.narrow data-values-server=(slug) data-values-retired=(slug) data-needs-values="no" aria-labelledby=(name_id) {
            h3 id=(name_id) {
                span.block-name { (name) }
                " "
                (ui::pill("muted", "No longer uses stored credentials"))
            }
            p.muted { "Your credentials for this server are still stored but are no longer sent." }
            details.confirm data-confirm {
                summary {
                    span.confirm-open { "Delete my stored credentials " span.chevron aria-hidden="true" {} }
                    " "
                    span.confirm-note { "This cannot be undone." }
                }
                div.confirm-body {
                    form method="post" action=(format!("/account/values/{slug}")) {
                        input type="hidden" name="csrf" value=(csrf);
                        input type="hidden" name="forget" value="1";
                        div.form-actions {
                            button type="submit" data-kind="danger" { "Delete my stored credentials" }
                        }
                    }
                    p.muted { "This cannot be undone." }
                }
            }
        }
    }
}

/// The notice of a save, first in the block of the server it reports on: how many required credentials
/// of that server are still missing.
fn saved_notice(server: &ServerView) -> Markup {
    let missing = server.missing();
    ui::notice(
        "ok",
        html! {
            p { "Credentials saved for " (server.name) "." }
            @if missing == 1 {
                p.attention { "1 required credential is still missing." }
            } @else if missing > 1 {
                p.attention { (missing) " required credentials are still missing." }
            }
        },
    )
}

/// A server's name as the block's heading, with its state after it.
fn server_name(server: &ServerView) -> Markup {
    let needs = if server.needs_values() { "yes" } else { "no" };
    let name_id = format!("values-{}-title", server.slug);
    html! {
        section data-values-server=(server.slug) data-needs-values=(needs) aria-labelledby=(name_id) {
            h3 id=(name_id) {
                span.block-name { (server.name) }
                (state_pill(server.state()))
            }
        }
    }
}

/// The state of a block, as the word with its mark.
fn state_pill(state: ValueState) -> Markup {
    match state {
        ValueState::Needed => ui::pill("warn", "Needs your credentials"),
        ValueState::Stored => ui::pill("ok", "Credentials stored"),
        ValueState::Nothing => ui::pill("muted", "Nothing stored"),
    }
}

/// One server's block with its credentials form. The refusal of a post shows in the form.
fn server_values(csrf: &str, email: &str, server: &ServerView, part: &Part) -> Markup {
    let needs = if server.needs_values() { "yes" } else { "no" };
    let name_id = format!("values-{}-title", server.slug);
    let refusal = part
        .refusal
        .as_ref()
        .filter(|refusal| refusal.slug == server.slug);
    let saved = part.saved.as_deref() == Some(server.slug.as_str());
    let stored = server.headers.iter().any(|header| header.set_at.is_some());
    let save_kind = if server.needs_values() {
        "primary"
    } else {
        "secondary"
    };
    html! {
        section.flow.narrow data-values-server=(server.slug) data-needs-values=(needs) aria-labelledby=(name_id) {
            @if saved {
                (saved_notice(server))
            }
            h3 id=(name_id) {
                span.block-name { (server.name) }
                " "
                (state_pill(server.state()))
            }
            p {
                "Sent to "
                span.whole { (ui::address(&server.host)) }
                " with your calls, as "
                span.whole { (ui::email(email)) "." }
            }
            @if server.plain_http {
                (ui::notice("warning", html! {
                    p { "This server is reached over plain http. Your credentials travel unencrypted." }
                }))
            }
            form.flow method="post" action=(format!("/account/values/{}", server.slug)) {
                input type="hidden" name="csrf" value=(csrf);
                @if let Some(refusal) = refusal {
                    (ui::refused(Some("The credentials were not saved."), refusal.message, None))
                }
                @for header in &server.headers {
                    div.fields data-cols="2" {
                        (header_field(header))
                    }
                }
                @if stored {
                    p.muted { "A stored credential is never shown again. Leave a field empty to keep it." }
                }
                div.form-actions {
                    button type="submit" data-kind=(save_kind) { "Save credentials" }
                }
            }
        }
    }
}

/// One declared header: a write-only field, its state under it, and the remove box when stored.
fn header_field(header: &values::HeaderView) -> Markup {
    let id = format!("value-{}", header.id);
    let hint_id = format!("{id}-hint");
    let remove_id = format!("remove-{}", header.id);
    let remove_name = format!("remove_{}", header.id);
    let value_name = format!("value_{}", header.id);
    let state = if header.set_at.is_some() {
        "set"
    } else {
        "unset"
    };
    html! {
        div.field {
            label for=(id) { code { (ui::breakable(&header.name)) } }
            input id=(id) name=(value_name) type="password" autocomplete="new-password"
                data-1p-ignore data-lpignore="true"
                placeholder=[header.set_at.map(|_| "Stored. Type to replace.")]
                aria-describedby=(hint_id);
            div.below {
                p.hint id=(hint_id) data-value-state=(state) data-header=(header.lower) {
                    @if let Some(at) = header.set_at {
                        span.state data-pill data-tone="ok" {
                            "Stored "
                            time datetime=(values::iso_day(at)) { (values::day(at)) }
                        }
                    } @else if header.required {
                        (ui::pill("warn", "Not set. Required."))
                    } @else {
                        (ui::pill("muted", "Not set."))
                    }
                }
                @if header.set_at.is_some() {
                    (ui::check(
                        &remove_id,
                        &remove_name,
                        Some("1"),
                        false,
                        "Remove the stored credential",
                        None,
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use scraper::{Html, Selector};

    use super::*;

    /// The account body as a fragment, with `clients` connected.
    fn body(clients: &[Connected]) -> Html {
        let markup = account_body("token", "bob@example.com", None, clients);
        Html::parse_fragment(&markup.into_string())
    }

    /// How many elements of `doc` match `css`.
    fn count(doc: &Html, css: &str) -> usize {
        doc.select(&Selector::parse(css).expect("selector")).count()
    }

    /// The collapsed text of the first element of `doc` that matches `css`.
    fn text(doc: &Html, css: &str) -> String {
        let selector = Selector::parse(css).expect("selector");
        let element = doc
            .select(&selector)
            .next()
            .unwrap_or_else(|| panic!("{css} must be on the page"));
        element
            .text()
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_page_is_a_head_with_the_address_then_two_parts() {
        let doc = body(&[]);
        assert_eq!(count(&doc, "div.page-head > h1"), 1);
        assert_eq!(text(&doc, "div.page-head > h1"), "Your account");
        assert_eq!(text(&doc, "p.lede"), "Signed in as bob@example.com");
        assert_eq!(count(&doc, "p.lede span.email"), 1);
        assert_eq!(count(&doc, "section.block"), 1);
        assert_eq!(count(&doc, "section.part"), 1);
        assert_eq!(
            text(&doc, "section.block p.muted"),
            "No client is connected to your account."
        );
    }

    #[test]
    fn sign_out_sits_on_the_title_row() {
        let doc = body(&[]);
        assert_eq!(
            text(
                &doc,
                r#"div.page-head > div.head-actions > form[action="/logout"] > button[data-kind="secondary"]"#
            ),
            "Sign out"
        );
    }

    #[test]
    fn the_panel_link_is_in_the_header_not_the_body() {
        let doc = body(&[]);
        assert_eq!(count(&doc, r#"a[data-nav="to-panel"]"#), 0);
        assert_eq!(count(&doc, "div.page-head a"), 0);
    }

    #[test]
    fn the_server_of_a_connected_app_sits_in_a_whole_span_as_code() {
        let clients = [Connected {
            public_id: "pub-1".to_owned(),
            client_name: "Claude Code".to_owned(),
            server: "demo".to_owned(),
        }];
        let doc = body(&clients);
        assert_eq!(count(&doc, "tr > td.half > span.whole > code"), 1);
        assert_eq!(text(&doc, "tr > td.half > span.whole > code"), "demo");
    }

    #[test]
    fn a_connected_client_is_a_row_with_its_details_and_a_danger_disconnect() {
        let clients = [Connected {
            public_id: "pub-1".to_owned(),
            client_name: "Claude Code".to_owned(),
            server: "demo".to_owned(),
        }];
        let doc = body(&clients);
        assert_eq!(
            count(
                &doc,
                r#"table.clients > tbody > tr[data-family="pub-1"][data-client-name="Claude Code"][data-server="demo"]"#
            ),
            1
        );
        assert_eq!(text(&doc, "tr > td.lead"), "Claude Code");
        assert_eq!(text(&doc, "tr > td.half"), "on demo");
        assert_eq!(
            text(
                &doc,
                r#"tr > td.act > form > button.row-action[data-kind="danger"]"#
            ),
            "Disconnect"
        );
        assert_eq!(count(&doc, "tr > td.act > form > input[name=csrf]"), 1);
    }

    #[test]
    fn the_password_fields_sit_in_a_fields_grid_inside_a_part() {
        let doc = body(&[]);
        assert_eq!(
            count(
                &doc,
                "section.part div.fields > div.field > input[type=password]"
            ),
            2
        );
        assert_eq!(
            text(
                &doc,
                r#"form[action="/account/password"] button[data-kind="secondary"]"#
            ),
            "Change password"
        );
        assert_eq!(
            count(
                &doc,
                r#"form[action="/account/password"] button[data-kind="primary"]"#
            ),
            0,
            "Change password is secondary, so the page has no primary button"
        );
        assert_eq!(
            count(
                &doc,
                "div.field > input#new_password[aria-describedby=new_password-hint] + p.hint#new_password-hint"
            ),
            1
        );
    }

    #[test]
    fn a_credential_input_asks_no_password_manager_to_fill_it() {
        let header = |id: i64, name: &str, set_at: Option<i64>| values::HeaderView {
            id,
            name: name.to_owned(),
            lower: name.to_ascii_lowercase(),
            required: set_at.is_none(),
            set_at,
        };
        let part = Part {
            servers: vec![ServerView {
                slug: "demo".to_owned(),
                name: "Demo".to_owned(),
                host: "demo.example.com".to_owned(),
                plain_http: false,
                headers: vec![
                    header(11, "X-Trace-Id", None),
                    header(12, "X-Region", Some(1_700_000_000)),
                ],
            }],
            ..Part::default()
        };
        let markup = account_body_with("token", "bob@example.com", None, &[], &part);
        let doc = Html::parse_fragment(&markup.into_string());
        assert_eq!(count(&doc, r#"input[name^="value_"]"#), 2);
        assert_eq!(
            count(
                &doc,
                r#"input[name^="value_"][type="password"][autocomplete="new-password"][data-1p-ignore][data-lpignore="true"]"#
            ),
            2,
            "every credential input must carry the three attributes"
        );
        assert_eq!(
            count(&doc, r#"input[name^="value_"][autocomplete="off"]"#),
            0
        );
        assert_eq!(
            count(
                &doc,
                r#"input[name^="value_"][autocomplete="current-password"]"#
            ),
            0
        );
    }

    #[test]
    fn a_refused_change_names_the_refusal_in_a_notice_above_the_fields() {
        let markup = account_body(
            "token",
            "bob@example.com",
            Some("The current password is wrong."),
            &[],
        );
        let doc = Html::parse_fragment(&markup.into_string());
        assert_eq!(
            text(
                &doc,
                r#"form[action="/account/password"] > div.notice[data-notice="error"] > p"#
            ),
            "The password was not changed. The current password is wrong."
        );
    }

    fn view_header(id: i64, name: &str, required: bool, set_at: Option<i64>) -> values::HeaderView {
        values::HeaderView {
            id,
            name: name.to_owned(),
            lower: name.to_ascii_lowercase(),
            required,
            set_at,
        }
    }

    fn view_server(slug: &str, name: &str, headers: Vec<values::HeaderView>) -> ServerView {
        ServerView {
            slug: slug.to_owned(),
            name: name.to_owned(),
            host: "demo.example.com".to_owned(),
            plain_http: false,
            headers,
        }
    }

    #[test]
    fn the_retired_block_sits_in_the_credentials_body_with_a_server_head_and_a_danger_disconnect() {
        let part = Part {
            retired: vec![("old".to_owned(), "Old Server".to_owned())],
            ..Part::default()
        };
        let markup = account_body_with("token", "bob@example.com", None, &[], &part);
        let doc = Html::parse_fragment(&markup.into_string());
        assert_eq!(
            count(
                &doc,
                r#"section.part[aria-labelledby="values-title"] > div.part-body > section[data-values-retired="old"][data-values-server="old"]"#
            ),
            1,
            "the retired block is a server block in the credentials part body"
        );
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-retired="old"] > h3 > span.block-name"#
            ),
            "Old Server"
        );
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-retired="old"] > h3 > span.state[data-tone="muted"]"#
            ),
            "No longer uses stored credentials"
        );
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-retired="old"] details[data-confirm] button[data-kind="danger"]"#
            ),
            "Delete my stored credentials"
        );
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-retired="old"] details[data-confirm] div.confirm-body > p.muted"#
            ),
            "This cannot be undone."
        );
        assert_eq!(
            count(&doc, "section[data-values-retired] p.muted"),
            2,
            "the block holds two muted lines: the one under the head and the one after the button"
        );
        assert_eq!(
            text(&doc, r#"section[data-values-retired="old"] > h3 + p.muted"#),
            "Your credentials for this server are still stored but are no longer sent."
        );
    }

    #[test]
    fn the_saved_notice_leads_its_servers_block_and_counts_the_missing_credentials() {
        let part = Part {
            servers: vec![view_server(
                "demo",
                "Demo",
                vec![
                    view_header(1, "X-Trace-Id", true, Some(1_700_000_000)),
                    view_header(2, "X-Region", true, None),
                ],
            )],
            saved: Some("demo".to_owned()),
            ..Part::default()
        };
        let markup = account_body_with("token", "bob@example.com", None, &[], &part);
        let doc = Html::parse_fragment(&markup.into_string());
        assert_eq!(
            count(&doc, r#"div.notice[data-notice="ok"]"#),
            1,
            "the saved notice is rendered once"
        );
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-server="demo"] > div.notice[data-notice="ok"]:first-child > p:not(.attention)"#
            ),
            "Credentials saved for Demo."
        );
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-server="demo"] > div.notice > p.attention"#
            ),
            "1 required credential is still missing."
        );
    }

    #[test]
    fn a_saved_server_with_nothing_missing_says_only_that_it_saved() {
        let part = Part {
            servers: vec![view_server(
                "demo",
                "Demo",
                vec![view_header(1, "X-Trace-Id", true, Some(1_700_000_000))],
            )],
            saved: Some("demo".to_owned()),
            ..Part::default()
        };
        let markup = account_body_with("token", "bob@example.com", None, &[], &part);
        let doc = Html::parse_fragment(&markup.into_string());
        assert_eq!(
            text(
                &doc,
                r#"section[data-values-server="demo"] > div.notice > p"#
            ),
            "Credentials saved for Demo."
        );
    }

    #[test]
    fn save_credentials_is_primary_only_for_a_server_that_needs_values() {
        let part = Part {
            servers: vec![
                view_server(
                    "needs",
                    "Needs",
                    vec![view_header(1, "X-Trace-Id", true, None)],
                ),
                view_server(
                    "stored",
                    "Stored",
                    vec![view_header(2, "X-Region", true, Some(1_700_000_000))],
                ),
            ],
            ..Part::default()
        };
        let markup = account_body_with("token", "bob@example.com", None, &[], &part);
        let doc = Html::parse_fragment(&markup.into_string());
        assert_eq!(
            count(
                &doc,
                r#"form[action="/account/values/needs"] button[data-kind="primary"]"#
            ),
            1
        );
        assert_eq!(
            count(
                &doc,
                r#"form[action="/account/values/stored"] button[data-kind="primary"]"#
            ),
            0
        );
        assert_eq!(
            count(
                &doc,
                r#"form[action="/account/values/stored"] button[data-kind="secondary"]"#
            ),
            1
        );
    }
}
