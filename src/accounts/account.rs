use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use super::values::{self, Part, ServerView};
use crate::app::AppState;
use crate::oauth::connected::{self, Connected};
use crate::web::ui::{self, Note};
use crate::web::{MainData, Nav, Viewer, form_page_with, internal_error, redirect};

pub async fn get_account(State(state): State<AppState>, viewer: Viewer) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    let clients = match connected::list(&state.db, user.id, now).await {
        Ok(clients) => clients,
        Err(err) => return internal_error("connected clients", &err),
    };
    match values::part_for(&state, &viewer).await {
        Ok(part) => account_page_with(&viewer, StatusCode::OK, None, &clients, &part),
        Err(err) => internal_error("stored values", &err),
    }
}

/// The account page with the connected `clients`, and an error line when `error` is given.
/// Anonymous viewers go to sign-in.
pub fn account_page(
    viewer: &Viewer,
    status: StatusCode,
    error: Option<&str>,
    clients: &[Connected],
) -> Response {
    account_page_with(viewer, status, error, clients, &Part::default())
}

/// `account_page` with the credentials part.
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
        @if !part.servers.is_empty() {
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
                        button type="submit" data-kind="primary" { "Change password" }
                    }
                }
            }
        }
    }
}

/// The part that holds one form per server that takes stored values.
fn credentials_part(csrf: &str, email: &str, part: &Part) -> Markup {
    html! {
        section.part aria-labelledby="values-title" {
            div.part-head {
                h2 id="values-title" { "Your credentials" }
                p { "Stored for you, sent with your calls, and never shown again." }
            }
            div.part-body {
                @for server in &part.servers {
                    (server_values(csrf, email, server, part))
                }
            }
        }
    }
}

/// One server's credentials form, or the lock note when the session cannot open the key.
fn server_values(csrf: &str, email: &str, server: &ServerView, part: &Part) -> Markup {
    let needs = if server.needs_values() { "yes" } else { "no" };
    let refusal = part
        .refusal
        .as_ref()
        .filter(|refusal| refusal.slug == server.slug);
    html! {
        section data-values-server=(server.slug) data-needs-values=(needs) {
            h3 { (server.name) }
            p { "Sent to " (server.host) " with your calls, as " (ui::email(email)) "." }
            @if server.plain_http {
                (ui::notice("warning", html! {
                    p { "This server is reached over plain http. Your credentials travel unencrypted." }
                }))
            }
            @if part.locked {
                p.muted data-values-locked { (values::LOCKED) }
            } @else {
                form.flow method="post" action=(format!("/account/values/{}", server.slug)) {
                    input type="hidden" name="csrf" value=(csrf);
                    @if let Some(refusal) = refusal {
                        (ui::refused(Some("The credentials were not saved."), refusal.message, None))
                    }
                    div.fields {
                        @for header in &server.headers {
                            (header_field(&server.slug, header))
                        }
                    }
                    div.form-actions {
                        button type="submit" data-kind="secondary" { "Save credentials" }
                    }
                }
            }
        }
    }
}

/// One declared header: a write-only field with what is known of it, and the remove box when stored.
fn header_field(slug: &str, header: &values::HeaderView) -> Markup {
    let id = format!("value-{slug}-{}", header.id);
    let hint_id = format!("{id}-hint");
    let remove_id = format!("remove-{slug}-{}", header.id);
    let state = if header.set_at.is_some() {
        "set"
    } else {
        "unset"
    };
    ui::field(
        &id,
        &header.name,
        false,
        html! {
            input id=(id) name=(format!("value_{}", header.id)) type="password" autocomplete="off"
                aria-describedby=(hint_id);
        },
        ui::Note::Below(
            &hint_id,
            html! {
                p.hint id=(hint_id) data-value-state=(state) data-header=(header.lower) {
                    @if let Some(at) = header.set_at {
                        "Stored " (values::day(at))
                    } @else {
                        "Not set"
                        @if header.required {
                            " " span { "Required" }
                        }
                    }
                }
                @if header.set_at.is_some() {
                    (ui::check(
                        &remove_id,
                        &format!("remove_{}", header.id),
                        Some("1"),
                        false,
                        "Remove the stored credential",
                        None,
                    ))
                }
            },
        ),
    )
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
                r#"form[action="/account/password"] button[data-kind="primary"]"#
            ),
            "Change password"
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
}
