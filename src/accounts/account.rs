use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use crate::app::AppState;
use crate::oauth::connected::{self, Connected};
use crate::web::ui::{self, Note};
use crate::web::{MainData, Nav, Viewer, form_page_with, internal_error, redirect};

pub async fn get_account(State(state): State<AppState>, viewer: Viewer) -> Response {
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let now = state.clock.now().unix_timestamp();
    match connected::list(&state.db, user.id, now).await {
        Ok(clients) => account_page(&viewer, StatusCode::OK, None, &clients),
        Err(err) => internal_error("connected clients", &err),
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
    let Some(user) = viewer.user.as_ref() else {
        return redirect("/login");
    };
    let data = MainData {
        nav: Nav::Account {
            admin: viewer.is_admin(),
        },
        ..MainData::default()
    };
    form_page_with(viewer, status, "account", "Your account", &data, |csrf| {
        account_body(csrf, &user.email, error, clients)
    })
}

fn account_body(csrf: &str, email: &str, error: Option<&str>, clients: &[Connected]) -> Markup {
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
                                        code { (row.server) }
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
