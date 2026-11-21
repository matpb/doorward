use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use maud::{Markup, html};

use crate::app::AppState;
use crate::oauth::connected::{self, Connected};
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
    html! {
        div.stack {
            div.page-head {
                h1 { "Your account" }
            }
            p.lede { "Signed in as " (email) }
            section.card {
                h2 { "Connected clients" }
                @if clients.is_empty() {
                    p { "No client is connected to your account." }
                } @else {
                    ul.rows {
                        @for row in clients {
                            li data-family=(row.public_id) data-client-name=(row.client_name) data-server=(row.server) {
                                div.row-main {
                                    span.row-title { (row.client_name) }
                                    p.row-meta { "on " (row.server) }
                                }
                                div.row-actions {
                                    form method="post" action=(format!("/account/clients/{}/disconnect", row.public_id)) {
                                        input type="hidden" name="csrf" value=(csrf);
                                        button type="submit" data-kind="danger" { "Disconnect" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            section.card {
                h2 { "Change password" }
                @if let Some(message) = error {
                    p.error { (message) }
                }
                form method="post" action="/account/password" {
                    input type="hidden" name="csrf" value=(csrf);
                    div.fields {
                        div {
                            label for="current_password" { "Current password" }
                            input id="current_password" name="current_password" type="password" autocomplete="current-password" required;
                        }
                        div {
                            label for="new_password" { "New password" }
                            input id="new_password" name="new_password" type="password" autocomplete="new-password" required;
                        }
                    }
                    button type="submit" data-kind="primary" { "Change password" }
                }
            }
            form method="post" action="/logout" {
                input type="hidden" name="csrf" value=(csrf);
                button type="submit" data-kind="secondary" { "Sign out" }
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
    fn the_page_is_a_stack_of_a_head_a_lede_and_two_cards() {
        let doc = body(&[]);
        assert_eq!(count(&doc, "div.stack > div.page-head > h1"), 1);
        assert_eq!(text(&doc, "div.page-head > h1"), "Your account");
        assert_eq!(text(&doc, "p.lede"), "Signed in as bob@example.com");
        assert_eq!(count(&doc, "div.stack > section.card"), 2);
        assert_eq!(
            text(&doc, "section.card > p"),
            "No client is connected to your account."
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
                r#"section.card ul.rows > li[data-family="pub-1"][data-client-name="Claude Code"][data-server="demo"]"#
            ),
            1
        );
        assert_eq!(
            text(&doc, "li > div.row-main > span.row-title"),
            "Claude Code"
        );
        assert_eq!(text(&doc, "li > div.row-main > p.row-meta"), "on demo");
        assert_eq!(
            text(
                &doc,
                r#"li > div.row-actions > form > button[data-kind="danger"]"#
            ),
            "Disconnect"
        );
        assert_eq!(
            count(&doc, "li > div.row-actions > form > input[name=csrf]"),
            1
        );
    }

    #[test]
    fn the_password_fields_sit_in_a_fields_grid_inside_a_card() {
        let doc = body(&[]);
        assert_eq!(
            count(&doc, "section.card div.fields > div > input[type=password]"),
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
            text(
                &doc,
                r#"div.stack > form[action="/logout"] button[data-kind="secondary"]"#
            ),
            "Sign out"
        );
    }
}
