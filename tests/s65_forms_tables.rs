mod common;

use std::collections::HashSet;

use common::TestGateway;
use common::admin;
use common::client::{Page, TestClient};
use common::headers::{declare_header, header_id, set_switches};
use common::upstream::{FakeUpstream, UpstreamOptions};
use common::values::store_value;
use common::world::World;
use scraper::{ElementRef, Html, Selector};
use serde_json::json;

const BOB: &str = "bob@example.com";
const DAVE: &str = "dave@example.com";
/// Every input but hidden, checkbox and radio, and every select and textarea.
const CONTROLS: &str =
    r#"input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]), select, textarea"#;
const ADD_SERVER_HINTS: [(&str, &str); 2] = [
    (
        "Path",
        "Letters, digits and hyphens, at most 24 characters.",
    ),
    ("Upstream address", "An http or https address."),
];

/// The world the form and table pages are read from.
struct Seeded {
    w: World,
    bob: TestClient,
    demo: String,
    bob_id: String,
    _upstream: FakeUpstream,
}

/// One list of statement 66: its name, its page, the attributes each tr carries, and its row count.
struct List {
    name: &'static str,
    page: Page,
    attrs: &'static [&'static str],
    rows: Option<usize>,
}

/// Collapses runs of whitespace into single spaces.
fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn text_of(element: ElementRef<'_>) -> String {
    collapse(&element.text().collect::<String>())
}

/// Every element under `root` matching `css`, in document order.
fn all<'a>(root: ElementRef<'a>, css: &str) -> Vec<ElementRef<'a>> {
    let selector =
        Selector::parse(css).unwrap_or_else(|err| panic!("bad selector {css:?}: {err:?}"));
    root.select(&selector).collect()
}

fn has_class(element: ElementRef<'_>, class: &str) -> bool {
    element
        .value()
        .attr("class")
        .unwrap_or("")
        .split_whitespace()
        .any(|name| name == class)
}

fn parent_element(element: ElementRef<'_>) -> Option<ElementRef<'_>> {
    element.parent().and_then(ElementRef::wrap)
}

fn element_children(element: ElementRef<'_>) -> Vec<ElementRef<'_>> {
    element.children().filter_map(ElementRef::wrap).collect()
}

/// True when the space-separated attribute `attr` of `element` holds the token `token`.
fn attr_holds(element: ElementRef<'_>, attr: &str, token: &str) -> bool {
    element
        .value()
        .attr(attr)
        .unwrap_or("")
        .split_whitespace()
        .any(|name| name == token)
}

/// The seeded world: demo with bob granted, two rules, a redirect, an open invitation, and bob's calls.
async fn seeded() -> Seeded {
    let w = World::start().await;
    let bob = w.user(BOB).await;
    let (upstream, demo) = w.upstream("demo", UpstreamOptions::default()).await;
    w.grant(BOB, &[demo.as_str()]).await;
    let bob_id = w.user_id(BOB).await;
    let page = admin::add_rule(&w.owner, "everyone", "allow", "server", Some(&demo), None).await;
    assert_eq!(page.status, 303, "the allow rule must be saved");
    let page = admin::add_rule(
        &w.owner,
        "everyone",
        "deny",
        "tool",
        Some(&demo),
        Some("delete_db"),
    )
    .await;
    assert_eq!(page.status, 303, "the deny rule must be saved");
    let page = admin::add_redirect(&w.owner, "https", "example.com", "/callback").await;
    assert_eq!(page.status, 303, "the redirect address must be saved");
    let _dave = w.invite_link(DAVE, "user").await;
    declare_header(&w.owner, &demo, "X-Trace-Id", true).await;
    declare_header(&w.owner, &demo, "X-Region", false).await;
    let page = set_switches(&w.owner, &demo, false, true).await;
    assert_eq!(page.status, 303, "the switches must be saved");
    let trace = header_id(&w.owner, &demo, "X-Trace-Id")
        .await
        .expect("the header must have a remove link");
    let stored = store_value(&bob, "demo", &trace, "trace-7f3a").await;
    assert_eq!(stored.status, 303, "the credential must be stored");

    let tokens = w.token(&bob, "demo").await;
    let mcp = w.session_mcp("demo", &tokens);
    assert_eq!(
        mcp.initialize().await.status,
        200,
        "initialize must answer 200"
    );
    let answered = mcp.call_tool("echo", json!({"text": "hi"})).await;
    assert_eq!(answered.status, 200, "the allowed call must answer 200");
    let refused = mcp.call_tool("delete_db", json!({})).await;
    assert_eq!(
        refused.error_code(),
        Some(-32602),
        "the denied call must be refused"
    );
    Seeded {
        w,
        bob,
        demo,
        bob_id,
        _upstream: upstream,
    }
}

/// The pages a person fills in, with their names, setup included for an instance with no owner.
async fn form_pages(s: &Seeded) -> Vec<(String, Page)> {
    let w = &s.w;
    let anonymous = w.client();
    let server = format!("/admin/servers/{}", s.demo);
    let user = format!("/admin/users/{}", s.bob_id);
    let mut pages = vec![
        (
            "/admin/servers".to_string(),
            w.owner.get("/admin/servers").await,
        ),
        (server.clone(), w.owner.get(&server).await),
        (
            "/admin/rules".to_string(),
            w.owner.get("/admin/rules").await,
        ),
        (
            "/admin/redirects".to_string(),
            w.owner.get("/admin/redirects").await,
        ),
        (
            "/admin/invitations".to_string(),
            w.owner.get("/admin/invitations").await,
        ),
        ("/admin/mail".to_string(), w.owner.get("/admin/mail").await),
        (user.clone(), w.owner.get(&user).await),
        ("/account".to_string(), s.bob.get("/account").await),
        ("/login".to_string(), anonymous.get("/login").await),
        ("/forgot".to_string(), anonymous.get("/forgot").await),
    ];
    let fresh = TestGateway::start().await;
    pages.push((
        "/setup (no owner)".to_string(),
        fresh.client().get("/setup").await,
    ));
    pages
}

/// The lists of statement 66 as the owner and bob read them.
async fn lists(s: &Seeded) -> Vec<List> {
    let w = &s.w;
    vec![
        List {
            name: "/admin/servers",
            page: w.owner.get("/admin/servers").await,
            attrs: &["data-server-id", "data-slug"],
            rows: Some(1),
        },
        List {
            name: "/admin/users",
            page: w.owner.get("/admin/users").await,
            attrs: &["data-user-id", "data-email"],
            rows: None,
        },
        List {
            name: "/admin/invitations",
            page: w.owner.get("/admin/invitations").await,
            attrs: &["data-invitation-id", "data-email"],
            rows: Some(1),
        },
        List {
            name: "/admin/servers/{id} (custom headers)",
            page: w.owner.get(&format!("/admin/servers/{}", s.demo)).await,
            attrs: &["data-header"],
            rows: Some(2),
        },
        List {
            name: "/admin/rules",
            page: w.owner.get("/admin/rules").await,
            attrs: &["data-rule-id"],
            rows: Some(2),
        },
        List {
            name: "/admin/redirects",
            page: w.owner.get("/admin/redirects").await,
            attrs: &["data-redirect-id"],
            rows: None,
        },
        List {
            name: "/admin/activity",
            page: w.owner.get("/admin/activity").await,
            attrs: &["data-kind"],
            rows: None,
        },
        List {
            name: "/account",
            page: s.bob.get("/account").await,
            attrs: &["data-family"],
            rows: None,
        },
    ]
}

/// Problems with the fields of a page: a control outside a div.field in a row, or no label before it.
fn field_problems(root: ElementRef<'_>) -> Vec<String> {
    let mut problems = Vec::new();
    for control in all(root, CONTROLS) {
        let id = control.value().attr("id").unwrap_or("");
        let name = control.value().attr("name").unwrap_or("");
        if id.is_empty() {
            problems.push(format!("the control {name:?} has no id"));
            continue;
        }
        let field = match parent_element(control) {
            Some(field) if field.value().name() == "div" && has_class(field, "field") => field,
            _ => {
                problems.push(format!("the control {id} must sit directly in a div.field"));
                continue;
            }
        };
        let row_ok = parent_element(field).is_some_and(|row| {
            row.value().name() == "fieldset"
                || (row.value().name() == "div" && has_class(row, "fields"))
        });
        if !row_ok {
            problems.push(format!(
                "the div.field of {id} must sit directly in a div.fields"
            ));
        }
        let kids = element_children(field);
        let position = kids.iter().position(|kid| kid.id() == control.id());
        let label = kids
            .iter()
            .position(|kid| kid.value().name() == "label" && kid.value().attr("for") == Some(id));
        match (label, position) {
            (Some(label), Some(position)) if label < position => {}
            _ => problems.push(format!(
                "the control {id} must follow a label[for={id}] that is a direct child of its div.field"
            )),
        }
    }
    problems
}

/// Problems with the labels of a page: no for, an input inside, or a bracket other than (optional).
fn label_problems(root: ElementRef<'_>) -> Vec<String> {
    let mut problems = Vec::new();
    for label in all(root, "label") {
        let text = text_of(label);
        if label.value().attr("for").is_none() {
            problems.push(format!("the label {text:?} has no for"));
        }
        if !all(label, "input").is_empty() {
            problems.push(format!("the label {text:?} holds an input"));
        }
        if text.contains('(') {
            let optional = all(label, "span.optional");
            let marked = optional.len() == 1 && text_of(optional[0]) == "(optional)";
            if !marked || text.replace("(optional)", "").contains('(') {
                problems.push(format!(
                    "the label {text:?} holds a bracket outside (optional)"
                ));
            }
        }
    }
    problems
}

/// Problems with the hints of a page: a p.hint with no id, or one no control in its field names.
fn hint_problems(root: ElementRef<'_>) -> Vec<String> {
    let mut problems = Vec::new();
    for hint in all(root, "p.hint") {
        let text = text_of(hint);
        let Some(id) = hint.value().attr("id") else {
            problems.push(format!("the hint {text:?} has no id"));
            continue;
        };
        let mut container = None;
        let mut node = parent_element(hint);
        while let Some(element) = node {
            if has_class(element, "field") || has_class(element, "check") {
                container = Some(element);
                break;
            }
            node = parent_element(element);
        }
        let tied = container.is_some_and(|container| {
            all(container, "[aria-describedby]")
                .into_iter()
                .any(|control| attr_holds(control, "aria-describedby", id))
        });
        if !tied {
            problems.push(format!(
                "the hint {id} must be named by aria-describedby on a control in its field"
            ));
        }
    }
    problems
}

/// Problems with the checkboxes of a page: one outside a div.check, or with no label for its id.
fn check_problems(root: ElementRef<'_>) -> Vec<String> {
    let mut problems = Vec::new();
    for input in all(root, r#"input[type="checkbox"]"#) {
        let id = input.value().attr("id").unwrap_or("");
        if id.is_empty() {
            problems.push("a checkbox has no id".to_string());
            continue;
        }
        let Some(parent) = parent_element(input) else {
            problems.push(format!("the checkbox {id} has no parent"));
            continue;
        };
        if parent.value().name() != "div" || !has_class(parent, "check") {
            problems.push(format!(
                "the checkbox {id} must sit directly in a div.check"
            ));
            continue;
        }
        let labelled = element_children(parent)
            .into_iter()
            .any(|kid| kid.value().name() == "label" && kid.value().attr("for") == Some(id));
        if !labelled {
            problems.push(format!(
                "the checkbox {id} needs a sibling label[for={id}] in its div.check"
            ));
        }
    }
    problems
}

/// Problems with the ids of a page: an id on two elements, a label[for] or an aria-describedby naming no id.
fn id_problems(root: ElementRef<'_>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut ids: HashSet<String> = HashSet::new();
    for element in all(root, "[id]") {
        let id = element.value().attr("id").unwrap_or("");
        if !ids.insert(id.to_owned()) {
            problems.push(format!("the id {id:?} is on more than one element"));
        }
    }
    for label in all(root, "label[for]") {
        let target = label.value().attr("for").unwrap_or("");
        if !ids.contains(target) {
            problems.push(format!("the label for {target:?} names no id on the page"));
        }
    }
    for element in all(root, "[aria-describedby]") {
        let described = element.value().attr("aria-describedby").unwrap_or("");
        for id in described.split_whitespace() {
            if !ids.contains(id) {
                problems.push(format!("aria-describedby names the missing id {id:?}"));
            }
        }
    }
    problems
}

/// Runs one check over every page and asserts that none has a problem.
fn assert_pages(pages: &[(String, Page)], check: fn(ElementRef<'_>) -> Vec<String>, rule: &str) {
    for (name, page) in pages {
        let doc = Html::parse_document(&page.body);
        let problems = check(doc.root_element());
        assert!(
            problems.is_empty(),
            "{name}: {rule}; problems: {problems:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_field_sits_in_a_row_under_its_label() {
    let s = seeded().await;
    let pages = form_pages(&s).await;
    for (name, page) in &pages {
        let doc = Html::parse_document(&page.body);
        assert!(
            !all(doc.root_element(), CONTROLS).is_empty(),
            "{name} must hold a control a person fills in, or the check would say nothing"
        );
    }
    assert_pages(
        &pages,
        field_problems,
        "every control must be a direct child of a div.field in a div.fields, after its label[for]",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn labels_are_tied_to_their_control_and_hold_no_brackets() {
    let s = seeded().await;
    let pages = form_pages(&s).await;
    assert_pages(
        &pages,
        label_problems,
        "every label needs a for, holds no input, and holds a bracket only as span.optional (optional)",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hints_are_tied_to_their_control() {
    let s = seeded().await;
    let pages = form_pages(&s).await;
    assert_pages(
        &pages,
        hint_problems,
        "every p.hint has an id that a control in its field names in aria-describedby",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn checkboxes_sit_in_a_check_beside_their_label() {
    let s = seeded().await;
    let pages = form_pages(&s).await;
    assert_pages(
        &pages,
        check_problems,
        "every checkbox sits directly in a div.check beside a label[for] with its id",
    );
    let server = s.w.owner.get(&format!("/admin/servers/{}", s.demo)).await;
    assert!(
        server.count(r#"input[type="checkbox"]"#) >= 1,
        "the server page must hold a checkbox, or the check would say nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ids_are_unique_and_every_description_exists() {
    let s = seeded().await;
    let mut pages = form_pages(&s).await;
    for list in lists(&s).await {
        pages.push((list.name.to_string(), list.page));
    }
    let trace = header_id(&s.w.owner, &s.demo, "X-Trace-Id")
        .await
        .expect("the header must have a remove link");
    let confirm = format!("/admin/servers/{}/headers/{trace}/remove", s.demo);
    pages.push((confirm.clone(), s.w.owner.get(&confirm).await));
    assert_pages(
        &pages,
        id_problems,
        "no id is on two elements, every label[for] names an id, and every aria-describedby id exists",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_form_says_what_the_path_and_the_upstream_take() {
    let s = seeded().await;
    let page = s.w.owner.get("/admin/servers").await;
    let doc = Html::parse_document(&page.body);
    for (label_text, hint) in ADD_SERVER_HINTS {
        let label = all(doc.root_element(), "label")
            .into_iter()
            .find(|label| text_of(*label) == label_text)
            .unwrap_or_else(|| panic!("the server form must have a label {label_text}"));
        let field = parent_element(label)
            .unwrap_or_else(|| panic!("the label {label_text} must sit in a field"));
        let hints = all(field, "p.hint");
        assert_eq!(
            hints.len(),
            1,
            "the field {label_text} must hold one p.hint"
        );
        assert_eq!(
            text_of(hints[0]),
            hint,
            "the hint of {label_text} must read {hint:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lists_are_tables_with_column_heads_and_rows() {
    let s = seeded().await;
    let mut checks: Vec<(String, Page, &str)> = lists(&s)
        .await
        .into_iter()
        .map(|list| (list.name.to_string(), list.page, "table.list"))
        .collect();
    checks.push((
        "/admin (latest activity)".to_string(),
        s.w.owner.get("/admin").await,
        "[data-latest-activity] table.list",
    ));
    for (name, page, scope) in checks {
        assert_eq!(
            page.count("ul.rows") + page.count("ol.rows"),
            0,
            "{name} must hold no ul.rows or ol.rows"
        );
        let doc = Html::parse_document(&page.body);
        let tables = all(doc.root_element(), scope);
        assert_eq!(
            tables.len(),
            1,
            "{name} must hold one {scope}, got {}",
            tables.len()
        );
        let table = tables[0];
        let heads = all(table, "thead th");
        assert!(
            !heads.is_empty(),
            "the table of {name} must hold column heads"
        );
        assert_eq!(
            all(table, r#"thead th[scope="col"]"#).len(),
            heads.len(),
            "every column head of {name} must have scope col"
        );
        assert!(
            !all(table, "tbody tr").is_empty(),
            "the table of {name} must hold rows in tbody"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rows_carry_their_data_on_the_row_element() {
    let s = seeded().await;
    for list in lists(&s).await {
        let attrs: String = list.attrs.iter().map(|attr| format!("[{attr}]")).collect();
        let found = list.page.count(&format!("tbody tr{attrs}"));
        match list.rows {
            Some(want) => assert_eq!(
                found, want,
                "{} must hold {want} tr carrying {attrs}, got {found}",
                list.name
            ),
            None => assert!(found >= 1, "{} must hold a tr carrying {attrs}", list.name),
        }
        for attr in list.attrs {
            assert_eq!(
                list.page.count(&format!("li[{attr}]")),
                0,
                "{} must not keep {attr} on an li",
                list.name
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_servers_counts_carry_their_unit_in_the_cell() {
    let s = seeded().await;
    let page = s.w.owner.get("/admin/servers").await;
    let doc = Html::parse_document(&page.body);
    let row = all(doc.root_element(), "tbody tr[data-server-id]");
    assert_eq!(row.len(), 1, "the servers list must hold the row of demo");
    for (attr, want) in [("data-tool-count", "3"), ("data-user-count", "1")] {
        let cells = all(row[0], &format!("td[{attr}]"));
        assert_eq!(cells.len(), 1, "the row of demo must hold one td[{attr}]");
        let text = text_of(cells[0]);
        assert!(
            text.starts_with(want),
            "td[{attr}] must start with {want}, got {text:?}"
        );
        assert_eq!(
            all(cells[0], "span.unit").len(),
            1,
            "td[{attr}] must hold one span.unit beside its number"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rule_row_starts_with_the_rule_id() {
    let s = seeded().await;
    let page = s.w.owner.get("/admin/rules").await;
    let doc = Html::parse_document(&page.body);
    let rows = all(doc.root_element(), "tbody tr[data-rule-id]");
    assert_eq!(rows.len(), 2, "the rules list must hold both rules");
    for row in rows {
        let id = row.value().attr("data-rule-id").unwrap_or("");
        let cells = all(row, "td");
        assert!(!cells.is_empty(), "a rule row must hold cells");
        let first = text_of(cells[0]);
        assert_eq!(
            first.strip_prefix("Rule ").unwrap_or(&first).trim(),
            id,
            "the first cell of the rule row {id} must show its id"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_name_breaks_only_after_its_underscores() {
    let s = seeded().await;
    let page = s.w.owner.get(&format!("/admin/servers/{}", s.demo)).await;
    assert!(
        page.body.contains("delete_<wbr>db"),
        "the raw page must break delete_db after its underscore with wbr"
    );
    let doc = Html::parse_document(&page.body);
    let found = all(doc.root_element(), "*").into_iter().any(|element| {
        text_of(element) == "delete_db" && element.inner_html().contains("delete_<wbr>db")
    });
    assert!(
        found,
        "an element holding the tool delete_db must keep its text unchanged with wbr inside"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_email_address_breaks_before_the_at_sign_first() {
    let s = seeded().await;
    let page = s.w.owner.get("/admin/users").await;
    assert!(
        page.body.contains("bob</span><wbr><span>@example"),
        "the raw users page must split bob's address before the @ with wbr between its spans"
    );
    let doc = Html::parse_document(&page.body);
    let found = all(doc.root_element(), "span.email")
        .into_iter()
        .any(|element| {
            text_of(element) == "bob@example.com"
                && element
                    .inner_html()
                    .replace("<span>", "")
                    .replace("</span>", "")
                    .contains("bob<wbr>@example")
        });
    assert!(
        found,
        "a span.email holding bob's address must keep its text unchanged with wbr before the @"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_row_shows_its_duration_in_ms() {
    let s = seeded().await;
    let page = s.w.owner.get("/admin/activity").await;
    let doc = Html::parse_document(&page.body);
    let calls = all(doc.root_element(), r#"tbody tr[data-kind="tool_call"]"#);
    assert!(
        calls.len() >= 2,
        "the activity page must hold the allowed and the refused tool call, got {}",
        calls.len()
    );
    for call in calls {
        let durations = all(call, "td.duration");
        assert_eq!(
            durations.len(),
            1,
            "a tool-call row must hold one td.duration"
        );
        let text = text_of(durations[0]);
        let digits = text.strip_suffix(" ms").unwrap_or("");
        assert!(
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
            "the duration of a tool call must read digits then ms, got {text:?}"
        );
    }
}

/// The declarations of a stylesheet as (at-rules, selector, name, value), comments removed.
fn declarations(css: &str) -> Vec<(Vec<String>, String, String, String)> {
    let mut plain = String::new();
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        plain.push_str(&rest[..start]);
        rest = match rest[start..].find("*/") {
            Some(end) => &rest[start + end + 2..],
            None => "",
        };
    }
    plain.push_str(rest);
    let mut found = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut buffer = String::new();
    for ch in plain.chars() {
        match ch {
            '{' => {
                stack.push(collapse(&buffer));
                buffer.clear();
            }
            ';' | '}' => {
                if let (Some((selector, ancestors)), Some((name, value))) =
                    (stack.split_last(), buffer.split_once(':'))
                {
                    found.push((
                        ancestors.to_vec(),
                        selector.clone(),
                        collapse(name),
                        collapse(value),
                    ));
                }
                buffer.clear();
                if ch == '}' {
                    stack.pop();
                }
            }
            _ => buffer.push(ch),
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread")]
async fn the_duration_cell_keeps_its_text_on_one_line() {
    let w = TestGateway::start().await;
    let c = w.client();
    let page = c.get("/login").await;
    let href = page
        .attr(r#"link[rel="stylesheet"]"#, "href")
        .expect("the sign-in page must link a stylesheet");
    let css = c.get(&href).await.body;
    let nowrap = declarations(&css)
        .into_iter()
        .any(|(_, selector, name, value)| {
            name == "white-space"
                && value == "nowrap"
                && selector
                    .split(',')
                    .any(|part| part.trim().contains(".duration"))
        });
    assert!(
        nowrap,
        "the stylesheet must hold a rule for .duration that declares white-space: nowrap"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_hints_under_the_two_switches_are_held_to_a_measure_of_60_characters() {
    let w = TestGateway::start().await;
    let c = w.client();
    let page = c.get("/login").await;
    let href = page
        .attr(r#"link[rel="stylesheet"]"#, "href")
        .expect("the sign-in page must link a stylesheet");
    let css = c.get(&href).await.body;
    let capped = declarations(&css)
        .into_iter()
        .any(|(_, selector, name, value)| {
            (name == "max-inline-size" || name == "max-width")
                && value == "60ch"
                && selector.split(',').any(|part| {
                    let part = part.trim();
                    part.contains("[data-switches]") && part.ends_with(".hint")
                })
        });
    assert!(
        capped,
        "the stylesheet must cap the hint of each switch in [data-switches] at 60ch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notice_inside_a_part_is_capped_at_the_width_of_a_page_notice() {
    let w = TestGateway::start().await;
    let c = w.client();
    let page = c.get("/login").await;
    let href = page
        .attr(r#"link[rel="stylesheet"]"#, "href")
        .expect("the sign-in page must link a stylesheet");
    let css = c.get(&href).await.body;
    let capped = declarations(&css)
        .into_iter()
        .any(|(_, selector, name, value)| {
            name == "max-inline-size"
                && value == "640px"
                && selector.contains("main > .notice")
                && selector.contains(".part-body .notice")
        });
    assert!(
        capped,
        "the stylesheet must cap a notice inside a part body at 640px, with the page notice"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_header_name_in_the_remove_title_is_set_in_the_mono_face() {
    let w = TestGateway::start().await;
    let c = w.client();
    let page = c.get("/login").await;
    let href = page
        .attr(r#"link[rel="stylesheet"]"#, "href")
        .expect("the sign-in page must link a stylesheet");
    let css = c.get(&href).await.body;
    let mono = declarations(&css)
        .into_iter()
        .any(|(_, selector, name, value)| {
            name == "font-family"
                && value == "var(--mono)"
                && selector
                    .split(',')
                    .any(|part| part.trim() == "h1 > .title-name")
        });
    assert!(
        mono,
        "the stylesheet must set h1 > .title-name in the mono face, as the consent destination is"
    );
}
