//! The text and HTML parts of the invitation, reset and new-connection mails. The link is the only
//! content. The HTML part of each mail is fixed byte for byte by the reference copies in `fixtures/`.

use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::mail::Message;

/// The parts of a mail; the recipient is added when it is sent.
pub struct Parts {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl Parts {
    pub fn to(self, to: String) -> Message {
        Message {
            to,
            subject: self.subject,
            text: self.text,
            html: self.html,
        }
    }
}

/// The server, the host the sign-in was sent to, and the time, as the new connection mail shows them.
pub struct Connection<'a> {
    pub server: &'a str,
    pub destination: &'a str,
    pub time: &'a str,
}

/// The host of the gateway's public address, with its port when written; redirects use `shown_host`.
pub fn host_and_port(address: &str) -> &str {
    let rest = address.split_once("://").map_or(address, |(_, rest)| rest);
    rest.split_once('/').map_or(rest, |(host, _)| host)
}

pub fn invitation(link: &str, host: &str) -> Parts {
    let subject = "You are invited to Doorward";
    Parts {
        subject: subject.to_owned(),
        text: format!(
            "You are invited to Doorward.\n\nSet your password at this link. It works once:\n\n{link}\n\n{}\n",
            closing_line(host)
        ),
        html: document(&Slots {
            subject,
            heading: subject,
            facts: &[],
            body: &["Set your password to accept. The link works once."],
            button: "Set your password",
            link,
            host,
            deny: false,
        })
        .into_string(),
    }
}

pub fn reset(link: &str, host: &str) -> Parts {
    let subject = "Reset your Doorward password";
    let asked = "Someone asked to reset the password of your Doorward account.";
    Parts {
        subject: subject.to_owned(),
        text: format!(
            "{asked}\n\nSet a new password at this link. It works once:\n\n{link}\n\n{RESET_NOTE}\n\n{}\n",
            closing_line(host)
        ),
        html: document(&Slots {
            subject,
            heading: subject,
            facts: &[],
            body: &[
                asked,
                RESET_NOTE,
                "Set a new one with this link. It works once.",
            ],
            button: "Set a new password",
            link,
            host,
            deny: false,
        })
        .into_string(),
    }
}

/// Sent when a client connects to the account for the first time; the link disconnects it.
pub fn new_connection(link: &str, facts: &Connection<'_>, host: &str) -> Parts {
    let subject = "A new app was connected to your Doorward account";
    Parts {
        subject: subject.to_owned(),
        text: format!(
            "{subject}.\n\nIt can use {server}.\nThe sign-in was sent to {destination}.\nConnected on {time}.\n\nIf you did not connect it, disconnect it at this link:\n\n{link}\n\n{closing}\n",
            server = facts.server,
            destination = facts.destination,
            time = facts.time,
            closing = closing_line(host),
        ),
        html: document(&Slots {
            subject,
            heading: subject,
            facts: &[
                Fact {
                    label: "It can use",
                    value: facts.server,
                    kind: Kind::Text,
                },
                Fact {
                    label: "The sign-in was sent to",
                    value: facts.destination,
                    kind: Kind::Host,
                },
                Fact {
                    label: "Connected on",
                    value: facts.time,
                    kind: Kind::Time,
                },
            ],
            body: &["If you did not connect it, disconnect it."],
            button: "Disconnect it",
            link,
            host,
            deny: true,
        })
        .into_string(),
    }
}

const INK: &str = "#181612";
const INK_2: &str = "#4A4743";
const SANS: &str =
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";
const MONO: &str = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace";
const CAPTION: &str = "Or copy this address into your browser:";
const CLOSING: &str = "Doorward decides who reaches which MCP server and which tool, and keeps a record of every call.";
const RESET_NOTE: &str = "If this was not you, ignore this mail. Your password stays the same.";
const NBSP: char = '\u{a0}';
const NL: PreEscaped<&str> = PreEscaped("\n");
const MSO_OPEN: &str = r#"<!--[if mso]><table role="presentation" width="560" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->"#;
const MSO_CLOSE: &str = "<!--[if mso]></td></tr></table><![endif]-->";
const STYLE: &str = "
:root { color-scheme: light dark; }
@media (prefers-color-scheme: dark) {
  .dw-room { background-color: #181715 !important; }
  .dw-ink { color: #F0EEEB !important; }
  .dw-ink-2 { color: #BFBDBA !important; }
  .dw-line { border-color: #F0EEEB !important; }
  .dw-box { border-color: #767471 !important; }
  .dw-button { border-color: #F0EEEB !important; background-color: #23211F !important; }
  .dw-deny { color: #FB817A !important; }
  .dw-button-deny { border-color: #FB817A !important; background-color: #36201E !important; }
}
";

/// How a fact's value is set: plain text, a host, or the time.
#[derive(Clone, Copy)]
enum Kind {
    Text,
    Host,
    Time,
}

/// One labelled value between the title and the body.
struct Fact<'a> {
    label: &'a str,
    value: &'a str,
    kind: Kind,
}

/// The words and slots of one mail's HTML part.
struct Slots<'a> {
    subject: &'a str,
    heading: &'a str,
    facts: &'a [Fact<'a>],
    body: &'a [&'a str],
    button: &'a str,
    link: &'a str,
    host: &'a str,
    deny: bool,
}

/// The closing sentence of the text part.
fn closing_line(host: &str) -> String {
    format!("Sent by the Doorward gateway at {host}. {CLOSING}")
}

/// The whole HTML part: the same document for all three mails, from the title to the closing line.
fn document(slots: &Slots<'_>) -> Markup {
    let (edge, fill) = if slots.deny {
        ("#B7191C", "#FDEBE9")
    } else {
        (INK, "#F2F0EC")
    };
    let button_class = if slots.deny {
        "dw-button-deny"
    } else {
        "dw-button"
    };
    let link_class = if slots.deny { "dw-deny" } else { "dw-ink" };
    let first = if slots.facts.is_empty() { 16 } else { 24 };
    html! {
        (DOCTYPE)
        (NL)
        html lang="en" {
            (NL)
            head {
                (NL)
                meta charset="utf-8";
                (NL)
                meta name="viewport" content="width=device-width, initial-scale=1";
                (NL)
                meta name="color-scheme" content="light dark";
                (NL)
                meta name="supported-color-schemes" content="light dark";
                (NL)
                title { (slots.subject) }
                (NL)
                style { (PreEscaped(STYLE)) }
                (NL)
            }
            (NL)
            body class="dw-room" style="margin:0;padding:0;background-color:#FBFAF7;" {
                (NL)
                table role="presentation" class="dw-room" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#FBFAF7" style="background-color:#FBFAF7;" {
                    (NL)
                    tr {
                        (NL)
                        td align="center" style="padding:0;" {
                            (NL)
                            (PreEscaped(MSO_OPEN))
                            (NL)
                            table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;" {
                                (NL)
                                tr {
                                    (NL)
                                    td style="padding:18px 24px 0 24px;" {
                                        (NL)
                                        table role="presentation" cellpadding="0" cellspacing="0" border="0" {
                                            (NL)
                                            tr {
                                                (NL)
                                                td class="dw-line" width="2" height="2" style="width:2px;height:2px;border-top:9px solid #181612;border-right:3px solid #181612;border-bottom:9px solid #181612;border-left:9px solid #181612;border-radius:2px;font-size:0;line-height:0;" { (PreEscaped("&nbsp;")) }
                                                (NL)
                                                td class="dw-ink" style="padding:0 0 0 18px;font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;font-size:17px;line-height:20px;font-weight:700;color:#181612;" { "Doorward" }
                                                (NL)
                                            }
                                            (NL)
                                        }
                                        (NL)
                                    }
                                    (NL)
                                }
                                (NL)
                                tr {
                                    (NL)
                                    td style="padding:16px 24px 0 24px;" {
                                        (NL)
                                        table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" {
                                            (NL)
                                            tr {
                                                (NL)
                                                td class="dw-line" height="0" style="height:0;border-top:2px solid #181612;font-size:0;line-height:0;" { (PreEscaped("&nbsp;")) }
                                                (NL)
                                            }
                                            (NL)
                                        }
                                        (NL)
                                    }
                                    (NL)
                                }
                                (NL)
                                tr {
                                    (NL)
                                    td style="padding:40px 24px 0 24px;" {
                                        (NL)
                                        h1 class="dw-ink" style="margin:0;font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;font-size:28px;line-height:32px;font-weight:700;color:#181612;" { (tied(slots.heading)) }
                                        (NL)
                                    }
                                    (NL)
                                }
                                (NL)
                                @for (index, fact) in slots.facts.iter().enumerate() {
                                    tr {
                                        (NL)
                                        td class="dw-ink-2" style=(label_style(index)) { (tied(fact.label)) }
                                        (NL)
                                    }
                                    (NL)
                                    tr {
                                        (NL)
                                        td class="dw-ink" style=(value_style(fact.kind)) { (value_html(fact)) }
                                        (NL)
                                    }
                                    (NL)
                                }
                                @for (index, line) in slots.body.iter().enumerate() {
                                    tr {
                                        (NL)
                                        td class="dw-ink" style=(format!("padding:{}px 24px 0 24px;font-family:{SANS};font-size:16px;line-height:24px;color:{INK};", if index == 0 { first } else { 12 })) { (tied(line)) }
                                        (NL)
                                    }
                                    (NL)
                                }
                                tr {
                                    (NL)
                                    td style="padding:24px 24px 0 24px;" {
                                        (NL)
                                        table role="presentation" cellpadding="0" cellspacing="0" border="0" {
                                            (NL)
                                            tr {
                                                (NL)
                                                td class=(button_class) bgcolor=(fill) style=(format!("background-color:{fill};border:2px solid {edge};border-radius:4px;mso-padding-alt:12px 24px;")) {
                                                    (NL)
                                                    a class=(link_class) href=(slots.link) style=(format!("display:inline-block;padding:12px 24px;font-family:{SANS};font-size:16px;line-height:24px;font-weight:700;color:{edge};text-decoration:none;")) { (slots.button) }
                                                    (NL)
                                                }
                                                (NL)
                                            }
                                            (NL)
                                        }
                                        (NL)
                                    }
                                    (NL)
                                }
                                (NL)
                                tr {
                                    (NL)
                                    td class="dw-ink-2" style=(format!("padding:32px 24px 0 24px;font-family:{SANS};font-size:13px;line-height:20px;color:{INK_2};")) { (tied(CAPTION)) }
                                    (NL)
                                }
                                (NL)
                                tr {
                                    (NL)
                                    td style="padding:8px 24px 0 24px;" {
                                        (NL)
                                        table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" {
                                            (NL)
                                            tr {
                                                (NL)
                                                td class="dw-box" style=(format!("padding:12px 16px;border:1px solid #82807B;border-radius:4px;font-family:{MONO};font-size:13px;line-height:20px;word-wrap:break-word;overflow-wrap:anywhere;")) {
                                                    (NL)
                                                    a class="dw-ink" href=(slots.link) style="color:#181612;text-decoration:none;word-wrap:break-word;overflow-wrap:anywhere;" { (address_html(slots.link)) }
                                                    (NL)
                                                }
                                                (NL)
                                            }
                                            (NL)
                                        }
                                        (NL)
                                    }
                                    (NL)
                                }
                                (NL)
                                tr {
                                    (NL)
                                    td class="dw-ink-2" style=(format!("padding:32px 24px 48px 24px;font-family:{SANS};font-size:13px;line-height:20px;color:{INK_2};word-wrap:break-word;overflow-wrap:anywhere;")) {
                                        "Sent by the Doorward gateway at " (host_html(slots.host, ".")) " " (tied(CLOSING))
                                    }
                                    (NL)
                                }
                                (NL)
                            }
                            (NL)
                            (PreEscaped(MSO_CLOSE))
                            (NL)
                        }
                        (NL)
                    }
                    (NL)
                }
                (NL)
            }
            (NL)
        }
        (NL)
    }
}

/// The top padding of a fact's label: 24 px for the first fact, 12 px for the others.
fn label_style(index: usize) -> String {
    let top = if index == 0 { 24 } else { 12 };
    format!(
        "padding:{top}px 24px 0 24px;font-family:{SANS};font-size:13px;line-height:20px;color:{INK_2};"
    )
}

/// The style of a fact's value: the monospace stack at 15 px for a host, the sans stack at 16 px otherwise.
fn value_style(kind: Kind) -> String {
    let face = match kind {
        Kind::Host => format!("font-family:{MONO};font-size:15px;"),
        Kind::Text | Kind::Time => format!("font-family:{SANS};font-size:16px;"),
    };
    format!(
        "padding:0 24px 0 24px;{face}line-height:24px;font-weight:700;color:{INK};word-wrap:break-word;overflow-wrap:anywhere;"
    )
}

fn value_html(fact: &Fact<'_>) -> Markup {
    match fact.kind {
        Kind::Text => plain(fact.value),
        Kind::Host => host_html(fact.value, ""),
        Kind::Time => tied(fact.value),
    }
}

/// Text escaped as maud escapes it, with each non-breaking space written as `&nbsp;`.
fn escaped(text: &str) -> String {
    html! { (text) }.into_string().replace(NBSP, "&nbsp;")
}

fn plain(text: &str) -> Markup {
    PreEscaped(escaped(text))
}

/// Text whose last word is tied to the word before it.
fn tied(text: &str) -> Markup {
    PreEscaped(escaped(&tie(text)))
}

/// The text with its last space written as a non-breaking space.
fn tie(text: &str) -> String {
    match text.rfind(' ') {
        Some(at) => format!("{}{NBSP}{}", &text[..at], &text[at + 1..]),
        None => text.to_owned(),
    }
}

/// A host by the host rule: one inline block per piece, with a break between two blocks.
/// `tail` goes inside the last block.
fn host_html(host: &str, tail: &str) -> Markup {
    pieces_html(&host_pieces("", host, tail))
}

/// Each piece in its own inline block, with a `wbr` between two blocks.
fn pieces_html(pieces: &[String]) -> Markup {
    html! {
        @for (index, piece) in pieces.iter().enumerate() {
            @if index > 0 {
                wbr;
            }
            span style="display:inline-block;max-width:100%;" { (piece) }
        }
    }
}

/// The host rule: an address or a host of fewer than three labels stays whole; else the last two labels share a piece.
/// `lead` opens the first piece and `tail` closes the last one.
fn host_pieces(lead: &str, host: &str, tail: &str) -> Vec<String> {
    let (name, port) = match host.rfind(':') {
        Some(at) if is_digits(&host[at + 1..]) => (&host[..at], &host[at..]),
        _ => (host, ""),
    };
    let labels: Vec<&str> = name.split('.').collect();
    let address = !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if address || name.contains(':') || labels.len() < 3 {
        return vec![format!("{lead}{host}{tail}")];
    }
    let (head, last_two) = labels.split_at(labels.len() - 2);
    let mut pieces: Vec<String> = head
        .iter()
        .enumerate()
        .map(|(index, label)| {
            if index == 0 {
                format!("{lead}{label}")
            } else {
                format!(".{label}")
            }
        })
        .collect();
    pieces.push(format!(".{}{port}{tail}", last_two.join(".")));
    pieces
}

/// True for one or more ASCII digits and nothing else.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The address as text: the scheme and host by the host rule, then the path and the token, each in
/// its own inline block. The slash after the host closes the host's last block.
fn address_html(link: &str) -> Markup {
    let (scheme, after_scheme) = link
        .find("://")
        .map_or(("", link), |at| link.split_at(at + 3));
    let (host, from_slash) = after_scheme
        .find('/')
        .map_or((after_scheme, ""), |at| after_scheme.split_at(at));
    let (slash, rest) = match from_slash.strip_prefix('/') {
        Some(rest) => ("/", rest),
        None => ("", ""),
    };
    let cut = rest.rfind('/').map_or(0, |at| at + 1);
    let (path, token) = rest.split_at(cut);
    let mut pieces = host_pieces(scheme, host, slash);
    if !path.is_empty() {
        pieces.push(path.to_owned());
    }
    if !token.is_empty() {
        pieces.push(token.to_owned());
    }
    pieces_html(&pieces)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITATION_HTML: &str = include_str!("fixtures/invitation.html");
    const RESET_HTML: &str = include_str!("fixtures/reset.html");
    const NEW_CONNECTION_HTML: &str = include_str!("fixtures/new-connection.html");
    const GATEWAY: &str = "doorward.example.com";
    const INVITE_LINK: &str =
        "https://doorward.example.com/invite/dw_iv_8Jq2ZrV4mXc7Tn1LkP0aYbE5sHdW9u-f3oRiN6t_xMv";
    const RESET_LINK: &str =
        "https://doorward.example.com/reset/dw_rs_Q7m1XcVb9tKe3LpZ0aYfN5sHdW2u-R8oJiG6t_wTy";
    const DISCONNECT_LINK: &str = "https://doorward.example.com/account/disconnect/dw_dl_4Hn8TzRq1WcYb6LkM0aPfE3sJdV7u-x2oBiC9t_gUe";
    const SERVER: &str = "Internal documentation search and retrieval (staging mirror)";
    const SPAN: &str = r#"<span style="display:inline-block;max-width:100%;">"#;
    const RESET_NOTE: &str = "If this was not you, ignore this mail. Your password stays the same.";
    const INVISIBLE: [char; 8] = [
        '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{00ad}', '\u{200e}',
        '\u{200f}',
    ];

    fn connection() -> Connection<'static> {
        Connection {
            server: SERVER,
            destination: "127.0.0.1:53535",
            time: "21 November 2026, 14:05 UTC",
        }
    }

    #[test]
    fn the_new_connection_mail_carries_its_link_in_both_parts() {
        let parts = new_connection(DISCONNECT_LINK, &connection(), GATEWAY);
        assert_eq!(
            parts.subject,
            "A new app was connected to your Doorward account"
        );
        assert!(parts.text.contains(DISCONNECT_LINK));
        assert!(parts.html.contains(DISCONNECT_LINK));
    }

    #[test]
    fn the_new_connection_html_escapes_its_link() {
        let parts = new_connection(
            "http://127.0.0.1:8717/account/disconnect/\"<x>",
            &connection(),
            GATEWAY,
        );
        assert!(!parts.html.contains("\"<x>"));
        assert!(parts.html.contains("&quot;&lt;x&gt;"));
    }

    #[test]
    fn the_link_is_in_both_parts() {
        let parts = invitation(INVITE_LINK, GATEWAY);
        assert_eq!(parts.subject, "You are invited to Doorward");
        assert!(parts.text.contains(INVITE_LINK));
        assert!(parts.html.contains(INVITE_LINK));
    }

    #[test]
    fn the_html_part_escapes_the_link() {
        let parts = reset("http://127.0.0.1:8717/reset/\"<x>", GATEWAY);
        assert_eq!(parts.subject, "Reset your Doorward password");
        assert!(!parts.html.contains("\"<x>"));
        assert!(parts.html.contains("&quot;&lt;x&gt;"));
    }

    #[test]
    fn the_invitation_html_is_the_built_reference() {
        assert_eq!(invitation(INVITE_LINK, GATEWAY).html, INVITATION_HTML);
    }

    #[test]
    fn the_reset_html_is_the_built_reference() {
        assert_eq!(reset(RESET_LINK, GATEWAY).html, RESET_HTML);
    }

    #[test]
    fn the_new_connection_html_is_the_built_reference() {
        let parts = new_connection(DISCONNECT_LINK, &connection(), GATEWAY);
        assert_eq!(parts.html, NEW_CONNECTION_HTML);
    }

    #[test]
    fn the_invitation_text_is_exact() {
        assert_eq!(
            invitation(INVITE_LINK, GATEWAY).text,
            format!(
                "You are invited to Doorward.\n\nSet your password at this link. It works once:\n\n{INVITE_LINK}\n\nSent by the Doorward gateway at {GATEWAY}. Doorward decides who reaches which MCP server and which tool, and keeps a record of every call.\n"
            )
        );
    }

    #[test]
    fn the_reset_text_is_exact() {
        assert_eq!(
            reset(RESET_LINK, GATEWAY).text,
            format!(
                "Someone asked to reset the password of your Doorward account.\n\nSet a new password at this link. It works once:\n\n{RESET_LINK}\n\n{RESET_NOTE}\n\nSent by the Doorward gateway at {GATEWAY}. Doorward decides who reaches which MCP server and which tool, and keeps a record of every call.\n"
            )
        );
    }

    #[test]
    fn the_new_connection_text_is_exact() {
        assert_eq!(
            new_connection(DISCONNECT_LINK, &connection(), GATEWAY).text,
            format!(
                "A new app was connected to your Doorward account.\n\nIt can use {SERVER}.\nThe sign-in was sent to 127.0.0.1:53535.\nConnected on 21 November 2026, 14:05 UTC.\n\nIf you did not connect it, disconnect it at this link:\n\n{DISCONNECT_LINK}\n\nSent by the Doorward gateway at {GATEWAY}. Doorward decides who reaches which MCP server and which tool, and keeps a record of every call.\n"
            )
        );
    }

    #[test]
    fn the_host_rule_writes_the_six_literal_cases() {
        assert_eq!(
            host_html("127.0.0.1:53535", "").into_string(),
            format!("{SPAN}127.0.0.1:53535</span>")
        );
        assert_eq!(
            host_html("example.com", "").into_string(),
            format!("{SPAN}example.com</span>")
        );
        assert_eq!(
            host_html("localhost:50790", "").into_string(),
            format!("{SPAN}localhost:50790</span>")
        );
        assert_eq!(
            host_html("mcp.example.com", "").into_string(),
            format!("{SPAN}mcp</span><wbr>{SPAN}.example.com</span>")
        );
        assert_eq!(
            host_html(
                "oauth-callback.developer-tools.internal.tessellate.example.com:443",
                ""
            )
            .into_string(),
            format!(
                "{SPAN}oauth-callback</span><wbr>{SPAN}.developer-tools</span><wbr>{SPAN}.internal</span><wbr>{SPAN}.tessellate</span><wbr>{SPAN}.example.com:443</span>"
            )
        );
        assert_eq!(
            host_html(GATEWAY, ".").into_string(),
            format!("{SPAN}doorward</span><wbr>{SPAN}.example.com.</span>")
        );
    }

    #[test]
    fn a_private_scheme_destination_is_one_piece() {
        assert_eq!(
            host_html("cursor:", "").into_string(),
            format!("{SPAN}cursor:</span>")
        );
    }

    #[test]
    fn a_host_of_five_labels_has_four_spans_and_breaks_before_a_dot_only() {
        let html = host_html("two.three.four.example.com", "").into_string();
        assert_eq!(html.matches("<span").count(), 4);
        let pieces: Vec<&str> = html.split("<wbr>").collect();
        assert_eq!(pieces.len(), 4);
        for piece in &pieces[1..] {
            assert!(piece.starts_with(&format!("{SPAN}.")), "{piece}");
        }
    }

    #[test]
    fn the_address_is_whole_pieces_host_path_and_token() {
        assert_eq!(
            address_html(INVITE_LINK).into_string(),
            format!(
                "{SPAN}https://doorward</span><wbr>{SPAN}.example.com/</span><wbr>{SPAN}invite/</span><wbr>{SPAN}dw_iv_8Jq2ZrV4mXc7Tn1LkP0aYbE5sHdW9u-f3oRiN6t_xMv</span>"
            )
        );
    }

    #[test]
    fn the_address_rule_handles_an_address_without_a_path() {
        assert_eq!(
            address_html("https://doorward.example.com").into_string(),
            format!("{SPAN}https://doorward</span><wbr>{SPAN}.example.com</span>")
        );
    }

    #[test]
    fn the_new_connection_path_sits_in_one_span() {
        assert_eq!(
            address_html(DISCONNECT_LINK).into_string(),
            format!(
                "{SPAN}https://doorward</span><wbr>{SPAN}.example.com/</span><wbr>{SPAN}account/disconnect/</span><wbr>{SPAN}dw_dl_4Hn8TzRq1WcYb6LkM0aPfE3sJdV7u-x2oBiC9t_gUe</span>"
            )
        );
    }

    #[test]
    fn a_loopback_address_with_a_port_has_its_host_in_one_span() {
        assert_eq!(
            address_html("http://127.0.0.1:8717/account/disconnect/dw_dl_x").into_string(),
            format!(
                "{SPAN}http://127.0.0.1:8717/</span><wbr>{SPAN}account/disconnect/</span><wbr>{SPAN}dw_dl_x</span>"
            )
        );
    }

    #[test]
    fn a_host_of_six_labels_has_five_spans_before_the_path() {
        assert_eq!(
            address_html(
                "https://doorward.platform-engineering.internal-tools.eu-central.example.com/account/disconnect/dw_dl_x"
            )
            .into_string(),
            format!(
                "{SPAN}https://doorward</span><wbr>{SPAN}.platform-engineering</span><wbr>{SPAN}.internal-tools</span><wbr>{SPAN}.eu-central</span><wbr>{SPAN}.example.com/</span><wbr>{SPAN}account/disconnect/</span><wbr>{SPAN}dw_dl_x</span>"
            )
        );
    }

    #[test]
    fn the_address_text_is_the_link_character_for_character() {
        for link in [INVITE_LINK, RESET_LINK, DISCONNECT_LINK] {
            let shown = address_html(link)
                .into_string()
                .replace("<wbr>", "")
                .replace(SPAN, "")
                .replace("</span>", "");
            assert_eq!(shown, link);
        }
    }

    #[test]
    fn no_part_holds_an_invisible_character() {
        let parts = [
            invitation(INVITE_LINK, GATEWAY),
            reset(RESET_LINK, GATEWAY),
            new_connection(DISCONNECT_LINK, &connection(), GATEWAY),
        ];
        for part in parts {
            for text in [&part.text, &part.html] {
                assert!(!text.contains(INVISIBLE), "{text}");
            }
        }
    }

    #[test]
    fn the_new_connection_html_escapes_the_server_and_the_destination() {
        let shown = Connection {
            server: "<i>&\"x",
            destination: "a<b>.example.com",
            time: "21 November 2026, 14:05 UTC",
        };
        let html = new_connection(DISCONNECT_LINK, &shown, GATEWAY).html;
        assert!(!html.contains("<i>"));
        assert!(html.contains("&lt;i&gt;&amp;&quot;x"));
        assert!(!html.contains("<b>"));
        assert!(html.contains("a&lt;b&gt;"));
    }

    #[test]
    fn the_public_host_keeps_a_port_only_when_the_address_writes_one() {
        assert_eq!(
            host_and_port("https://gateway.example.com"),
            "gateway.example.com"
        );
        assert_eq!(host_and_port("http://127.0.0.1:8717"), "127.0.0.1:8717");
        assert_eq!(
            host_and_port("https://gateway.example.com/"),
            "gateway.example.com"
        );
        assert_eq!(host_and_port("http://[::1]:8717"), "[::1]:8717");
    }
}
