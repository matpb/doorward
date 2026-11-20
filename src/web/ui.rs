//! Small markup helpers shared by the pages: status pills and notices.

use maud::{Markup, html};

/// A status word with a marker. tone: "ok" | "bad" | "warn" | "muted".
pub fn pill(tone: &str, text: &str) -> Markup {
    html! {
        span class="pill" data-pill data-tone=(tone) { (text) }
    }
}

/// A boxed message. kind: "ok" | "warning" | "error".
pub fn notice(kind: &str, body: Markup) -> Markup {
    html! {
        div class="notice" data-notice=(kind) { (body) }
    }
}

#[cfg(test)]
mod tests {
    use maud::html;

    use super::*;

    #[test]
    fn a_pill_is_a_span_with_its_tone_and_its_text() {
        assert_eq!(
            pill("ok", "Active").into_string(),
            r#"<span class="pill" data-pill data-tone="ok">Active</span>"#
        );
    }

    #[test]
    fn a_pill_escapes_its_text() {
        assert_eq!(
            pill("bad", "<b>&</b>").into_string(),
            r#"<span class="pill" data-pill data-tone="bad">&lt;b&gt;&amp;&lt;/b&gt;</span>"#
        );
    }

    #[test]
    fn a_notice_is_a_div_with_its_kind_around_its_body() {
        assert_eq!(
            notice("warning", html! { p { "Check it." } }).into_string(),
            r#"<div class="notice" data-notice="warning"><p>Check it.</p></div>"#
        );
    }

    #[test]
    fn a_notice_keeps_plain_text_escaped() {
        assert_eq!(
            notice("error", html! { "a < b" }).into_string(),
            r#"<div class="notice" data-notice="error">a &lt; b</div>"#
        );
    }
}
