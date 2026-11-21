//! Small markup helpers shared by the pages: status pills, notices and identifiers.

use maud::{Markup, PreEscaped, html};

/// A status word with a marker. tone: "ok" | "bad" | "warn" | "muted".
pub fn pill(tone: &str, text: &str) -> Markup {
    html! {
        span class="state" data-pill data-tone=(tone) { (text) }
    }
}

/// Text with a `<wbr>` where a long identifier may break: after `_ / ? & =`, before `@`
/// and before a `.` that a letter or digit follows.
pub fn breakable(text: &str) -> Markup {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (index, &ch) in chars.iter().enumerate() {
        let next = chars.get(index + 1).copied();
        if ch == '@' || (ch == '.' && next.is_some_and(|c| c.is_ascii_alphanumeric())) {
            out.push_str("<wbr>");
        }
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
        let breaks_after = matches!(ch, '_' | '?' | '=' | '&') || (ch == '/' && next != Some('/'));
        if breaks_after && next.is_some() {
            out.push_str("<wbr>");
        }
    }
    PreEscaped(out)
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
            r#"<span class="state" data-pill data-tone="ok">Active</span>"#
        );
    }

    #[test]
    fn a_pill_escapes_its_text() {
        assert_eq!(
            pill("bad", "<b>&</b>").into_string(),
            r#"<span class="state" data-pill data-tone="bad">&lt;b&gt;&amp;&lt;/b&gt;</span>"#
        );
    }

    #[test]
    fn breakable_breaks_identifiers_after_underscores() {
        assert_eq!(
            breakable("create_pull_request").into_string(),
            "create_<wbr>pull_<wbr>request"
        );
    }

    #[test]
    fn breakable_breaks_addresses_before_the_at_and_the_dots() {
        assert_eq!(
            breakable("li.wei@tessellate.example.com").into_string(),
            "li<wbr>.wei<wbr>@tessellate<wbr>.example<wbr>.com"
        );
    }

    #[test]
    fn breakable_escapes_then_breaks_after_an_ampersand() {
        assert_eq!(breakable("a<b&c").into_string(), "a&lt;b&amp;<wbr>c");
    }

    #[test]
    fn breakable_never_breaks_after_the_last_character_or_before_a_dot_without_a_letter() {
        assert_eq!(breakable("v1.").into_string(), "v1.");
        assert_eq!(breakable("a_").into_string(), "a_");
        assert_eq!(breakable("a/").into_string(), "a/");
        assert_eq!(breakable("a..b").into_string(), "a.<wbr>.b");
    }

    #[test]
    fn breakable_breaks_after_a_slash_only_when_no_slash_follows_it() {
        assert_eq!(breakable("//x").into_string(), "//<wbr>x");
        assert_eq!(breakable("a/b").into_string(), "a/<wbr>b");
    }

    #[test]
    fn breakable_of_nothing_is_empty() {
        assert_eq!(breakable("").into_string(), "");
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
