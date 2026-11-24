//! Small markup helpers shared by the pages: status pills, notices and identifiers.

use maud::{Markup, Render, html};

/// A status word with a marker. tone: "ok" | "bad" | "warn" | "muted".
pub fn pill(tone: &str, text: &str) -> Markup {
    html! {
        span class="state" data-pill data-tone=(tone) { (text) }
    }
}

/// Text with a `<wbr>` where a long identifier may break: after `_ / ? & =`, before `@`
/// and before a `.` that a letter or digit follows. Maud escapes every piece of the text.
pub fn breakable(text: &str) -> Markup {
    let chars: Vec<char> = text.chars().collect();
    // breaks[k] is true when a `<wbr>` sits before chars[k].
    let mut breaks = vec![false; chars.len() + 1];
    for (index, &ch) in chars.iter().enumerate() {
        let next = chars.get(index + 1).copied();
        if ch == '@' || (ch == '.' && next.is_some_and(|c| c.is_ascii_alphanumeric())) {
            breaks[index] = true;
        }
        let breaks_after = matches!(ch, '_' | '?' | '=' | '&') || (ch == '/' && next != Some('/'));
        if breaks_after && next.is_some() {
            breaks[index + 1] = true;
        }
    }
    // Each piece is the text up to the next break, with whether a `<wbr>` precedes it.
    let mut pieces: Vec<(bool, String)> = Vec::new();
    for (index, &ch) in chars.iter().enumerate() {
        if breaks[index] || pieces.is_empty() {
            pieces.push((breaks[index], String::new()));
        }
        if let Some((_, piece)) = pieces.last_mut() {
            piece.push(ch);
        }
    }
    html! {
        @for (wrap, piece) in &pieces {
            @if *wrap {
                wbr;
            }
            (piece)
        }
    }
}

/// A name that may break only after a hyphen: a `wbr` follows each `-` that is not the last character.
pub fn hyphenated(text: &str) -> Markup {
    let pieces: Vec<&str> = text.split_inclusive('-').collect();
    html! {
        @for (index, piece) in pieces.iter().enumerate() {
            (piece)
            @if index + 1 < pieces.len() {
                wbr;
            }
        }
    }
}

/// A web address in a table cell: its origin, then each path piece in a `span.whole` behind a `wbr`.
/// The cuts are on ASCII `://` and `/` only, so the text is unchanged.
pub fn web_address(text: &str) -> Markup {
    let host_start = text.find("://").map_or(0, |index| index + 3);
    let Some(origin_len) = text[host_start..]
        .find('/')
        .map(|index| host_start + index + 1)
    else {
        return breakable(text);
    };
    let (origin, path) = text.split_at(origin_len);
    html! {
        (breakable(origin))
        @for piece in path.split_inclusive('/') {
            wbr;
            span.whole { (breakable(piece)) }
        }
    }
}

/// A host or web address in pieces: a `code.address` of one span per piece, with a `wbr` between two
/// pieces. Cuts fall before each `.` and after each `/` that ends a piece, never inside `://`.
pub fn address(text: &str) -> Markup {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut pieces: Vec<&str> = Vec::new();
    let mut start = 0;
    for (position, &(index, ch)) in chars.iter().enumerate() {
        let previous = position.checked_sub(1).map(|before| chars[before].1);
        let next = chars.get(position + 1).map(|&(_, after)| after);
        if ch == '.' && index > start {
            pieces.push(&text[start..index]);
            start = index;
        }
        if ch == '/' && next.is_some_and(|after| after != '/') && previous != Some('/') {
            let end = index + ch.len_utf8();
            pieces.push(&text[start..end]);
            start = end;
        }
    }
    if start < text.len() {
        pieces.push(&text[start..]);
    }
    html! {
        code.address {
            @for (position, piece) in pieces.iter().enumerate() {
                @if position > 0 {
                    wbr;
                }
                span { (piece) }
            }
        }
    }
}

/// The notice above a refused form: its lead-in when it has one, the refusal when it has a message,
/// and a link to the field it is about, given as (id, label), when it is about one field.
pub fn refused<'a>(
    lead: Option<&str>,
    message: impl Into<Option<&'a str>>,
    field: Option<(&str, &str)>,
) -> Markup {
    refused_markup(lead, message.into().map(|text| html! { (text) }), field)
}

/// `refused` with its refusal as markup, so a header name in the reason can be set in code.
pub fn refused_markup(
    lead: Option<&str>,
    message: Option<Markup>,
    field: Option<(&str, &str)>,
) -> Markup {
    html! {
        div.notice data-notice="error" role="alert" {
            p {
                @if let Some(lead) = lead {
                    strong { (lead) }
                }
                @if let Some(message) = message {
                    @if lead.is_some() {
                        " "
                    }
                    (message)
                }
                @if let Some((id, label)) = field {
                    " "
                    a href=(format!("#{id}")) { "Go to the " (label) " field" }
                }
            }
        }
    }
}

/// The aria-invalid of a control: "true" when a refusal is about it.
pub fn invalid(error: Option<&str>) -> Option<&'static str> {
    error.map(|_| "true")
}

/// The note under a field: the refusal about it when there is one, else its hint, if it has one.
pub fn note_under<'a>(error: Option<&'a str>, hint: Option<&'a str>) -> Note<'a> {
    match (error, hint) {
        (Some(text), _) => Note::Error(text),
        (None, Some(text)) => Note::Hint(text),
        (None, None) => Note::None,
    }
}

/// The longest value a refused form sends back, in characters, when its field has no limit of its own.
pub const SENT_BACK_LIMIT: usize = 500;
/// The longest address a refused email field sends back: the longest address that is stored.
pub const EMAIL_SENT_BACK_LIMIT: usize = 254;

/// A posted value as a refused form shows it again: "" when the posted value is longer than
/// `limit` characters, else the value without its control characters.
pub fn sent_back(value: &str, limit: usize) -> String {
    if value.chars().count() > limit {
        return String::new();
    }
    value.chars().filter(|c| !c.is_control()).collect()
}

/// The hint under a secret field when a refused post carried a secret, which is never sent back.
pub const RE_ENTER_HINT: &str = "Enter it again: a secret is never sent back.";

/// A boxed message. kind: "ok" | "warning" | "error".
pub fn notice(kind: &str, body: Markup) -> Markup {
    html! {
        div class="notice" data-notice=(kind) { (body) }
    }
}

/// An email address in the sans face: its local part and its `@domain` are each a span, with a
/// `<wbr>` between them, split at the last `@`.
pub fn email(address: &str) -> Markup {
    html! {
        span.email {
            @if let Some((local, domain)) = address.rsplit_once('@') {
                span { (breakable(local)) }
                wbr;
                span { "@" (breakable(domain)) }
            } @else {
                span { (breakable(address)) }
            }
        }
    }
}

/// A time as a `time` element. `plain` is a time as the activity page writes it, `D Mon YYYY
/// HH:MM:SS UTC`; the date and the clock are each unbreakable, and `zone` adds the unit " UTC".
pub fn time_cell(datetime: &str, plain: &str, zone: bool) -> Markup {
    let words = plain.strip_suffix(" UTC").unwrap_or(plain);
    let (date, clock) = words.rsplit_once(' ').unwrap_or((words, ""));
    html! {
        time datetime=(datetime) {
            span.nowrap { (date) }
            " "
            span.nowrap {
                (clock)
                @if zone { span.unit { " UTC" } }
            }
        }
    }
}

/// A count with its unit kept beside it: the number, then a unit span with the word for it.
pub fn count_with_unit(count: i64, one: &str, many: &str) -> Markup {
    let word = if count == 1 { one } else { many };
    html! { (count) span.unit { " " (word) } }
}

/// What sits under a field's control. The id of a hint or an error is the field's id with
/// `-hint` or `-error`; `Below` carries its own id and the markup of `div.below`.
pub enum Note<'a> {
    None,
    Hint(&'a str),
    /// A hint whose text holds markup, such as a header name set in code.
    HintMarkup(Markup),
    Error(&'a str),
    Below(&'a str, Markup),
}

impl Note<'_> {
    /// The id the control of field `id` names in aria-describedby, or None when nothing describes it.
    pub fn describer(&self, id: &str) -> Option<String> {
        match self {
            Note::None => None,
            Note::Hint(_) | Note::HintMarkup(_) => Some(format!("{id}-hint")),
            Note::Error(_) => Some(format!("{id}-error")),
            Note::Below(describer, _) => Some((*describer).to_owned()),
        }
    }
}

/// A count with a thousands comma between each group of three digits, a minus sign first if negative.
pub fn thousands(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if value < 0 {
        out.push('-');
    }
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// One labelled field whose div also carries `classes`, as `field` does otherwise.
pub fn field_in(classes: &str, id: &str, label: &str, control: Markup, note: Note<'_>) -> Markup {
    html! {
        div class=(format!("field {classes}")) {
            label for=(id) { (label) }
            (control)
            (note_markup(id, note))
        }
    }
}

/// One labelled field: its label, then the control, then its note. `optional` adds "(optional)".
/// The control names the note in aria-describedby.
pub fn field(id: &str, label: &str, optional: bool, control: Markup, note: Note<'_>) -> Markup {
    html! {
        div.field {
            label for=(id) {
                (label)
                @if optional { " " span.optional { "(optional)" } }
            }
            (control)
            (note_markup(id, note))
        }
    }
}

/// The note of a field as markup.
pub fn note_markup(id: &str, note: Note<'_>) -> Markup {
    match note {
        Note::None => html! {},
        Note::Hint(text) => hint(&format!("{id}-hint"), text),
        Note::HintMarkup(markup) => html! { p.hint id=(format!("{id}-hint")) { (markup) } },
        Note::Error(text) => field_error(&format!("{id}-error"), text),
        Note::Below(_, markup) => html! { div.below { (markup) } },
    }
}

/// A hint under a control: a `p.hint` with the id the control names in aria-describedby.
pub fn hint(id: &str, text: &str) -> Markup {
    html! { p.hint id=(id) { (text) } }
}

/// The error that refused a field, under it: a `p.field-error` with the id its control names.
pub fn field_error(id: &str, text: &str) -> Markup {
    html! { p.field-error id=(id) { (text) } }
}

/// A checkbox beside its label, with an optional hint under the label. The checkbox has no value
/// unless one is given, so a form posts "on" for it.
pub fn check(
    id: &str,
    name: &str,
    value: Option<&str>,
    checked: bool,
    label: impl Render,
    note: Option<&str>,
) -> Markup {
    let hint_id = format!("{id}-hint");
    let described = note.map(|_| hint_id.as_str());
    html! {
        div.check {
            input type="checkbox" id=(id) name=(name) value=[value] checked[checked] aria-describedby=[described];
            label for=(id) { (label) }
            @if let Some(text) = note {
                (hint(&hint_id, text))
            }
        }
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
    fn hyphenated_breaks_after_each_hyphen_and_nowhere_else() {
        assert_eq!(
            hyphenated("X-Atlassian-Api-Token").into_string(),
            "X-<wbr>Atlassian-<wbr>Api-<wbr>Token"
        );
        assert_eq!(
            hyphenated("create_pull.request").into_string(),
            "create_pull.request"
        );
        assert_eq!(hyphenated("a-").into_string(), "a-");
        assert_eq!(hyphenated("").into_string(), "");
    }

    #[test]
    fn hyphenated_escapes_its_text() {
        assert_eq!(hyphenated("a<-b").into_string(), "a&lt;-<wbr>b");
    }

    #[test]
    fn breakable_of_nothing_is_empty() {
        assert_eq!(breakable("").into_string(), "");
    }

    #[test]
    fn breakable_escapes_quotes_and_markup_in_every_piece() {
        assert_eq!(
            breakable("\"<a>\"_\"<\"").into_string(),
            "&quot;&lt;a&gt;&quot;_<wbr>&quot;&lt;&quot;"
        );
    }

    #[test]
    fn an_address_breaks_before_each_dot_and_after_each_path_slash() {
        assert_eq!(
            address("atlassian.example.com").into_string(),
            r#"<code class="address"><span>atlassian</span><wbr><span>.example</span><wbr><span>.com</span></code>"#
        );
        assert_eq!(
            address("https://gateway.example.com/account").into_string(),
            r#"<code class="address"><span>https://gateway</span><wbr><span>.example</span><wbr><span>.com/</span><wbr><span>account</span></code>"#
        );
    }

    #[test]
    fn an_address_keeps_its_text_and_escapes_it() {
        assert_eq!(
            address("a<b.example").into_string(),
            r#"<code class="address"><span>a&lt;b</span><wbr><span>.example</span></code>"#
        );
        assert_eq!(
            address("").into_string(),
            r#"<code class="address"></code>"#
        );
    }

    #[test]
    fn a_refusal_with_a_field_links_to_it_after_its_lead_in() {
        assert_eq!(
            refused(
                Some("The rule was not added."),
                "Choose the effect allow or deny.",
                Some(("rule-effect", "effect"))
            )
            .into_string(),
            r##"<div class="notice" data-notice="error" role="alert"><p><strong>The rule was not added.</strong> Choose the effect allow or deny. <a href="#rule-effect">Go to the effect field</a></p></div>"##
        );
    }

    #[test]
    fn a_refusal_without_a_lead_or_a_field_is_its_message_alone() {
        assert_eq!(
            refused(None, "Choose only servers that exist.", None).into_string(),
            r#"<div class="notice" data-notice="error" role="alert"><p>Choose only servers that exist.</p></div>"#
        );
    }

    #[test]
    fn a_refusal_whose_reason_is_markup_keeps_the_markup_before_its_link() {
        assert_eq!(
            refused_markup(
                Some("The header was not added."),
                Some(html! { code { "X-Trace-Id" } " cannot be used." }),
                Some(("header-name", "header name"))
            )
            .into_string(),
            r##"<div class="notice" data-notice="error" role="alert"><p><strong>The header was not added.</strong> <code>X-Trace-Id</code> cannot be used. <a href="#header-name">Go to the header name field</a></p></div>"##
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

    #[test]
    fn an_email_splits_into_a_local_span_a_wbr_and_an_at_domain_span() {
        assert_eq!(
            email("tomasz.wisniewski@example.com").into_string(),
            r#"<span class="email"><span>tomasz<wbr>.wisniewski</span><wbr><span>@example<wbr>.com</span></span>"#
        );
        assert_eq!(
            email("bob@example.com").into_string(),
            r#"<span class="email"><span>bob</span><wbr><span>@example<wbr>.com</span></span>"#
        );
        assert_eq!(
            email("oluwaseun.adebayo-richardson@contractors.example.com").into_string(),
            r#"<span class="email"><span>oluwaseun<wbr>.adebayo-richardson</span><wbr><span>@contractors<wbr>.example<wbr>.com</span></span>"#
        );
    }

    #[test]
    fn an_email_escapes_markup_characters_in_its_local_part() {
        assert_eq!(
            email("x&y<z@example.com").into_string(),
            r#"<span class="email"><span>x&amp;<wbr>y&lt;z</span><wbr><span>@example<wbr>.com</span></span>"#
        );
    }

    #[test]
    fn an_email_with_two_ats_splits_at_the_last_one() {
        assert_eq!(
            email("x@y@example.com").into_string(),
            r#"<span class="email"><span>x<wbr>@y</span><wbr><span>@example<wbr>.com</span></span>"#
        );
    }

    #[test]
    fn an_email_without_an_at_is_one_inner_span_with_no_split() {
        assert_eq!(
            email("deploy-bot").into_string(),
            r#"<span class="email"><span>deploy-bot</span></span>"#
        );
    }

    #[test]
    fn a_time_keeps_its_datetime_and_splits_date_and_clock_into_nowrap_spans() {
        assert_eq!(
            time_cell("2026-11-20T14:32:07Z", "20 Nov 2026 14:32:07 UTC", true).into_string(),
            r#"<time datetime="2026-11-20T14:32:07Z"><span class="nowrap">20 Nov 2026</span> <span class="nowrap">14:32:07<span class="unit"> UTC</span></span></time>"#
        );
    }

    #[test]
    fn a_time_without_zone_has_no_unit_span() {
        assert_eq!(
            time_cell("2026-11-20T14:32:07Z", "20 Nov 2026 14:32:07 UTC", false).into_string(),
            r#"<time datetime="2026-11-20T14:32:07Z"><span class="nowrap">20 Nov 2026</span> <span class="nowrap">14:32:07</span></time>"#
        );
    }

    #[test]
    fn a_count_keeps_its_unit_in_a_span_in_the_singular_and_the_plural() {
        assert_eq!(
            count_with_unit(3, "tool", "tools").into_string(),
            r#"3<span class="unit"> tools</span>"#
        );
        assert_eq!(
            count_with_unit(1, "user", "users").into_string(),
            r#"1<span class="unit"> user</span>"#
        );
        assert_eq!(
            count_with_unit(0, "tool", "tools").into_string(),
            r#"0<span class="unit"> tools</span>"#
        );
    }

    #[test]
    fn a_field_is_a_label_then_its_control_then_its_hint() {
        let control = html! {
            input id="server-slug" name="slug" type="text" class="mono" aria-describedby="server-slug-hint";
        };
        assert_eq!(
            field(
                "server-slug",
                "Path",
                false,
                control,
                Note::Hint("Letters.")
            )
            .into_string(),
            r#"<div class="field"><label for="server-slug">Path</label><input id="server-slug" name="slug" type="text" class="mono" aria-describedby="server-slug-hint"><p class="hint" id="server-slug-hint">Letters.</p></div>"#
        );
    }

    #[test]
    fn an_optional_field_marks_its_label_with_a_span() {
        let control = html! { input id="secret-name" name="secret_header_name" type="text"; };
        assert_eq!(
            field("secret-name", "Header name", true, control, Note::None).into_string(),
            r#"<div class="field"><label for="secret-name">Header name <span class="optional">(optional)</span></label><input id="secret-name" name="secret_header_name" type="text"></div>"#
        );
    }

    #[test]
    fn a_refused_field_shows_its_error_in_place_of_the_hint() {
        let control = html! { input id="server-slug" name="slug" type="text" aria-invalid="true" aria-describedby="server-slug-error"; };
        assert_eq!(
            field(
                "server-slug",
                "Path",
                false,
                control,
                Note::Error("Another server already uses that path.")
            )
            .into_string(),
            r#"<div class="field"><label for="server-slug">Path</label><input id="server-slug" name="slug" type="text" aria-invalid="true" aria-describedby="server-slug-error"><p class="field-error" id="server-slug-error">Another server already uses that path.</p></div>"#
        );
    }

    #[test]
    fn a_field_note_below_the_control_is_wrapped_in_div_below() {
        let control = html! { input id="secret-value" name="secret_header_value" type="password"; };
        let below = html! {
            (hint("secret-value-hint", "Stored, never shown again. Leave empty to keep it. If you change the upstream address, enter it again."))
        };
        assert_eq!(
            field(
                "secret-value",
                "Header value",
                true,
                control,
                Note::Below("secret-value-hint", below)
            )
            .into_string(),
            r#"<div class="field"><label for="secret-value">Header value <span class="optional">(optional)</span></label><input id="secret-value" name="secret_header_value" type="password"><div class="below"><p class="hint" id="secret-value-hint">Stored, never shown again. Leave empty to keep it. If you change the upstream address, enter it again.</p></div></div>"#
        );
    }

    #[test]
    fn a_checkbox_row_is_an_input_beside_its_label_and_a_hint() {
        assert_eq!(
            check(
                "pass-resources",
                "pass_resources",
                None,
                true,
                "Pass resources to the upstream",
                Some("When off, clients get an empty list.")
            )
            .into_string(),
            r#"<div class="check"><input type="checkbox" id="pass-resources" name="pass_resources" checked aria-describedby="pass-resources-hint"><label for="pass-resources">Pass resources to the upstream</label><p class="hint" id="pass-resources-hint">When off, clients get an empty list.</p></div>"#
        );
    }

    #[test]
    fn a_checkbox_row_without_a_hint_names_no_description_and_can_carry_a_value() {
        assert_eq!(
            check(
                "user-7",
                "user_id",
                Some("7"),
                false,
                html! { "Priya" },
                None
            )
            .into_string(),
            r#"<div class="check"><input type="checkbox" id="user-7" name="user_id" value="7"><label for="user-7">Priya</label></div>"#
        );
    }

    #[test]
    fn a_sent_back_value_drops_its_control_characters() {
        assert_eq!(sent_back("a\u{7}b\tc\n", SENT_BACK_LIMIT), "abc");
        assert_eq!(sent_back("", SENT_BACK_LIMIT), "");
    }

    #[test]
    fn a_sent_back_value_keeps_up_to_its_limit_and_drops_a_longer_one() {
        assert_eq!(sent_back(&"x".repeat(500), 500), "x".repeat(500));
        assert_eq!(sent_back(&"x".repeat(501), 500), "");
    }

    #[test]
    fn a_sent_back_value_counts_characters_and_counts_control_characters_too() {
        assert_eq!(sent_back(&"é".repeat(3), 3), "ééé");
        assert_eq!(sent_back(&"é".repeat(4), 3), "");
        assert_eq!(sent_back(&format!("{}x", "\u{7}".repeat(3)), 4), "x");
        assert_eq!(sent_back(&format!("{}x", "\u{7}".repeat(3)), 3), "");
    }

    /// The text a web address shows once its markup is parsed.
    fn shown_text(text: &str) -> String {
        let markup = web_address(text).into_string();
        scraper::Html::parse_fragment(&markup)
            .root_element()
            .text()
            .collect()
    }

    /// The inputs a web address may hold: the sample, the other schemes and shapes, markup characters,
    /// non-ASCII text and a 2000 character piece.
    fn address_inputs() -> Vec<String> {
        [
            "https://claude.ai/api/mcp/auth_callback",
            "cursor://anysphere.cursor-retrieval/oauth/",
            "http://example.net/cb",
            "https://example.com",
            "https://example.com/",
            "no-scheme/path/x",
            "plain",
            "",
            "///",
            "https://example.com//a///b",
            "https://example.com/a<script>&\"x\"/b",
            "https://example.com/café/日本語/ünï",
        ]
        .iter()
        .map(|text| text.to_string())
        .chain([format!("https://example.com/{}", "auth_".repeat(400))])
        .collect()
    }

    #[test]
    fn a_web_address_breaks_after_each_slash_and_keeps_each_piece_whole() {
        assert_eq!(
            web_address("https://claude.ai/api/mcp/auth_callback").into_string(),
            r#"https://<wbr>claude<wbr>.ai/<wbr><span class="whole">api/</span><wbr><span class="whole">mcp/</span><wbr><span class="whole">auth_<wbr>callback</span>"#
        );
    }

    #[test]
    fn the_other_samples_break_as_the_prototype_does() {
        assert_eq!(
            web_address("cursor://anysphere.cursor-retrieval/oauth/").into_string(),
            r#"cursor://<wbr>anysphere<wbr>.cursor-retrieval/<wbr><span class="whole">oauth/</span>"#
        );
        assert_eq!(
            web_address("http://example.net/cb").into_string(),
            r#"http://<wbr>example<wbr>.net/<wbr><span class="whole">cb</span>"#
        );
        assert_eq!(
            web_address("https://example.com").into_string(),
            "https://<wbr>example<wbr>.com"
        );
        assert_eq!(
            web_address("https://example.com/").into_string(),
            "https://<wbr>example<wbr>.com/"
        );
        assert_eq!(
            web_address("no-scheme/path/x").into_string(),
            r#"no-scheme/<wbr><span class="whole">path/</span><wbr><span class="whole">x</span>"#
        );
        assert_eq!(web_address("plain").into_string(), "plain");
        assert_eq!(web_address("").into_string(), "");
    }

    #[test]
    fn empty_pieces_are_not_emitted_and_slashes_stay_as_pieces() {
        assert_eq!(
            web_address("https://example.com//a///b").into_string(),
            r#"https://<wbr>example<wbr>.com/<wbr><span class="whole">/</span><wbr><span class="whole">a/</span><wbr><span class="whole">/</span><wbr><span class="whole">/</span><wbr><span class="whole">b</span>"#
        );
        assert_eq!(
            web_address("///").into_string(),
            r#"/<wbr><span class="whole">/</span><wbr><span class="whole">/</span>"#
        );
    }

    #[test]
    fn markup_characters_in_a_piece_are_escaped() {
        assert_eq!(
            web_address("https://example.com/a<script>&\"x\"/b").into_string(),
            r#"https://<wbr>example<wbr>.com/<wbr><span class="whole">a&lt;script&gt;&amp;<wbr>&quot;x&quot;/</span><wbr><span class="whole">b</span>"#
        );
        assert!(
            !web_address("https://example.com/<script>")
                .into_string()
                .contains("<script")
        );
    }

    #[test]
    fn the_text_shown_is_the_text_given_for_every_input() {
        for input in address_inputs() {
            assert_eq!(
                shown_text(&input),
                input,
                "the text of {input:?} must be unchanged"
            );
        }
    }

    #[test]
    fn every_whole_span_follows_a_wbr_and_no_white_space_is_emitted() {
        for input in address_inputs() {
            let markup = web_address(&input).into_string();
            let doc = scraper::Html::parse_fragment(&markup);
            for node in doc.root_element().descendants() {
                if let Some(text) = node.value().as_text() {
                    assert!(
                        !text.chars().any(char::is_whitespace),
                        "the text of {input:?} must hold no white space between its tags"
                    );
                }
            }
            let selector = scraper::Selector::parse("span.whole").expect("selector");
            for span in doc.select(&selector) {
                let before = span
                    .prev_sibling()
                    .and_then(scraper::ElementRef::wrap)
                    .map(|element| element.value().name().to_owned());
                assert_eq!(
                    before.as_deref(),
                    Some("wbr"),
                    "each span.whole of {input:?} must follow a wbr"
                );
            }
        }
    }
}
