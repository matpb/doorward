//! The filters of the activity page and its export, read from the query string, and the rows they
//! match as one WHERE clause whose values are bound, never written into the SQL.

use std::collections::HashSet;

use rusqlite::types::Value;
use time::{Date, Month};

/// The detail of a tool result that reports an error: the text `proxy::stream` records. Its match
/// with a real call is checked by `every_event_key_selects_its_kinds` in tests/s94_activity_filters.rs.
pub const TOOL_ERROR: &str = "the tool reported an error";
const DAY: i64 = 86_400;

/// The keys of the event filter with their labels, in the order the form lists them.
pub const EVENTS: [(&str, &str); 10] = [
    ("tool_call", "Tool call"),
    ("tool_refused", "Tool call refused"),
    ("tool_failed", "Tool call failed"),
    ("sign_in", "Sign-in"),
    ("sign_in_refused", "Sign-in refused"),
    ("client", "Client connection"),
    ("admin_change", "Admin change"),
    ("invitation", "Invitation"),
    ("account", "Account change"),
    ("other", "Other"),
];

/// The keys of the period filter with their labels, in the order the form lists them.
pub const PERIODS: [(&str, &str); 6] = [
    ("all", "All time"),
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("90d", "Last 90 days"),
    ("custom", "Custom dates"),
];

/// The filter values of a query string. An absent or empty value is no filter. `page` numbers the
/// page and is not a filter.
#[derive(Clone, Default)]
pub struct Filters {
    pub period: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub event: Option<String>,
    pub user: Option<String>,
    pub server: Option<String>,
    pub tool: Option<String>,
    pub client: Option<String>,
    pub q: Option<String>,
    pub page: Option<String>,
}

impl Filters {
    /// The first value of each key of a raw query string. Other keys are ignored.
    pub fn of(raw: Option<&str>) -> Filters {
        let mut filters = Filters::default();
        let mut seen = HashSet::new();
        for (key, value) in form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
            if !seen.insert(key.to_string()) {
                continue;
            }
            let slot = match key.as_ref() {
                "period" => &mut filters.period,
                "from" => &mut filters.from,
                "to" => &mut filters.to,
                "event" => &mut filters.event,
                "user" => &mut filters.user,
                "server" => &mut filters.server,
                "tool" => &mut filters.tool,
                "client" => &mut filters.client,
                "q" => &mut filters.q,
                "page" => &mut filters.page,
                _ => continue,
            };
            if !value.is_empty() {
                *slot = Some(value.into_owned());
            }
        }
        filters
    }

    /// The set filters as (key, value) in the order a link writes them. `page` is not among them.
    pub fn pairs(&self) -> Vec<(&'static str, &str)> {
        [
            ("period", &self.period),
            ("from", &self.from),
            ("to", &self.to),
            ("event", &self.event),
            ("user", &self.user),
            ("server", &self.server),
            ("tool", &self.tool),
            ("client", &self.client),
            ("q", &self.q),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.as_deref().map(|value| (key, value)))
        .collect()
    }

    /// Whether the period is set to something other than all time.
    pub fn period_is_set(&self) -> bool {
        self.period.as_deref().is_some_and(|period| period != "all")
    }

    pub fn is_custom(&self) -> bool {
        self.period.as_deref() == Some("custom")
    }

    /// The user filter as an id; None when it is absent or is not a number.
    pub fn user_id(&self) -> Option<i64> {
        self.user.as_deref().and_then(|text| text.parse().ok())
    }

    /// The server filter as an id; None when it is absent or is not a number.
    pub fn server_id(&self) -> Option<i64> {
        self.server.as_deref().and_then(|text| text.parse().ok())
    }
}

/// The conditions a row must meet, with the values of their `?` placeholders in order.
#[derive(Clone, Default)]
pub struct Criteria {
    conditions: Vec<String>,
    values: Vec<Value>,
}

impl Criteria {
    /// Adds one condition. Its `?` placeholders take `values` in order.
    pub fn add(&mut self, condition: &str, values: Vec<Value>) {
        debug_assert_eq!(condition.matches('?').count(), values.len());
        self.conditions.push(format!("({condition})"));
        self.values.extend(values);
    }

    /// The WHERE clause, with its leading space, or nothing when there is no condition.
    pub fn clause(&self) -> String {
        if self.conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.conditions.join(" AND "))
        }
    }

    /// The bound values, in the order of the placeholders.
    pub fn values(&self) -> &[Value] {
        &self.values
    }
}

/// The conditions of the filters as they stand at `now`, a unix time. A value that names nothing
/// adds the condition `0`, which no row meets.
pub fn criteria(filters: &Filters, now: i64) -> Criteria {
    let mut scope = Criteria::default();
    period(&mut scope, filters, now);
    if let Some(event) = filters.event.as_deref() {
        event_condition(&mut scope, event);
    }
    if let Some(user) = filters.user.as_deref() {
        id_condition(&mut scope, "user_id", user);
    }
    if let Some(server) = filters.server.as_deref() {
        id_condition(&mut scope, "server_id", server);
    }
    if let Some(tool) = filters.tool.as_deref() {
        scope.add("tool = ?", vec![text(tool)]);
    }
    if let Some(client) = filters.client.as_deref() {
        scope.add("client = ?", vec![text(client)]);
    }
    if let Some(q) = filters.q.as_deref() {
        search(&mut scope, q);
    }
    scope
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn nothing(scope: &mut Criteria) {
    scope.add("0", Vec::new());
}

fn period(scope: &mut Criteria, filters: &Filters, now: i64) {
    let seconds = match filters.period.as_deref() {
        None | Some("all") => return,
        Some("24h") => DAY,
        Some("7d") => 7 * DAY,
        Some("30d") => 30 * DAY,
        Some("90d") => 90 * DAY,
        Some("custom") => return custom(scope, filters),
        Some(_) => return nothing(scope),
    };
    scope.add("at >= ?", vec![Value::Integer(now.saturating_sub(seconds))]);
}

/// The days from the first to the last, both UTC and both whole: from the first second of the first
/// day up to, not including, the first second after the last day.
fn custom(scope: &mut Criteria, filters: &Filters) {
    let (Some(first), Some(last)) = (
        parse_day(filters.from.as_deref()),
        parse_day(filters.to.as_deref()),
    ) else {
        return nothing(scope);
    };
    let start = Value::Integer(day_start(first));
    match last.next_day() {
        Some(after) => scope.add(
            "at >= ? AND at < ?",
            vec![start, Value::Integer(day_start(after))],
        ),
        None => scope.add("at >= ?", vec![start]),
    }
}

/// The first second of a UTC day, as a unix time.
fn day_start(day: Date) -> i64 {
    day.midnight().assume_utc().unix_timestamp()
}

/// A day written `YYYY-MM-DD`, or None when the text is missing or is not a day that exists.
pub fn parse_day(text: Option<&str>) -> Option<Date> {
    let mut parts = text?.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !digits(year, 4) || !digits(month, 2) || !digits(day, 2) {
        return None;
    }
    let month = Month::try_from(month.parse::<u8>().ok()?).ok()?;
    Date::from_calendar_date(year.parse().ok()?, month, day.parse().ok()?).ok()
}

/// Exactly `len` ASCII digits.
fn digits(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// `column = id` for a number; a text that is not a number names no row.
fn id_condition(scope: &mut Criteria, column: &str, text: &str) {
    match text.parse::<i64>() {
        Ok(id) => scope.add(&format!("{column} = ?"), vec![Value::Integer(id)]),
        Err(_) => nothing(scope),
    }
}

/// The rows of one event, by kind and, for tool calls, by decision, outcome and tool-error marker.
/// A key that names no event is no row.
fn event_condition(scope: &mut Criteria, key: &str) {
    let (sql, values) = match key {
        "tool_call" => (
            "kind = 'tool_call' AND decision <> 'deny' AND outcome = 'ok' AND detail <> ?",
            vec![text(TOOL_ERROR)],
        ),
        "tool_refused" => ("kind = 'tool_call' AND decision = 'deny'", Vec::new()),
        "tool_failed" => (
            "kind = 'tool_call' AND decision <> 'deny' AND (outcome <> 'ok' OR detail = ?)",
            vec![text(TOOL_ERROR)],
        ),
        "sign_in" => ("kind = 'login'", Vec::new()),
        "sign_in_refused" => ("kind = 'login_failed'", Vec::new()),
        "client" => (
            "kind IN ('client_connected', 'client_disconnected')",
            Vec::new(),
        ),
        "admin_change" => ("kind = 'admin_change'", Vec::new()),
        "invitation" => ("kind = 'invitation'", Vec::new()),
        "account" => (
            "kind IN ('owner_created', 'reset', 'password_change')",
            Vec::new(),
        ),
        "other" => (
            "kind NOT IN ('tool_call', 'login', 'login_failed', 'client_connected', \
             'client_disconnected', 'admin_change', 'invitation', 'owner_created', 'reset', \
             'password_change')",
            Vec::new(),
        ),
        _ => return nothing(scope),
    };
    scope.add(sql, values);
}

/// Substring match on the user, server, tool, client and detail; SQLite's LIKE folds ASCII case only.
/// The pattern's `%`, `_` and `\` are escaped, so they match themselves.
fn search(scope: &mut Criteria, q: &str) {
    let pattern = text(&format!("%{}%", escape_like(q)));
    scope.add(
        "user_email LIKE ? ESCAPE '\\' OR server_slug LIKE ? ESCAPE '\\' OR tool LIKE ? ESCAPE '\\' \
         OR client LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\'",
        vec![pattern; 5],
    );
}

/// The text with `\`, `%` and `_` escaped, for a LIKE pattern whose escape character is `\`.
pub fn escape_like(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_day_is_four_two_two_digits_and_must_exist() {
        assert_eq!(
            parse_day(Some("2030-01-05")),
            Date::from_calendar_date(2030, Month::January, 5).ok()
        );
        for text in [
            "2030-1-5",
            "30-01-05",
            "2030-02-30",
            "2030-13-01",
            "2030-00-10",
            "2030-01-00",
            "2030-01-05x",
            " 2030-01-05",
            "2030-01-05-",
            "2030/01/05",
            "",
        ] {
            assert_eq!(parse_day(Some(text)), None, "{text:?} is not a day");
        }
        assert_eq!(parse_day(None), None, "a missing day is no day");
    }

    #[test]
    fn like_wildcards_are_escaped_and_backslash_too() {
        assert_eq!(escape_like(r"a_b%c\d"), r"a\_b\%c\\d");
        assert_eq!(escape_like("plain"), "plain");
    }

    #[test]
    fn the_first_value_of_a_key_is_taken_and_an_empty_first_value_is_no_filter() {
        let filters = Filters::of(Some("user=&user=2&server=3&server=4&page=2&page=1&other=x"));
        assert_eq!(filters.user, None, "an empty first value is no filter");
        assert_eq!(filters.server.as_deref(), Some("3"), "the first value wins");
        assert_eq!(
            filters.page.as_deref(),
            Some("2"),
            "the first page value wins"
        );
        let none = Filters::of(None);
        assert!(none.pairs().is_empty(), "no query means no filter");
    }

    #[test]
    fn a_rolling_period_is_a_bound_value_counted_back_from_now() {
        let filters = Filters {
            period: Some("24h".into()),
            ..Filters::default()
        };
        let scope = criteria(&filters, 1_000_000);
        assert_eq!(scope.clause(), " WHERE (at >= ?)");
        assert_eq!(scope.values(), &[Value::Integer(1_000_000 - DAY)]);
    }

    #[test]
    fn an_unknown_event_or_period_or_a_bad_day_is_the_condition_zero() {
        for filters in [
            Filters {
                event: Some("bogus".into()),
                ..Filters::default()
            },
            Filters {
                period: Some("weekly".into()),
                ..Filters::default()
            },
            Filters {
                period: Some("custom".into()),
                from: Some("2030-01-05".into()),
                ..Filters::default()
            },
            Filters {
                user: Some("abc".into()),
                ..Filters::default()
            },
        ] {
            let scope = criteria(&filters, 0);
            assert!(scope.clause().ends_with("(0)"), "{}", scope.clause());
        }
    }

    #[test]
    fn a_search_binds_one_escaped_pattern_for_each_column() {
        let filters = Filters {
            q: Some("50%_".into()),
            ..Filters::default()
        };
        let scope = criteria(&filters, 0);
        assert_eq!(scope.values().len(), 5);
        assert!(
            scope
                .values()
                .iter()
                .all(|value| value == &text(r"%50\%\_%"))
        );
        assert!(
            !scope.clause().contains("50"),
            "the text is bound, not written into the SQL"
        );
    }

    #[test]
    fn a_custom_range_runs_from_the_first_second_to_before_the_day_after_the_last() {
        let filters = Filters {
            period: Some("custom".into()),
            from: Some("2030-01-05".into()),
            to: Some("2030-01-06".into()),
            ..Filters::default()
        };
        let first = day_start(Date::from_calendar_date(2030, Month::January, 5).expect("a day"));
        let after = day_start(Date::from_calendar_date(2030, Month::January, 7).expect("a day"));
        let scope = criteria(&filters, 0);
        assert_eq!(scope.clause(), " WHERE (at >= ? AND at < ?)");
        assert_eq!(
            scope.values(),
            &[Value::Integer(first), Value::Integer(after)]
        );
    }
}
