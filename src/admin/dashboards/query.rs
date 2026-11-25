//! The numbers of one chart: one scan of the activity rows its conditions select, folded in Rust.
//! The conditions are the Activity page's own, and no statement sorts, groups or windows its rows.

use std::collections::{HashMap, HashSet};

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, params_from_iter};
use time::OffsetDateTime;
use time::format_description;

use crate::admin::activity::filters::{Criteria, Filters, criteria};

use super::model::{ChartSpec, GroupBy, Metric, Period, TOP_COUNTS};

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

/// One time bucket: its label as the table writes it, and its value. A duration bucket with no call
/// has no value.
pub struct Bucket {
    pub label: String,
    pub value: Option<i64>,
}

/// One ranked category: its label, its value, and the Activity filters that show its rows.
pub struct Category {
    pub label: String,
    pub value: i64,
    /// The Activity filters of the row; None when the row has no key to filter by.
    pub link: Option<Vec<(&'static str, String)>>,
}

/// What a chart draws: time buckets, ranked categories, one number, or the unused tools.
pub enum Series {
    Buckets(Vec<Bucket>),
    Ranked(Vec<Category>),
    Number(Option<i64>),
    Unused(Vec<(String, String)>),
}

impl Series {
    /// Whether the series holds no activity: no category, no unused tool, no value, or only zeros.
    pub fn is_empty(&self) -> bool {
        match self {
            Series::Buckets(buckets) => buckets
                .iter()
                .all(|bucket| bucket.value.is_none_or(|value| value == 0)),
            Series::Ranked(categories) => categories.is_empty(),
            Series::Number(value) => value.is_none(),
            Series::Unused(tools) => tools.is_empty(),
        }
    }
}

/// The names of a chart's server, user and tool filters, as its caption names them.
#[derive(Default)]
pub struct Scope {
    pub server: Option<String>,
    pub user: Option<String>,
    pub tool: Option<String>,
}

/// The names of a chart's server, user and tool filters; a filter that names nothing is absent.
pub fn scope_of(conn: &Connection, spec: &ChartSpec) -> rusqlite::Result<Scope> {
    let server = match spec.server_id {
        Some(id) => conn
            .query_row("SELECT slug FROM servers WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?,
        None => None,
    };
    let user = match spec.user_id {
        Some(id) => conn
            .query_row("SELECT email FROM users WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?,
        None => None,
    };
    Ok(Scope {
        server,
        user,
        tool: spec.tool.clone(),
    })
}

/// A chart's series with the names its caption shows.
pub struct Drawn {
    pub series: Series,
    pub scope: Scope,
}

/// The series of a chart over `period` (the chart's own, or the dashboard's switch) at `now`, a unix time.
pub fn series(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    match (spec.metric, spec.group_by) {
        (Metric::UnusedTools, _) => unused(conn, spec, period, now),
        (_, GroupBy::Time) => time_series(conn, spec, period, now),
        (_, GroupBy::Nothing) => number(conn, spec, period, now),
        (_, group) => ranked(conn, spec, period, now, group),
    }
}

/// Every statement a chart runs, with its values, in the order `series` runs them.
#[cfg(test)]
pub fn statements(spec: &ChartSpec, period: Period, now: i64) -> Vec<(String, Vec<Value>)> {
    match (spec.metric, spec.group_by) {
        (Metric::UnusedTools, _) => vec![
            select(&scope(spec, period, now, true), "server_id, tool"),
            catalog_statement(spec),
        ],
        (_, GroupBy::Time) => vec![time_statement(spec, period, now)],
        (_, GroupBy::Nothing) => vec![number_statement(spec, period, now)],
        (_, group) => vec![ranked_statement(spec, period, now, group)],
    }
}

/// The first second, width in seconds and count of a time chart: hours for 24 hours, UTC days otherwise.
pub fn bucket_frame(period: Period, now: i64) -> (i64, i64, i64) {
    let (width, count) = match period {
        Period::H24 => (HOUR, 24),
        Period::D7 => (DAY, 7),
        Period::D30 => (DAY, 30),
        Period::D90 => (DAY, 90),
    };
    let end = (now.div_euclid(width) + 1) * width;
    (end - count * width, width, count)
}

/// The conditions of a chart: its metric's event, its filters, and the period when rolling.
fn scope(spec: &ChartSpec, period: Period, now: i64, rolling: bool) -> Criteria {
    let filters = Filters {
        period: rolling.then(|| period.as_str().to_owned()),
        event: event_of(spec.metric).map(str::to_owned),
        user: spec.user_id.map(|id| id.to_string()),
        server: spec.server_id.map(|id| id.to_string()),
        tool: spec.tool.clone(),
        ..Filters::default()
    };
    criteria(&filters, now)
}

/// The Activity page's event key for a metric's rows: one event for a count, the let-through calls for
/// the people and durations, which are computed from them.
fn event_of(metric: Metric) -> Option<&'static str> {
    match metric {
        Metric::Calls => Some("tool_call"),
        Metric::Refused => Some("tool_refused"),
        Metric::Failed => Some("tool_failed"),
        Metric::AllCalls => Some("tool_any"),
        Metric::SignIns => Some("sign_in"),
        Metric::SignInsRefused => Some("sign_in_refused"),
        Metric::ActiveUsers
        | Metric::DurationMedian
        | Metric::DurationP95
        | Metric::UnusedTools => Some("tool_let_through"),
    }
}

/// The rows of one group as they fold: the count, the distinct users, and the durations of a percentile.
#[derive(Default)]
struct Group {
    count: i64,
    users: HashSet<i64>,
    durations: Vec<u32>,
}

impl Group {
    fn add(&mut self, metric: Metric, user: Option<i64>, duration: Option<i64>) {
        self.count += 1;
        if let (Metric::ActiveUsers, Some(user)) = (metric, user) {
            self.users.insert(user);
        }
        if let (Some(_), Some(ms)) = (metric.percentile(), duration) {
            self.durations.push(clamp_ms(ms));
        }
    }

    /// The count, the distinct users, or the percentile; None for a percentile with no duration.
    fn value(&mut self, metric: Metric) -> Option<i64> {
        match metric.percentile() {
            Some(percent) => nearest_rank(&mut self.durations, percent),
            None if metric == Metric::ActiveUsers => i64::try_from(self.users.len()).ok(),
            None => Some(self.count),
        }
    }
}

/// A duration in milliseconds as the four bytes a percentile holds; a longer one is held as the largest.
fn clamp_ms(ms: i64) -> u32 {
    u32::try_from(ms.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX)
}

/// The nearest-rank percentile: the value at rank ceil(percent * n / 100), or None when there is none.
fn nearest_rank(values: &mut [u32], percent: i64) -> Option<i64> {
    let n = i64::try_from(values.len()).ok().filter(|n| *n > 0)?;
    let index = usize::try_from((percent * n + 99) / 100 - 1).ok()?;
    let (_, nth, _) = values.select_nth_unstable(index);
    Some(i64::from(*nth))
}

/// The statement that reads the rows of `scope` with `columns`, and its bound values.
fn select(scope: &Criteria, columns: &str) -> (String, Vec<Value>) {
    (
        format!("SELECT {columns} FROM activity{}", scope.clause()),
        scope.values().to_vec(),
    )
}

/// Runs a statement and folds each row it returns, in the order the statement returns them.
fn each<T>(
    conn: &Connection,
    (sql, values): &(String, Vec<Value>),
    read: impl Fn(&Row<'_>) -> rusqlite::Result<T>,
    mut fold: impl FnMut(T),
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map(params_from_iter(values.iter()), read)?;
    for row in rows {
        fold(row?);
    }
    Ok(())
}

fn time_statement(spec: &ChartSpec, period: Period, now: i64) -> (String, Vec<Value>) {
    let (start, width, count) = bucket_frame(period, now);
    let mut scope = scope(spec, period, now, false);
    scope.add(
        "at >= ? AND at < ?",
        vec![Value::Integer(start), Value::Integer(start + width * count)],
    );
    if spec.metric.percentile().is_some() {
        scope.add("duration_ms IS NOT NULL", Vec::new());
    }
    select(&scope, "at, user_id, duration_ms")
}

fn time_series(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    let (start, width, count) = bucket_frame(period, now);
    let statement = time_statement(spec, period, now);
    let mut groups: Vec<Group> = (0..count).map(|_| Group::default()).collect();
    each(
        conn,
        &statement,
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        },
        |(at, user, duration)| {
            let slot = (at - start).div_euclid(width);
            if let Some(group) = usize::try_from(slot).ok().and_then(|i| groups.get_mut(i)) {
                group.add(spec.metric, user, duration);
            }
        },
    )?;
    let buckets = groups
        .iter_mut()
        .enumerate()
        .map(|(index, group)| {
            let first = start + i64::try_from(index).unwrap_or(0) * width;
            Ok(Bucket {
                label: bucket_label(period, first)?,
                value: group.value(spec.metric),
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Series::Buckets(buckets))
}

/// The label of a bucket: the hour for a 24-hour chart, the day otherwise, in UTC.
fn bucket_label(period: Period, start: i64) -> rusqlite::Result<String> {
    let when = OffsetDateTime::from_unix_timestamp(start).map_err(invalid_time)?;
    let text = match period {
        Period::H24 => "[year]-[month]-[day] [hour]:[minute]",
        _ => "[year]-[month]-[day]",
    };
    let format = format_description::parse_borrowed::<2>(text).map_err(invalid_time)?;
    when.format(&format).map_err(invalid_time)
}

fn invalid_time<E>(err: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

fn number_statement(spec: &ChartSpec, period: Period, now: i64) -> (String, Vec<Value>) {
    let mut scope = scope(spec, period, now, true);
    if spec.metric.percentile().is_some() {
        scope.add("duration_ms IS NOT NULL", Vec::new());
    }
    select(&scope, "user_id, duration_ms")
}

fn number(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    let mut group = Group::default();
    each(
        conn,
        &number_statement(spec, period, now),
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        |(user, duration)| group.add(spec.metric, user, duration),
    )?;
    Ok(Series::Number(group.value(spec.metric)))
}

/// The columns a category is read by: the two recorded texts it is grouped on, and the condition that
/// leaves out a row with no key.
struct Columns {
    raw1: &'static str,
    raw2: &'static str,
    nonempty: Option<&'static str>,
}

fn columns(group: GroupBy) -> Columns {
    match group {
        GroupBy::User => Columns {
            raw1: "user_email",
            raw2: "''",
            nonempty: Some("user_email <> ''"),
        },
        GroupBy::Server => Columns {
            raw1: "server_slug",
            raw2: "''",
            nonempty: Some("server_slug <> ''"),
        },
        GroupBy::Tool => Columns {
            raw1: "tool",
            raw2: "server_slug",
            nonempty: Some("tool <> ''"),
        },
        _ => Columns {
            raw1: "client",
            raw2: "''",
            nonempty: None,
        },
    }
}

/// The label of a category: its user, server or client, or its server and tool.
fn label_of(group: GroupBy, raw1: &str, raw2: &str) -> String {
    match group {
        GroupBy::Tool => format!("{raw2} / {raw1}"),
        GroupBy::Client if raw1.is_empty() => "unknown".to_owned(),
        _ => raw1.to_owned(),
    }
}

fn ranked_statement(
    spec: &ChartSpec,
    period: Period,
    now: i64,
    group: GroupBy,
) -> (String, Vec<Value>) {
    let by = columns(group);
    let mut scope = scope(spec, period, now, true);
    if let Some(condition) = by.nonempty {
        scope.add(condition, Vec::new());
    }
    if spec.metric.percentile().is_some() {
        scope.add("duration_ms IS NOT NULL", Vec::new());
    }
    select(
        &scope,
        &format!("{}, {}, user_id, duration_ms", by.raw1, by.raw2),
    )
}

fn ranked(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
    group: GroupBy,
) -> rusqlite::Result<Series> {
    let statement = ranked_statement(spec, period, now, group);
    let mut groups: HashMap<(String, String), Group> = HashMap::new();
    each(
        conn,
        &statement,
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
        |(raw1, raw2, user, duration)| {
            groups
                .entry((raw1, raw2))
                .or_default()
                .add(spec.metric, user, duration);
        },
    )?;
    let mut ranked: Vec<(String, i64, String, String)> = groups
        .into_iter()
        .filter_map(|((raw1, raw2), mut group_rows)| {
            let value = group_rows.value(spec.metric)?;
            Some((label_of(group, &raw1, &raw2), value, raw1, raw2))
        })
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top = usize::try_from(spec.top_n.unwrap_or(TOP_COUNTS[0])).unwrap_or(0);
    ranked.truncate(top);
    let categories = ranked
        .into_iter()
        .map(|(label, value, raw1, raw2)| Category {
            label,
            value,
            link: link_of(spec, period, group, &raw1, &raw2),
        })
        .collect();
    Ok(Series::Ranked(categories))
}

/// The Activity filters that show one category's rows, with the chart's own filters and period. A
/// user, server or tool is matched by its recorded email, slug or name, so a deleted one still links.
fn link_of(
    spec: &ChartSpec,
    period: Period,
    group: GroupBy,
    raw1: &str,
    raw2: &str,
) -> Option<Vec<(&'static str, String)>> {
    if group == GroupBy::Client && raw1.is_empty() {
        return None;
    }
    let mut pairs: Vec<(&'static str, String)> = vec![("period", period.as_str().to_owned())];
    if let Some(event) = event_of(spec.metric) {
        pairs.push(("event", event.to_owned()));
    }
    if let Some(user) = spec.user_id {
        pairs.push(("user", user.to_string()));
    }
    if let Some(server) = spec.server_id {
        pairs.push(("server", server.to_string()));
    }
    if let Some(tool) = &spec.tool {
        pairs.push(("tool", tool.clone()));
    }
    let mut add = |key: &'static str, value: String| {
        if !pairs.iter().any(|(existing, _)| *existing == key) {
            pairs.push((key, value));
        }
    };
    match group {
        GroupBy::User => add("email", raw1.to_owned()),
        GroupBy::Server => add("slug", raw1.to_owned()),
        GroupBy::Tool => {
            add("tool", raw1.to_owned());
            add("slug", raw2.to_owned());
        }
        _ => add("client", raw1.to_owned()),
    }
    Some(pairs)
}

/// The statement that lists the catalog tools of the chart's server and tool filters, unsorted.
fn catalog_statement(spec: &ChartSpec) -> (String, Vec<Value>) {
    let mut catalog = Criteria::default();
    if let Some(server) = spec.server_id {
        catalog.add("tool_catalog.server_id = ?", vec![Value::Integer(server)]);
    }
    if let Some(tool) = &spec.tool {
        catalog.add("tool_catalog.name = ?", vec![Value::Text(tool.clone())]);
    }
    (
        format!(
            "SELECT servers.slug, tool_catalog.name, tool_catalog.server_id, tool_catalog.position \
             FROM tool_catalog JOIN servers ON servers.id = tool_catalog.server_id{}",
            catalog.clause()
        ),
        catalog.values().to_vec(),
    )
}

/// The tools of the server lists with no let-through call in the period, in server slug then catalog order.
fn unused(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    let (used_sql, used_values) = select(&scope(spec, period, now, true), "server_id, tool");
    let mut called: HashSet<(i64, String)> = HashSet::new();
    each(
        conn,
        &(used_sql, used_values),
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?)),
        |(server, tool)| {
            if let Some(server) = server {
                called.insert((server, tool));
            }
        },
    )?;
    let mut listed = Vec::new();
    each(
        conn,
        &catalog_statement(spec),
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
        |listing| listed.push(listing),
    )?;
    listed.retain(|(_, name, server, _)| !called.contains(&(*server, name.clone())));
    listed.sort_by(|a, b| a.0.cmp(&b.0).then(a.3.cmp(&b.3)));
    Ok(Series::Unused(
        listed
            .into_iter()
            .map(|(slug, name, _, _)| (slug, name))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::dashboards::model::{Shape, Width};

    const NOW: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z

    /// A database with the columns the chart queries read, and one server.
    fn memory() -> Connection {
        let conn = Connection::open_in_memory().expect("memory database");
        conn.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);
             CREATE TABLE servers (id INTEGER PRIMARY KEY, slug TEXT NOT NULL);
             CREATE TABLE tool_catalog (server_id INTEGER, position INTEGER, name TEXT, definition TEXT);
             CREATE TABLE activity (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
               kind TEXT NOT NULL, user_id INTEGER, user_email TEXT NOT NULL DEFAULT '',
               server_id INTEGER, server_slug TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '',
               client TEXT NOT NULL DEFAULT '', decision TEXT NOT NULL DEFAULT '',
               outcome TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
               duration_ms INTEGER);
             INSERT INTO servers (id, slug) VALUES (1, 'demo');",
        )
        .expect("schema");
        conn
    }

    fn spec(metric: Metric, group_by: GroupBy, shape: Shape) -> ChartSpec {
        ChartSpec {
            metric,
            group_by,
            shape,
            period: Period::D90,
            server_id: None,
            user_id: None,
            tool: None,
            top_n: Some(10),
            width: Width::Half,
        }
    }

    /// Inserts one let-through call at `at` with a duration.
    fn call(conn: &Connection, at: i64, ms: i64) {
        conn.execute(
            "INSERT INTO activity (at, kind, server_id, server_slug, tool, decision, outcome, duration_ms) \
             VALUES (?1, 'tool_call', 1, 'demo', 'alpha', 'allow', 'ok', ?2)",
            rusqlite::params![at, ms],
        )
        .expect("a call");
    }

    /// The value of each daily bucket of a seven-day duration chart.
    fn daily(conn: &Connection, metric: Metric) -> Vec<Option<i64>> {
        match series(
            conn,
            &spec(metric, GroupBy::Time, Shape::Line),
            Period::D7,
            NOW,
        )
        .expect("a series")
        {
            Series::Buckets(buckets) => buckets.iter().map(|bucket| bucket.value).collect(),
            _ => panic!("a time chart draws buckets"),
        }
    }

    #[test]
    fn the_hour_frame_ends_at_the_current_hour_and_the_day_frame_at_today() {
        assert_eq!(bucket_frame(Period::H24, NOW), (NOW - 23 * HOUR, HOUR, 24));
        assert_eq!(
            bucket_frame(Period::H24, NOW + 1_234),
            (NOW - 23 * HOUR, HOUR, 24),
            "a time inside the hour names that hour as the last bucket"
        );
        assert_eq!(bucket_frame(Period::D7, NOW), (NOW - 6 * DAY, DAY, 7));
        assert_eq!(
            bucket_frame(Period::D90, NOW + DAY - 1),
            (NOW - 89 * DAY, DAY, 90)
        );
        assert_eq!(bucket_frame(Period::D30, NOW), (NOW - 29 * DAY, DAY, 30));
    }

    #[test]
    fn the_bucket_labels_are_utc_hours_or_days() {
        assert_eq!(
            bucket_label(Period::H24, NOW - HOUR).expect("label"),
            "2029-12-31 23:00"
        );
        assert_eq!(
            bucket_label(Period::D7, NOW - DAY).expect("label"),
            "2029-12-31"
        );
    }

    #[test]
    fn the_median_and_p95_are_nearest_rank_over_the_calls_of_a_bucket() {
        let conn = memory();
        // Ten calls on one day with durations 1 to 10, and one call the day before with 4 ms.
        for ms in 1..=10 {
            call(&conn, NOW - 2 * DAY + ms, ms);
        }
        call(&conn, NOW - 3 * DAY, 4);
        let median = daily(&conn, Metric::DurationMedian);
        assert_eq!(median[4], Some(5), "the fifth of ten");
        assert_eq!(median[3], Some(4), "a single call is its own median");
        assert_eq!(median[0], None, "an empty day has no value");
        let p95 = daily(&conn, Metric::DurationP95);
        assert_eq!(p95[4], Some(10), "ceil(0.95 * 10) is the tenth");
        assert_eq!(p95[3], Some(4));
    }

    #[test]
    fn a_percentile_of_an_even_count_takes_the_lower_middle_value() {
        let conn = memory();
        for ms in [10, 20, 30, 40] {
            call(&conn, NOW - DAY, ms);
        }
        let median = daily(&conn, Metric::DurationMedian);
        assert_eq!(median[5], Some(20), "ceil(0.5 * 4) is the second of four");
        let p95 = daily(&conn, Metric::DurationP95);
        assert_eq!(p95[5], Some(40), "ceil(0.95 * 4) is the fourth of four");
    }

    #[test]
    fn a_zero_count_is_an_empty_series_for_buckets_and_zero_for_a_number() {
        let conn = memory();
        let buckets = series(
            &conn,
            &spec(Metric::Calls, GroupBy::Time, Shape::Bars),
            Period::H24,
            NOW,
        )
        .expect("series");
        assert!(
            buckets.is_empty(),
            "all zero buckets say there is no activity"
        );
        let number = series(
            &conn,
            &spec(Metric::Calls, GroupBy::Nothing, Shape::Number),
            Period::H24,
            NOW,
        )
        .expect("series");
        assert!(
            matches!(number, Series::Number(Some(0))),
            "a count of none is zero"
        );
        assert!(!number.is_empty());
    }

    /// Every statement of every metric, grouping and filter the builder allows, with the real indexes:
    /// no sort, window or temporary table, and no full scan of the activity table.
    #[test]
    fn every_chart_statement_searches_an_index_without_a_sort_or_temporary_table() {
        use crate::db::Db;
        use rusqlite::params_from_iter;

        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("doorward.db");
        Db::open(&path).expect("the migrated database");
        let conn = Connection::open(&path).expect("a connection");
        let filters = [
            (None, None, None),
            (Some(1), None, None),
            (None, Some(1), None),
            (None, None, Some("alpha")),
            (Some(1), Some(1), Some("alpha")),
        ];
        let mut checked = 0;
        for metric in Metric::ALL {
            for group_by in GroupBy::ALL {
                for period in Period::ALL {
                    for (server_id, user_id, tool) in filters {
                        let chart = ChartSpec {
                            metric: *metric,
                            group_by: *group_by,
                            shape: Shape::Table,
                            period: *period,
                            server_id,
                            user_id,
                            tool: tool.map(str::to_owned),
                            top_n: Some(10),
                            width: Width::Half,
                        };
                        for (sql, values) in statements(&chart, *period, NOW) {
                            let explain = format!("EXPLAIN QUERY PLAN {sql}");
                            let mut plan = conn.prepare(&explain).expect("the plan");
                            let details: Vec<String> = plan
                                .query_map(params_from_iter(values.iter()), |row| row.get(3))
                                .expect("the plan rows")
                                .collect::<rusqlite::Result<_>>()
                                .expect("the plan text");
                            let label = format!("{metric:?}/{group_by:?}/{period:?}: {sql}");
                            assert!(!details.is_empty(), "{label} has a plan");
                            for detail in &details {
                                assert!(!detail.contains("TEMP B-TREE"), "{label}: {detail}");
                                assert!(!detail.contains("CO-ROUTINE"), "{label}: {detail}");
                                assert!(
                                    !detail.starts_with("SCAN activity")
                                        || detail.contains("USING"),
                                    "{label}: {detail}"
                                );
                            }
                            checked += 1;
                        }
                    }
                }
            }
        }
        // Nine metrics and six groupings give one statement each, the unused tools two; four periods, five filter sets.
        assert_eq!(checked, (9 * 6 + 6 * 2) * 4 * 5);
    }
}
