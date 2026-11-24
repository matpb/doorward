//! The numbers of one chart: one read of the activity table per chart, bounded by its period. The
//! conditions are the Activity page's own (its filters and events), so a number and that page agree.

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params_from_iter};
use time::OffsetDateTime;
use time::format_description;

use crate::admin::activity::filters::{Criteria, Filters, criteria};
use crate::servers;

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

/// The conditions of a chart: its metric's event or class, its filters, and the period when rolling.
fn scope(spec: &ChartSpec, period: Period, now: i64, rolling: bool) -> Criteria {
    let filters = Filters {
        period: rolling.then(|| period.as_str().to_owned()),
        event: event_of(spec.metric).map(str::to_owned),
        user: spec.user_id.map(|id| id.to_string()),
        server: spec.server_id.map(|id| id.to_string()),
        tool: spec.tool.clone(),
        ..Filters::default()
    };
    let mut scope = criteria(&filters, now);
    if let Some(class) = class_of(spec.metric) {
        scope.add(class, Vec::new());
    }
    scope
}

/// The Activity page's event key for a metric that counts one event; None for the others.
fn event_of(metric: Metric) -> Option<&'static str> {
    match metric {
        Metric::Calls => Some("tool_call"),
        Metric::Refused => Some("tool_refused"),
        Metric::Failed => Some("tool_failed"),
        Metric::AllCalls => Some("tool_any"),
        Metric::SignIns => Some("sign_in"),
        Metric::SignInsRefused => Some("sign_in_refused"),
        _ => None,
    }
}

/// The row class of a metric that is not one Activity event: the calls let through.
fn class_of(metric: Metric) -> Option<&'static str> {
    match metric {
        Metric::ActiveUsers | Metric::DurationMedian | Metric::DurationP95 => {
            Some("kind = 'tool_call' AND decision <> 'deny'")
        }
        _ => None,
    }
}

/// The aggregate of a count metric.
fn count_of(metric: Metric) -> &'static str {
    match metric {
        Metric::ActiveUsers => "COUNT(DISTINCT user_id)",
        _ => "COUNT(*)",
    }
}

fn time_series(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    let (start, width, count) = bucket_frame(period, now);
    let mut scope = scope(spec, period, now, false);
    scope.add(
        "at >= ? AND at < ?",
        vec![Value::Integer(start), Value::Integer(start + width * count)],
    );
    let percentile = spec.metric.percentile();
    if percentile.is_some() {
        scope.add("duration_ms IS NOT NULL", Vec::new());
    }
    let clause = scope.clause();
    let mut buckets = Vec::new();
    for index in 0..count {
        let first = start + index * width;
        buckets.push(Bucket {
            label: bucket_label(period, first)?,
            value: percentile.is_none().then_some(0),
        });
    }
    let sql = match percentile {
        Some(_) => format!(
            "WITH rows AS (SELECT CAST((at - ?) / {width} AS INTEGER) AS bucket, duration_ms \
             FROM activity{clause}), \
             ranked AS (SELECT bucket, duration_ms, \
             ROW_NUMBER() OVER (PARTITION BY bucket ORDER BY duration_ms) AS rn, \
             COUNT(*) OVER (PARTITION BY bucket) AS n FROM rows) \
             SELECT bucket, duration_ms FROM ranked WHERE rn = (? * n + 99) / 100"
        ),
        None => format!(
            "SELECT CAST((at - ?) / {width} AS INTEGER) AS bucket, {} FROM activity{clause} \
             GROUP BY bucket",
            count_of(spec.metric)
        ),
    };
    let mut values = vec![Value::Integer(start)];
    values.extend_from_slice(scope.values());
    if let Some(percent) = percentile {
        values.push(Value::Integer(percent));
    }
    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (bucket, value) = row?;
        if let Some(slot) = usize::try_from(bucket)
            .ok()
            .and_then(|index| buckets.get_mut(index))
        {
            slot.value = Some(value);
        }
    }
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

fn number(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    let mut scope = scope(spec, period, now, true);
    let value = match spec.metric.percentile() {
        Some(percent) => {
            scope.add("duration_ms IS NOT NULL", Vec::new());
            let sql = format!(
                "SELECT duration_ms FROM (SELECT duration_ms, \
                 ROW_NUMBER() OVER (ORDER BY duration_ms) AS rn, COUNT(*) OVER () AS n \
                 FROM activity{}) WHERE rn = (? * n + 99) / 100",
                scope.clause()
            );
            let mut values = scope.values().to_vec();
            values.push(Value::Integer(percent));
            conn.query_row(&sql, params_from_iter(values), |row| row.get(0))
                .optional()?
        }
        None => {
            let sql = format!(
                "SELECT {} FROM activity{}",
                count_of(spec.metric),
                scope.clause()
            );
            Some(conn.query_row(&sql, params_from_iter(scope.values()), |row| row.get(0))?)
        }
    };
    Ok(Series::Number(value))
}

/// The columns a category is read by: its label, the id of the user or server it names, and the two
/// recorded texts it is grouped on.
struct Columns {
    label: &'static str,
    id_row: &'static str,
    id_group: &'static str,
    raw1: &'static str,
    raw2: &'static str,
    nonempty: Option<&'static str>,
}

fn columns(group: GroupBy) -> Columns {
    match group {
        GroupBy::User => Columns {
            label: "user_email",
            id_row: "user_id",
            id_group: "MAX(user_id)",
            raw1: "user_email",
            raw2: "''",
            nonempty: Some("user_email <> ''"),
        },
        GroupBy::Server => Columns {
            label: "server_slug",
            id_row: "server_id",
            id_group: "MAX(server_id)",
            raw1: "server_slug",
            raw2: "''",
            nonempty: Some("server_slug <> ''"),
        },
        GroupBy::Tool => Columns {
            label: "server_slug || ' / ' || tool",
            id_row: "server_id",
            id_group: "MAX(server_id)",
            raw1: "tool",
            raw2: "server_slug",
            nonempty: Some("tool <> ''"),
        },
        _ => Columns {
            label: "CASE WHEN client = '' THEN 'unknown' ELSE client END",
            id_row: "NULL",
            id_group: "NULL",
            raw1: "client",
            raw2: "''",
            nonempty: None,
        },
    }
}

fn ranked(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
    group: GroupBy,
) -> rusqlite::Result<Series> {
    let by = columns(group);
    let mut scope = scope(spec, period, now, true);
    if let Some(condition) = by.nonempty {
        scope.add(condition, Vec::new());
    }
    let percentile = spec.metric.percentile();
    if percentile.is_some() {
        scope.add("duration_ms IS NOT NULL", Vec::new());
    }
    let clause = scope.clause();
    let mut values = scope.values().to_vec();
    let sql = match percentile {
        None => format!(
            "SELECT {label} AS label, {id} AS id, {raw1} AS raw1, {raw2} AS raw2, \
             {agg} AS value FROM activity{clause} GROUP BY {raw1}, {raw2} \
             ORDER BY value DESC, label LIMIT ?",
            label = by.label,
            id = by.id_group,
            raw1 = by.raw1,
            raw2 = by.raw2,
            agg = count_of(spec.metric),
        ),
        Some(percent) => {
            values.push(Value::Integer(percent));
            format!(
                "WITH rows AS (SELECT {label} AS label, {id} AS id, {raw1} AS raw1, \
                 {raw2} AS raw2, duration_ms FROM activity{clause}), \
                 ranked AS (SELECT label, id, raw1, raw2, duration_ms, \
                 ROW_NUMBER() OVER (PARTITION BY raw1, raw2 ORDER BY duration_ms) AS rn, \
                 COUNT(*) OVER (PARTITION BY raw1, raw2) AS n FROM rows) \
                 SELECT label, id, raw1, raw2, duration_ms AS value FROM ranked \
                 WHERE rn = (? * n + 99) / 100 ORDER BY value DESC, label LIMIT ?",
                label = by.label,
                id = by.id_row,
                raw1 = by.raw1,
                raw2 = by.raw2,
            )
        }
    };
    values.push(Value::Integer(spec.top_n.unwrap_or(TOP_COUNTS[0])));
    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut categories = Vec::new();
    for row in rows {
        let (label, id, raw1, raw2, value) = row?;
        let link = link_of(conn, spec, period, group, id, &raw1, &raw2)?;
        categories.push(Category { label, value, link });
    }
    Ok(Series::Ranked(categories))
}

/// The Activity filters that show one category's rows, with the chart's own filters and period.
fn link_of(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    group: GroupBy,
    id: Option<i64>,
    raw1: &str,
    raw2: &str,
) -> rusqlite::Result<Option<Vec<(&'static str, String)>>> {
    if group == GroupBy::Client && raw1.is_empty() {
        return Ok(None);
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
        GroupBy::User => match id {
            Some(id) if servers::user_exists(conn, id)? => add("user", id.to_string()),
            _ => add("q", raw1.to_owned()),
        },
        GroupBy::Server => match id {
            Some(id) if servers::server_exists(conn, id)? => add("server", id.to_string()),
            _ => add("q", raw1.to_owned()),
        },
        GroupBy::Tool => {
            add("tool", raw1.to_owned());
            match id {
                Some(id) if servers::server_exists(conn, id)? => add("server", id.to_string()),
                _ => add("q", raw2.to_owned()),
            }
        }
        _ => add("client", raw1.to_owned()),
    }
    Ok(Some(pairs))
}

/// The tools of the server lists with no let-through call in the period, in server slug then catalog order.
fn unused(
    conn: &Connection,
    spec: &ChartSpec,
    period: Period,
    now: i64,
) -> rusqlite::Result<Series> {
    let mut used = scope(spec, period, now, true);
    used.add("kind = 'tool_call' AND decision <> 'deny'", Vec::new());
    let clause = used.clause();
    let mut values = used.values().to_vec();
    let mut catalog = String::new();
    if let Some(server) = spec.server_id {
        catalog.push_str(" AND tool_catalog.server_id = ?");
        values.push(Value::Integer(server));
    }
    if let Some(tool) = &spec.tool {
        catalog.push_str(" AND tool_catalog.name = ?");
        values.push(Value::Text(tool.clone()));
    }
    let sql = format!(
        "SELECT servers.slug, tool_catalog.name FROM tool_catalog \
         JOIN servers ON servers.id = tool_catalog.server_id \
         LEFT JOIN (SELECT DISTINCT server_id, tool FROM activity{clause}) AS used \
         ON used.server_id = tool_catalog.server_id AND used.tool = tool_catalog.name \
         WHERE used.tool IS NULL{catalog} ORDER BY servers.slug, tool_catalog.position"
    );
    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), |row| {
        Ok((row.get(0)?, row.get(1)?))
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map(Series::Unused)
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
}
