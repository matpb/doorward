//! Dashboards and charts in the database. Each change runs in one transaction that decides its limits
//! and names, writes its change to the activity log, and reports what it did.

use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use crate::admin::rules::record;
use crate::servers;
use crate::web::SessionUser;

use super::model::{
    CHART_FULL, CHART_LIMIT, ChartSpec, Checked, DASHBOARD_FULL, DASHBOARD_LIMIT, GroupBy, Metric,
    NAME_TAKEN, Period, SERVER, Shape, USER, Width,
};

/// The outcome of a change: done with its value, refused with the message of the refusal, or the
/// dashboard or chart it names does not exist.
pub enum Change<T> {
    Done(T),
    Refused(&'static str),
    Missing,
}

/// The direction of a move.
#[derive(Clone, Copy)]
pub enum Direction {
    Up,
    Down,
}

impl Direction {
    pub fn parse(text: &str) -> Option<Direction> {
        match text {
            "up" => Some(Direction::Up),
            "down" => Some(Direction::Down),
            _ => None,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Direction::Up => "up",
            Direction::Down => "down",
        }
    }

    /// The index the item moves to, or None when it is already at that end.
    fn neighbour(self, index: usize, len: usize) -> Option<usize> {
        match self {
            Direction::Up => index.checked_sub(1),
            Direction::Down => Some(index + 1).filter(|next| *next < len),
        }
    }
}

/// A dashboard as stored: its id and its name.
pub struct Board {
    pub id: i64,
    pub name: String,
}

/// A chart as stored: its id, its title and its definition.
pub struct Stored {
    pub id: i64,
    pub title: String,
    pub spec: ChartSpec,
}

fn board_row(row: &Row<'_>) -> rusqlite::Result<Board> {
    Ok(Board {
        id: row.get(0)?,
        name: row.get(1)?,
    })
}

/// Every dashboard in its order.
pub fn boards_in(conn: &Connection) -> rusqlite::Result<Vec<Board>> {
    let mut statement = conn.prepare("SELECT id, name FROM dashboards ORDER BY position, id")?;
    let rows = statement.query_map([], board_row)?;
    rows.collect()
}

/// One dashboard by id; None when there is none.
pub fn board_in(conn: &Connection, id: i64) -> rusqlite::Result<Option<Board>> {
    conn.query_row(
        "SELECT id, name FROM dashboards WHERE id = ?1",
        params![id],
        board_row,
    )
    .optional()
}

/// The charts of one dashboard in their order.
pub fn charts_in(conn: &Connection, board: i64) -> rusqlite::Result<Vec<Stored>> {
    let mut statement = conn.prepare(
        "SELECT id, position, title, metric, group_by, shape, period, server_id, user_id, tool, \
         top_n, width FROM charts WHERE dashboard_id = ?1 ORDER BY position, id",
    )?;
    let rows = statement.query_map(params![board], stored_chart)?;
    rows.collect()
}

/// One chart of a dashboard by id; None when the dashboard has no such chart.
fn chart_in(conn: &Connection, board: i64, chart: i64) -> rusqlite::Result<Option<Stored>> {
    conn.query_row(
        "SELECT id, position, title, metric, group_by, shape, period, server_id, user_id, tool, \
         top_n, width FROM charts WHERE dashboard_id = ?1 AND id = ?2",
        params![board, chart],
        stored_chart,
    )
    .optional()
}

/// A chart row, its closed-list columns read back into their values. Column 1 is its position.
fn stored_chart(row: &Row<'_>) -> rusqlite::Result<Stored> {
    Ok(Stored {
        id: row.get(0)?,
        title: row.get(2)?,
        spec: ChartSpec {
            metric: listed(Metric::parse(&row.get::<_, String>(3)?), 3)?,
            group_by: listed(GroupBy::parse(&row.get::<_, String>(4)?), 4)?,
            shape: listed(Shape::parse(&row.get::<_, String>(5)?), 5)?,
            period: listed(Period::parse(&row.get::<_, String>(6)?), 6)?,
            server_id: row.get(7)?,
            user_id: row.get(8)?,
            tool: row.get(9)?,
            top_n: row.get(10)?,
            width: listed(Width::parse(&row.get::<_, String>(11)?), 11)?,
        },
    })
}

/// A stored closed-list value; the schema's checks make every stored value one of the list.
fn listed<T>(value: Option<T>, column: usize) -> rusqlite::Result<T> {
    value.ok_or(rusqlite::Error::InvalidColumnType(
        column,
        String::from("closed list"),
        Type::Text,
    ))
}

fn count_boards(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM dashboards", [], |row| row.get(0))
}

fn count_charts(conn: &Connection, board: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM charts WHERE dashboard_id = ?1",
        params![board],
        |row| row.get(0),
    )
}

fn name_taken(conn: &Connection, name: &str, except: Option<i64>) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM dashboards WHERE name = ?1 AND id <> ?2)",
        params![name, except.unwrap_or(0)],
        |row| row.get(0),
    )
}

/// The refusal of a chart whose server or user filter names nothing, None when both exist.
fn missing_filter(conn: &Connection, spec: &ChartSpec) -> rusqlite::Result<Option<&'static str>> {
    if let Some(server) = spec.server_id
        && !servers::server_exists(conn, server)?
    {
        return Ok(Some(SERVER));
    }
    if let Some(user) = spec.user_id
        && !servers::user_exists(conn, user)?
    {
        return Ok(Some(USER));
    }
    Ok(None)
}

/// Creates a dashboard at the end of the order. Refused when the limit or the name is taken.
pub fn create_board(
    conn: &mut Connection,
    actor: &SessionUser,
    name: &str,
    at: i64,
) -> rusqlite::Result<Change<i64>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if count_boards(&tx)? >= DASHBOARD_LIMIT {
        return Ok(Change::Refused(DASHBOARD_FULL));
    }
    if name_taken(&tx, name, None)? {
        return Ok(Change::Refused(NAME_TAKEN));
    }
    tx.execute(
        "INSERT INTO dashboards (name, position, created_at, updated_at) \
         VALUES (?1, (SELECT COALESCE(MAX(position), 0) + 1 FROM dashboards), ?2, ?2)",
        params![name, at],
    )?;
    let id = tx.last_insert_rowid();
    record(&tx, at, actor, &format!("created dashboard {name}"))?;
    tx.commit()?;
    Ok(Change::Done(id))
}

/// Renames a dashboard. A name another dashboard has is refused; the same name changes nothing.
pub fn rename_board(
    conn: &mut Connection,
    actor: &SessionUser,
    id: i64,
    name: &str,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, id)? else {
        return Ok(Change::Missing);
    };
    if name_taken(&tx, name, Some(id))? {
        return Ok(Change::Refused(NAME_TAKEN));
    }
    if board.name != name {
        tx.execute(
            "UPDATE dashboards SET name = ?1, updated_at = ?2 WHERE id = ?3",
            params![name, at, id],
        )?;
        record(
            &tx,
            at,
            actor,
            &format!("renamed dashboard {} to {name}", board.name),
        )?;
    }
    tx.commit()?;
    Ok(Change::Done(()))
}

/// Deletes a dashboard and, with it, its charts.
pub fn delete_board(
    conn: &mut Connection,
    actor: &SessionUser,
    id: i64,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, id)? else {
        return Ok(Change::Missing);
    };
    tx.execute("DELETE FROM dashboards WHERE id = ?1", params![id])?;
    record(&tx, at, actor, &format!("deleted dashboard {}", board.name))?;
    tx.commit()?;
    Ok(Change::Done(()))
}

/// Moves a dashboard one place up or down the order; at an end it changes nothing.
pub fn move_board(
    conn: &mut Connection,
    actor: &SessionUser,
    id: i64,
    direction: Direction,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, id)? else {
        return Ok(Change::Missing);
    };
    let mut order = boards_in(&tx)?;
    let Some(index) = order.iter().position(|item| item.id == id) else {
        return Ok(Change::Missing);
    };
    if let Some(next) = direction.neighbour(index, order.len()) {
        order.swap(index, next);
        for (position, item) in order.iter().enumerate() {
            tx.execute(
                "UPDATE dashboards SET position = ?1 WHERE id = ?2",
                params![i64::try_from(position + 1).unwrap_or(i64::MAX), item.id],
            )?;
        }
        record(
            &tx,
            at,
            actor,
            &format!("moved dashboard {} {}", board.name, direction.word()),
        )?;
    }
    tx.commit()?;
    Ok(Change::Done(()))
}

/// Adds a chart at the end of a dashboard. Refused when the dashboard is full or a filter names nothing.
pub fn add_chart(
    conn: &mut Connection,
    actor: &SessionUser,
    board_id: i64,
    checked: &Checked,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, board_id)? else {
        return Ok(Change::Missing);
    };
    if count_charts(&tx, board_id)? >= CHART_LIMIT {
        return Ok(Change::Refused(CHART_FULL));
    }
    if let Some(message) = missing_filter(&tx, &checked.spec)? {
        return Ok(Change::Refused(message));
    }
    let spec = &checked.spec;
    tx.execute(
        "INSERT INTO charts (dashboard_id, position, title, metric, group_by, shape, period, \
         server_id, user_id, tool, top_n, width) VALUES (?1, \
         (SELECT COALESCE(MAX(position), 0) + 1 FROM charts WHERE dashboard_id = ?1), \
         ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            board_id,
            checked.title,
            spec.metric.as_str(),
            spec.group_by.as_str(),
            spec.shape.as_str(),
            spec.period.as_str(),
            spec.server_id,
            spec.user_id,
            spec.tool,
            spec.top_n,
            spec.width.as_str(),
        ],
    )?;
    record(
        &tx,
        at,
        actor,
        &format!("added chart {} to dashboard {}", checked.title, board.name),
    )?;
    tx.commit()?;
    Ok(Change::Done(()))
}

/// Replaces a chart's title and definition. Refused when a filter names nothing.
pub fn update_chart(
    conn: &mut Connection,
    actor: &SessionUser,
    board_id: i64,
    chart_id: i64,
    checked: &Checked,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, board_id)? else {
        return Ok(Change::Missing);
    };
    if chart_in(&tx, board_id, chart_id)?.is_none() {
        return Ok(Change::Missing);
    }
    if let Some(message) = missing_filter(&tx, &checked.spec)? {
        return Ok(Change::Refused(message));
    }
    let spec = &checked.spec;
    tx.execute(
        "UPDATE charts SET title = ?1, metric = ?2, group_by = ?3, shape = ?4, period = ?5, \
         server_id = ?6, user_id = ?7, tool = ?8, top_n = ?9, width = ?10 WHERE id = ?11",
        params![
            checked.title,
            spec.metric.as_str(),
            spec.group_by.as_str(),
            spec.shape.as_str(),
            spec.period.as_str(),
            spec.server_id,
            spec.user_id,
            spec.tool,
            spec.top_n,
            spec.width.as_str(),
            chart_id,
        ],
    )?;
    record(
        &tx,
        at,
        actor,
        &format!(
            "changed chart {} on dashboard {}",
            checked.title, board.name
        ),
    )?;
    tx.commit()?;
    Ok(Change::Done(()))
}

/// Deletes one chart of a dashboard.
pub fn delete_chart(
    conn: &mut Connection,
    actor: &SessionUser,
    board_id: i64,
    chart_id: i64,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, board_id)? else {
        return Ok(Change::Missing);
    };
    let Some(chart) = chart_in(&tx, board_id, chart_id)? else {
        return Ok(Change::Missing);
    };
    tx.execute("DELETE FROM charts WHERE id = ?1", params![chart_id])?;
    record(
        &tx,
        at,
        actor,
        &format!(
            "deleted chart {} from dashboard {}",
            chart.title, board.name
        ),
    )?;
    tx.commit()?;
    Ok(Change::Done(()))
}

/// Moves a chart one place up or down its dashboard; at an end it changes nothing.
pub fn move_chart(
    conn: &mut Connection,
    actor: &SessionUser,
    board_id: i64,
    chart_id: i64,
    direction: Direction,
    at: i64,
) -> rusqlite::Result<Change<()>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(board) = board_in(&tx, board_id)? else {
        return Ok(Change::Missing);
    };
    let mut order = charts_in(&tx, board_id)?;
    let Some(index) = order.iter().position(|item| item.id == chart_id) else {
        return Ok(Change::Missing);
    };
    let title = order[index].title.clone();
    if let Some(next) = direction.neighbour(index, order.len()) {
        order.swap(index, next);
        for (position, item) in order.iter().enumerate() {
            tx.execute(
                "UPDATE charts SET position = ?1 WHERE id = ?2",
                params![i64::try_from(position + 1).unwrap_or(i64::MAX), item.id],
            )?;
        }
        record(
            &tx,
            at,
            actor,
            &format!(
                "moved chart {title} {} on dashboard {}",
                direction.word(),
                board.name
            ),
        )?;
    }
    tx.commit()?;
    Ok(Change::Done(()))
}
