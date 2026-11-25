CREATE TABLE dashboards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 80),
  position INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE charts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dashboard_id INTEGER NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 80),
  metric TEXT NOT NULL CHECK (metric IN ('calls', 'refused', 'failed', 'all_calls',
    'active_users', 'sign_ins', 'sign_ins_refused', 'duration_median', 'duration_p95',
    'unused_tools')),
  group_by TEXT NOT NULL CHECK (group_by IN ('time', 'user', 'server', 'tool', 'client', 'none')),
  shape TEXT NOT NULL CHECK (shape IN ('line', 'bars', 'ranked', 'number', 'table')),
  period TEXT NOT NULL CHECK (period IN ('24h', '7d', '30d', '90d')),
  server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  tool TEXT CHECK (tool IS NULL OR length(tool) BETWEEN 1 AND 128),
  top_n INTEGER CHECK (top_n IS NULL OR top_n IN (5, 10, 20, 50)),
  width TEXT NOT NULL CHECK (width IN ('half', 'full')),
  CHECK ((group_by IN ('user', 'server', 'tool', 'client')) = (top_n IS NOT NULL)),
  CHECK (
    (metric = 'unused_tools' AND group_by = 'none' AND shape = 'table')
    OR (metric <> 'unused_tools' AND group_by = 'time' AND shape IN ('line', 'bars', 'table'))
    OR (metric <> 'unused_tools' AND group_by IN ('user', 'server', 'tool', 'client')
        AND shape IN ('ranked', 'table'))
    OR (metric <> 'unused_tools' AND group_by = 'none' AND shape = 'number')
  )
) STRICT;

CREATE INDEX charts_dashboard ON charts(dashboard_id, position);
CREATE INDEX dashboards_position ON dashboards(position);

INSERT INTO dashboards (id, name, position, created_at, updated_at)
  VALUES (1, 'Usage', 1, CAST(strftime('%s', 'now') AS INTEGER), CAST(strftime('%s', 'now') AS INTEGER));

INSERT INTO charts (dashboard_id, position, title, metric, group_by, shape, period, top_n, width) VALUES
  (1, 1, 'Tool calls over time', 'calls', 'time', 'bars', '30d', NULL, 'full'),
  (1, 2, 'Active users over time', 'active_users', 'time', 'line', '30d', NULL, 'half'),
  (1, 3, 'Tool calls refused over time', 'refused', 'time', 'line', '30d', NULL, 'half'),
  (1, 4, 'Most active users', 'calls', 'user', 'ranked', '30d', 10, 'half'),
  (1, 5, 'Servers by use', 'calls', 'server', 'ranked', '30d', 10, 'half'),
  (1, 6, 'Tools by use', 'calls', 'tool', 'ranked', '30d', 20, 'half'),
  (1, 7, 'Unused tools', 'unused_tools', 'none', 'table', '30d', NULL, 'half'),
  (1, 8, 'Slowest tools p95', 'duration_p95', 'tool', 'ranked', '30d', 10, 'half'),
  (1, 9, 'Calls by client', 'calls', 'client', 'ranked', '30d', 10, 'half'),
  (1, 10, 'Failed calls by server', 'failed', 'server', 'ranked', '30d', 10, 'full');
