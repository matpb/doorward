CREATE TABLE activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  user_id INTEGER,
  user_email TEXT NOT NULL DEFAULT '',
  server_id INTEGER,
  server_slug TEXT NOT NULL DEFAULT '',
  tool TEXT NOT NULL DEFAULT '',
  client TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  duration_ms INTEGER
) STRICT;
CREATE INDEX activity_at ON activity(at);
CREATE INDEX activity_user ON activity(user_id);
CREATE INDEX activity_server ON activity(server_id);
