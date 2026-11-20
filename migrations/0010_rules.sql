CREATE TABLE rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  effect TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
  tool TEXT,
  created_at INTEGER NOT NULL,
  CHECK (tool IS NULL OR server_id IS NOT NULL)
) STRICT;
CREATE UNIQUE INDEX rules_subject_target
  ON rules(COALESCE(user_id, 0), COALESCE(server_id, 0), COALESCE(tool, ''));
CREATE INDEX rules_server ON rules(server_id);
