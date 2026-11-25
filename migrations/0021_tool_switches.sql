CREATE TABLE tool_switches (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  set_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, server_id, tool)
) STRICT;
