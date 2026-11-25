CREATE TABLE tool_switches (
  user_id INTEGER NOT NULL,
  server_id INTEGER NOT NULL,
  tool TEXT NOT NULL,
  set_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, server_id, tool),
  FOREIGN KEY (user_id, server_id) REFERENCES user_servers(user_id, server_id) ON DELETE CASCADE
) STRICT;
