CREATE TABLE servers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  upstream_url TEXT NOT NULL,
  secret_header_name TEXT NOT NULL DEFAULT '',
  secret_header_value TEXT,
  pass_resources INTEGER NOT NULL DEFAULT 0,
  pass_prompts INTEGER NOT NULL DEFAULT 0,
  lockdown TEXT NOT NULL DEFAULT 'unknown' CHECK (lockdown IN ('ok','open','unknown')),
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE user_servers (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, server_id)
) STRICT;
CREATE INDEX user_servers_server ON user_servers(server_id);
