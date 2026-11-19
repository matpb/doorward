CREATE TABLE redirect_allow (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scheme TEXT NOT NULL,
  host TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('shipped','added')),
  enabled INTEGER NOT NULL DEFAULT 1,
  UNIQUE (scheme, host, path_prefix)
) STRICT;
CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
) STRICT;
CREATE TABLE dcr_attempts (
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL,
  at INTEGER NOT NULL
) STRICT;
CREATE INDEX dcr_attempts_address ON dcr_attempts(address, at);
CREATE TABLE auth_requests (
  id_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  target_slug TEXT,
  state TEXT,
  code_challenge TEXT NOT NULL,
  session_hash TEXT,
  client_name TEXT,
  address TEXT NOT NULL,
  shown_at INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX auth_requests_address ON auth_requests(address, created_at);
CREATE TABLE token_families (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  client_name TEXT NOT NULL,
  auth_epoch INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
) STRICT;
CREATE INDEX token_families_user ON token_families(user_id);
CREATE INDEX token_families_server ON token_families(server_id);
CREATE TABLE auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
  combined INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  auth_epoch INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  family_id INTEGER REFERENCES token_families(id) ON DELETE SET NULL
) STRICT;
CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id INTEGER NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX access_tokens_family ON access_tokens(family_id);
CREATE TABLE refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id INTEGER NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  replay TEXT
) STRICT;
CREATE INDEX refresh_tokens_family ON refresh_tokens(family_id);
CREATE TABLE known_clients (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  redirect_key TEXT NOT NULL,
  first_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, client_id, redirect_key)
) STRICT;
CREATE TABLE disconnect_links (
  token_hash TEXT PRIMARY KEY,
  family_id INTEGER NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
) STRICT;
