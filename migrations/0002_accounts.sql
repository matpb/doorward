CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','user')),
  disabled INTEGER NOT NULL DEFAULT 0,
  auth_epoch INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX users_one_owner ON users(role) WHERE role = 'owner';
CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_epoch INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE login_blocks (
  account_hash TEXT PRIMARY KEY,
  failures INTEGER NOT NULL,
  last_failed_at INTEGER NOT NULL
) STRICT;
CREATE TABLE login_failures (
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL,
  at INTEGER NOT NULL
) STRICT;
CREATE INDEX login_failures_address ON login_failures(address, at);
