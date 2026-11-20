DROP TABLE login_blocks;
DROP TABLE login_failures;
CREATE TABLE login_failures (
  id INTEGER PRIMARY KEY,
  account_hash TEXT NOT NULL,
  address TEXT NOT NULL,
  at INTEGER NOT NULL
) STRICT;
CREATE INDEX login_failures_address ON login_failures(address);
CREATE INDEX login_failures_pair ON login_failures(account_hash, address);
CREATE INDEX login_failures_at ON login_failures(at);
