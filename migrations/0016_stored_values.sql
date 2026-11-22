ALTER TABLE users ADD COLUMN dek_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN dek_wrap TEXT;
ALTER TABLE users ADD COLUMN dek_salt TEXT;
ALTER TABLE users ADD COLUMN values_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN dek_wrap TEXT;
ALTER TABLE auth_codes ADD COLUMN dek_wrap TEXT;
ALTER TABLE access_tokens ADD COLUMN dek_wrap TEXT;
ALTER TABLE refresh_tokens ADD COLUMN dek_wrap TEXT;
CREATE TABLE user_header_values (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  header_id INTEGER NOT NULL REFERENCES server_headers(id) ON DELETE CASCADE,
  sealed TEXT NOT NULL,
  set_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, header_id)
) STRICT;
