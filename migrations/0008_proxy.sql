CREATE TABLE tool_catalog (
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  name TEXT NOT NULL,
  definition TEXT NOT NULL,
  PRIMARY KEY (server_id, name)
) STRICT;
CREATE TABLE upstream_sessions (
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  id_hash TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id INTEGER NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (server_id, id_hash)
) STRICT;
ALTER TABLE servers ADD COLUMN catalog_at INTEGER;
ALTER TABLE servers ADD COLUMN catalog_error TEXT;
