CREATE TABLE invitation_servers (
  invitation_id INTEGER NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  PRIMARY KEY (invitation_id, server_id)
) STRICT;
CREATE INDEX invitation_servers_server ON invitation_servers(server_id);
CREATE TABLE invitation_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invitation_id INTEGER NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
  effect TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
  tool TEXT,
  created_at INTEGER NOT NULL,
  CHECK (tool IS NULL OR server_id IS NOT NULL)
) STRICT;
CREATE UNIQUE INDEX invitation_rules_target
  ON invitation_rules(invitation_id, COALESCE(server_id, 0), COALESCE(tool, ''));
CREATE INDEX invitation_rules_server ON invitation_rules(server_id);
