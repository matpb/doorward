CREATE INDEX oauth_clients_unused ON oauth_clients(created_at) WHERE used_at IS NULL;
