-- Keyed by server then time: a server filter reads its rows in the order the export and page sort them.
CREATE INDEX activity_server_at ON activity(server_id, at);
-- Server rows are read through activity_server_at, which also serves a server alone.
DROP INDEX activity_server;
