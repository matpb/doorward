-- Keyed by server then time: a server filter reads its rows in the order the export and page sort them.
CREATE INDEX activity_server_at ON activity(server_id, at);

-- Deleting a server or user deletes its charts; each one removed is written to the log.
CREATE TRIGGER charts_removed_with_server_or_user AFTER DELETE ON charts
WHEN EXISTS (SELECT 1 FROM dashboards WHERE id = OLD.dashboard_id)
  AND ((OLD.server_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM servers WHERE id = OLD.server_id))
    OR (OLD.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users WHERE id = OLD.user_id)))
BEGIN
  INSERT INTO activity (at, kind, user_id, user_email, server_id, server_slug, tool, client,
    decision, outcome, detail, duration_ms)
  VALUES (CAST(strftime('%s', 'now') AS INTEGER), 'admin_change', NULL, '', NULL, '', '', '', '', '',
    'deleted chart ' || OLD.title || ' from dashboard '
    || (SELECT name FROM dashboards WHERE id = OLD.dashboard_id)
    || CASE WHEN OLD.server_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM servers WHERE id = OLD.server_id)
         THEN ': its server was deleted' ELSE ': its user was deleted' END,
    NULL);
END;
