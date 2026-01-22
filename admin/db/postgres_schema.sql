-- MMMBC Admin: Postgres schema for announcements + bulletins
--
-- This schema matches the JSON shapes exported to the website:
-- - announcements.json: { posts: [{ id, title, body, createdAt, startsAt?, expiresAt?, source? }] }
-- - bulletins.json:     { bulletins: [{ id, title, originalName, fileName, mimeType, url, startsAt, endsAt, linkedAnnouncementId?, createdAt }] }

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  starts_at TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NULL,
  source TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_announcements_created_at ON announcements(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_announcements_starts_at ON announcements(starts_at);
CREATE INDEX IF NOT EXISTS idx_announcements_expires_at ON announcements(expires_at);

CREATE TABLE IF NOT EXISTS bulletins (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  original_name TEXT NULL,
  file_name TEXT NOT NULL,
  mime_type TEXT NULL,
  url TEXT NOT NULL,
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  linked_announcement_id TEXT NULL REFERENCES announcements(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bulletins_window ON bulletins(starts_at, ends_at);
CREATE INDEX IF NOT EXISTS idx_bulletins_created_at ON bulletins(created_at DESC);
