CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  markdown TEXT NOT NULL,
  published_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscribers (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'unsubscribed')),
  confirm_hash TEXT,
  consent_at TEXT NOT NULL,
  confirmed_at TEXT
);

CREATE TABLE IF NOT EXISTS unsubscribe_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE,
  created_at TEXT NOT NULL,
  FOREIGN KEY (email) REFERENCES subscribers(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS protected_links (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL,
  target_url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_cache (
  url_hash TEXT PRIMARY KEY,
  scan_id TEXT,
  verdict TEXT NOT NULL,
  reason TEXT NOT NULL,
  checked_at INTEGER NOT NULL,
  joe_checked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  url_hash TEXT PRIMARY KEY,
  encrypted_url TEXT NOT NULL,
  web_risk_done INTEGER NOT NULL DEFAULT 0,
  urlscan_id TEXT,
  urlscan_done INTEGER NOT NULL DEFAULT 0,
  joe_required INTEGER NOT NULL DEFAULT 0,
  joe_submission_id TEXT,
  joe_webids TEXT NOT NULL DEFAULT '[]',
  joe_done INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  next_run_at INTEGER NOT NULL,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS click_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id TEXT NOT NULL,
  clicked_at TEXT NOT NULL,
  verdict TEXT NOT NULL,
  provider TEXT NOT NULL,
  reason TEXT NOT NULL,
  FOREIGN KEY (link_id) REFERENCES protected_links(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS newsletter_sends (
  post_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  recipient_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  error TEXT,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS click_events_link_idx ON click_events(link_id);
CREATE INDEX IF NOT EXISTS subscribers_status_idx ON subscribers(status);
CREATE INDEX IF NOT EXISTS scan_jobs_next_run_idx ON scan_jobs(next_run_at);

INSERT OR IGNORE INTO posts (id, slug, title, summary, markdown, published_at)
VALUES (
  '9e3bdc89-8b5e-49b0-8a98-511e598a6ba9',
  'welcome-to-the-journal',
  'Welcome to the journal',
  'A small, calm place for thoughtful updates.',
  'This is the starter post. Use the protected editor to publish your own article and send it to confirmed subscribers.\n\nWhen a published post is emailed, external links are rewritten to the blog''s own protected links.\n\n[Visit an example website](https://example.com/)',
  '2026-01-01T00:00:00.000Z'
);