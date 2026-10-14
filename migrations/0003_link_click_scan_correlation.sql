ALTER TABLE click_events ADD COLUMN url_hash TEXT;

CREATE INDEX IF NOT EXISTS click_events_url_hash_idx
  ON click_events(url_hash, verdict);