ALTER TABLE protected_links ADD COLUMN recipient_email TEXT;

CREATE INDEX IF NOT EXISTS protected_links_recipient_idx
  ON protected_links(recipient_email);

CREATE INDEX IF NOT EXISTS click_events_verdict_time_idx
  ON click_events(verdict, clicked_at);