USE airport_security;

-- FR01-FR06, SR04-SR07: idempotent migration for deployments created before the notes extension.
CREATE TABLE IF NOT EXISTS event_notes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  scan_event_id INT NOT NULL,
  author_operator_id INT NOT NULL,
  note_text TEXT NOT NULL,
  visibility ENUM('private', 'shared') NOT NULL DEFAULT 'private',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL,
  INDEX idx_event_notes_event_created (scan_event_id, created_at),
  INDEX idx_event_notes_author (author_operator_id),
  CONSTRAINT fk_event_notes_event
    FOREIGN KEY (scan_event_id) REFERENCES scan_events(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_event_notes_author
    FOREIGN KEY (author_operator_id) REFERENCES operators(id)
    ON DELETE RESTRICT
);
