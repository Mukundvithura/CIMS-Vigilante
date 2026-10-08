-- CIMS schema. Matches the ER diagram in docs/04_data_dfd.md.
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  role          TEXT    NOT NULL CHECK (role IN ('REPORTER','ANALYST','MANAGER','ADMIN','AUDITOR')),
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incidents (
  id          INTEGER PRIMARY KEY,
  title       TEXT    NOT NULL,
  description TEXT    NOT NULL,
  severity    TEXT    CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status      TEXT    NOT NULL DEFAULT 'NEW'
              CHECK (status IN ('NEW','TRIAGED','ASSIGNED','INVESTIGATING','RESOLVED','CLOSED')),
  reporter_id INTEGER NOT NULL REFERENCES users(id),
  assignee_id INTEGER REFERENCES users(id),
  created_at  TEXT    NOT NULL,
  updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id          INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  filename    TEXT    NOT NULL,
  stored_name TEXT    NOT NULL UNIQUE,
  sha256      TEXT    NOT NULL,
  size        INTEGER NOT NULL,
  uploaded_by INTEGER NOT NULL REFERENCES users(id),
  uploaded_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
  id          INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  author_id   INTEGER NOT NULL REFERENCES users(id),
  note        TEXT    NOT NULL,
  created_at  TEXT    NOT NULL
);

-- Append-only, hash-chained audit trail (SR-05).
CREATE TABLE IF NOT EXISTS audit_log (
  id        INTEGER PRIMARY KEY,
  ts        TEXT    NOT NULL,
  actor_id  INTEGER,
  action    TEXT    NOT NULL,
  target    TEXT    NOT NULL,
  details   TEXT    NOT NULL,
  prev_hash TEXT    NOT NULL,
  hash      TEXT    NOT NULL
);

-- Immutability: evidence, notes and audit rows can never be edited or deleted through the DB.
CREATE TRIGGER IF NOT EXISTS notes_no_update    BEFORE UPDATE ON notes     BEGIN SELECT RAISE(ABORT, 'notes are immutable'); END;
CREATE TRIGGER IF NOT EXISTS notes_no_delete    BEFORE DELETE ON notes     BEGIN SELECT RAISE(ABORT, 'notes are immutable'); END;
