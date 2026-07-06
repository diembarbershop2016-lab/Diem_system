CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  price INTEGER NOT NULL DEFAULT 0,
  duration INTEGER NOT NULL DEFAULT 0,
  color TEXT NOT NULL DEFAULT '#1A1916',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS log_entries (
  id TEXT PRIMARY KEY,
  service_id TEXT,
  service_name_snapshot TEXT,
  date DATE NOT NULL,
  time TIME NOT NULL,
  price INTEGER NOT NULL DEFAULT 0,
  tip INTEGER NOT NULL DEFAULT 0,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS log_entries_date_idx ON log_entries (date);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
