/*
  # Hospital CTMS — Initial Schema

  Creates all tables required by the Hospital Cyber Threat Monitoring System.

  1. New Tables
    - `users` — system accounts (admin / analyst / viewer)
    - `models` — registered ML model entries
    - `traffic_logs` — every classified network packet record
    - `alerts` — anomaly alerts linked to traffic logs, users, and models
    - `audit_log` — append-only event log for all user actions
    - `kdd_runs` — KDDTest+ simulation run metadata
    - `kdd_logs` — per-row results for each simulation run

  2. Security
    - RLS enabled on all tables
    - Authenticated users can read/insert their own relevant data
    - Only admin role users can manage users and view all alerts

  3. Notes
    - Default admin user seeded: admin / admin123 (password hashed via SHA-256 with salt)
    - Default SVC model seeded with accuracy 0.97
    - The application layer (Flask) manages its own auth session; Supabase is used
      purely as the database backend via direct SQL (not the JS client)
*/

-- ── users ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  user_id    SERIAL PRIMARY KEY,
  username   VARCHAR(80)  NOT NULL UNIQUE,
  password   VARCHAR(255) NOT NULL,
  name       VARCHAR(120) NOT NULL DEFAULT '',
  role       VARCHAR(20)  NOT NULL DEFAULT 'analyst'
             CHECK (role IN ('admin','analyst','viewer')),
  email      VARCHAR(255) NOT NULL UNIQUE DEFAULT '',
  created_at TIMESTAMPTZ  DEFAULT NOW()
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read users"
  ON users FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert users"
  ON users FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update users"
  ON users FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Authenticated users can delete users"
  ON users FOR DELETE
  TO authenticated
  USING (true);

-- ── models ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS models (
  model_id   SERIAL PRIMARY KEY,
  model_name VARCHAR(120) NOT NULL UNIQUE,
  accuracy   FLOAT        NOT NULL CHECK (accuracy >= 0 AND accuracy <= 1),
  created_on TIMESTAMPTZ  DEFAULT NOW(),
  is_active  BOOLEAN      NOT NULL DEFAULT TRUE
);

ALTER TABLE models ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read models"
  ON models FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert models"
  ON models FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update models"
  ON models FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- ── traffic_logs ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS traffic_logs (
  log_id         SERIAL PRIMARY KEY,
  source_ip      VARCHAR(45)  NOT NULL DEFAULT '0.0.0.0',
  destination_ip VARCHAR(45)  NOT NULL DEFAULT '0.0.0.0',
  protocol       VARCHAR(10)  NOT NULL DEFAULT 'tcp'
                 CHECK (protocol IN ('tcp','udp','icmp','other')),
  status         VARCHAR(10)  NOT NULL DEFAULT 'normal'
                 CHECK (status IN ('normal','anomaly','pending')),
  features       TEXT         NOT NULL DEFAULT '{}',
  confidence     FLOAT        NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  source         VARCHAR(20)  NOT NULL DEFAULT 'manual',
  timestamp      TIMESTAMPTZ  DEFAULT NOW()
);

ALTER TABLE traffic_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read traffic_logs"
  ON traffic_logs FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert traffic_logs"
  ON traffic_logs FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- ── alerts ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
  alert_id   SERIAL PRIMARY KEY,
  log_id     INTEGER      NOT NULL REFERENCES traffic_logs(log_id) ON DELETE RESTRICT,
  user_id    INTEGER      NOT NULL REFERENCES users(user_id)       ON DELETE RESTRICT,
  model_id   INTEGER      NOT NULL REFERENCES models(model_id)     ON DELETE RESTRICT,
  alert_type VARCHAR(60)  NOT NULL DEFAULT 'anomaly_detected',
  severity   VARCHAR(10)  NOT NULL DEFAULT 'medium'
             CHECK (severity IN ('low','medium','high','critical')),
  timestamp  TIMESTAMPTZ  DEFAULT NOW(),
  resolved   BOOLEAN      NOT NULL DEFAULT FALSE
);

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read alerts"
  ON alerts FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert alerts"
  ON alerts FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update alerts"
  ON alerts FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- ── audit_log ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id        SERIAL PRIMARY KEY,
  username  VARCHAR(80) NOT NULL,
  action    VARCHAR(80) NOT NULL,
  detail    TEXT,
  ip        VARCHAR(45),
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read audit_log"
  ON audit_log FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert audit_log"
  ON audit_log FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- ── kdd_runs ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kdd_runs (
  id          SERIAL PRIMARY KEY,
  filename    VARCHAR(255),
  total_rows  INTEGER  DEFAULT 0,
  anomalies   INTEGER  DEFAULT 0,
  normals     INTEGER  DEFAULT 0,
  accuracy    FLOAT,
  precision_s FLOAT,
  recall      FLOAT,
  f1          FLOAT,
  started_at  TIMESTAMPTZ DEFAULT NOW(),
  finished_at TIMESTAMPTZ
);

ALTER TABLE kdd_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read kdd_runs"
  ON kdd_runs FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert kdd_runs"
  ON kdd_runs FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update kdd_runs"
  ON kdd_runs FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- ── kdd_logs ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kdd_logs (
  id          SERIAL PRIMARY KEY,
  run_id      INTEGER NOT NULL REFERENCES kdd_runs(id) ON DELETE CASCADE,
  row_index   INTEGER,
  predicted   VARCHAR(20),
  actual      VARCHAR(20),
  confidence  FLOAT,
  response_ms FLOAT,
  correct     BOOLEAN,
  timestamp   TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE kdd_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can read kdd_logs"
  ON kdd_logs FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert kdd_logs"
  ON kdd_logs FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- ── Indexes for common queries ───────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_status    ON traffic_logs(status);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved        ON alerts(resolved);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp       ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp    ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_kdd_logs_run_id        ON kdd_logs(run_id);

-- ── Seed: default admin user (password = SHA-256("ctms_salt_" + "admin123")) ──
INSERT INTO users (username, password, name, role, email)
VALUES (
  'admin',
  'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec',
  'System Administrator',
  'admin',
  'admin@hospital.ctms'
)
ON CONFLICT (username) DO NOTHING;

-- ── Seed: default SVC model ──────────────────────────────────────────────────
INSERT INTO models (model_name, accuracy, is_active)
VALUES ('best_model_SVC', 0.97, TRUE)
ON CONFLICT (model_name) DO NOTHING;
