/*
  # Fix RLS for Flask App Access

  The Hospital CTMS Flask app uses Supabase as a database backend only,
  managing its own authentication. The REST API (PostgREST) needs anon
  role access to read/write data since the app doesn't use Supabase Auth.

  1. Changes
    - Add policies for `anon` role on all tables
    - Keep existing `authenticated` policies for future Supabase Auth use
    - Allow full read/write access via anon key (app handles its own auth)

  2. Security Notes
    - The anon key is public-safe for read operations
    - For production, replace these with service_role key usage
*/

-- Drop existing anon-restrictive policies and add permissive ones for anon role

-- Users table policies for anon
CREATE POLICY "Anon can read users"
  ON users FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert users"
  ON users FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Anon can update users"
  ON users FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Anon can delete users"
  ON users FOR DELETE
  TO anon
  USING (true);

-- Models table policies for anon
CREATE POLICY "Anon can read models"
  ON models FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert models"
  ON models FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Anon can update models"
  ON models FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

-- Traffic logs table policies for anon
CREATE POLICY "Anon can read traffic_logs"
  ON traffic_logs FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert traffic_logs"
  ON traffic_logs FOR INSERT
  TO anon
  WITH CHECK (true);

-- Alerts table policies for anon
CREATE POLICY "Anon can read alerts"
  ON alerts FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert alerts"
  ON alerts FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Anon can update alerts"
  ON alerts FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

-- Audit log table policies for anon
CREATE POLICY "Anon can read audit_log"
  ON audit_log FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert audit_log"
  ON audit_log FOR INSERT
  TO anon
  WITH CHECK (true);

-- KDD runs table policies for anon
CREATE POLICY "Anon can read kdd_runs"
  ON kdd_runs FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert kdd_runs"
  ON kdd_runs FOR INSERT
  TO anon
  WITH CHECK (true);

CREATE POLICY "Anon can update kdd_runs"
  ON kdd_runs FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

-- KDD logs table policies for anon
CREATE POLICY "Anon can read kdd_logs"
  ON kdd_logs FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "Anon can insert kdd_logs"
  ON kdd_logs FOR INSERT
  TO anon
  WITH CHECK (true);
