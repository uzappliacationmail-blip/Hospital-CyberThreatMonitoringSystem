#!/usr/bin/env python3
"""
setup_db.py — Hospital CTMS  |  Database Setup & Verification Script
=====================================================================
Run this once before starting the server, or any time you want to
verify the database state.

Usage:
    python setup_db.py                  # auto-detect engine, create all tables
    python setup_db.py --verify         # verify all tables + integrity
    python setup_db.py --seed-demo      # also insert demo data
    python setup_db.py --reset          # drop + recreate SQLite DB (SQLite only)

Exit codes:
    0 — success
    1 — fatal error (DB unreachable, schema mismatch, integrity failure)
"""

import sys, os, argparse, logging, sqlite3, json, datetime

# Make sure we can import from the same directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Logging (always to stdout so it's visible in CI / Docker) ────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("ctms.setup")

# Promote ctms.db logger to DEBUG so setup shows all detail
logging.getLogger("ctms.db").setLevel(logging.DEBUG)

BANNER = """
╔══════════════════════════════════════════════════════╗
║   Hospital Cyber Threat Monitoring System            ║
║   Database Setup & Verification  —  setup_db.py     ║
╚══════════════════════════════════════════════════════╝"""

EXPECTED_TABLES = {
    "users":        ["user_id", "username", "name", "role", "email", "created_at"],
    "models":       ["model_id", "model_name", "accuracy", "created_on", "is_active"],
    "traffic_logs": ["log_id", "source_ip", "destination_ip", "protocol",
                     "status", "features", "confidence", "source", "timestamp"],
    "alerts":       ["alert_id", "log_id", "user_id", "model_id",
                     "alert_type", "severity", "timestamp", "resolved"],
    "audit_log":    ["id", "username", "action", "detail", "ip", "timestamp"],
    "kdd_runs":     ["id", "filename", "total_rows", "anomalies", "normals",
                     "accuracy", "precision_s", "recall", "f1",
                     "started_at", "finished_at"],
    "kdd_logs":     ["id", "run_id", "row_index", "predicted", "actual",
                     "confidence", "response_ms", "correct", "timestamp"],
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Init (creates schema + seeds defaults)
# ══════════════════════════════════════════════════════════════════════════════

def step_init() -> bool:
    log.info("Step 1 — Initialising database …")
    try:
        from database import init_db
        init_db()
        log.info("Step 1 — ✅  init_db() completed without errors")
        return True
    except Exception as exc:
        log.error("Step 1 — ❌  init_db() raised: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Table & column verification
# ══════════════════════════════════════════════════════════════════════════════

def _sqlite_columns(conn, table: str) -> list[str]:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return [r["name"] for r in cur.fetchall()]


def _mysql_columns(conn, table: str, db_name: str) -> list[str]:
    cur = conn.cursor()
    cur.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION",
        (db_name, table)
    )
    return [r[0] for r in cur.fetchall()]


def step_verify_schema() -> bool:
    import database as db
    log.info("Step 2 — Verifying schema (engine=%s) …", db._engine)
    ok = True

    conn = db.get_conn()
    try:
        for table, expected_cols in EXPECTED_TABLES.items():
            if db._engine == "sqlite":
                actual = _sqlite_columns(conn, table)
            else:
                actual = _mysql_columns(conn, table, db.MYSQL_CONFIG["database"])

            if not actual:
                log.error("  ❌  Table '%s' — MISSING", table)
                ok = False
                continue

            missing = [c for c in expected_cols if c not in actual]
            if missing:
                log.error("  ❌  Table '%s' — missing columns: %s", table, missing)
                ok = False
            else:
                log.info("  ✅  Table '%-14s' — all %d expected columns present",
                         table, len(expected_cols))
    finally:
        conn.close()

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Referential integrity spot-check
# ══════════════════════════════════════════════════════════════════════════════

def step_verify_integrity() -> bool:
    import database as db
    log.info("Step 3 — Verifying referential integrity …")
    ok = True
    conn = db.get_conn(); ph = db._ph()

    try:
        # Orphaned alerts (log_id missing)
        if db._engine == "mysql":
            conn.cursor().execute("""
                SELECT COUNT(*) FROM alerts a
                LEFT JOIN traffic_logs t ON a.log_id = t.log_id
                WHERE t.log_id IS NULL
            """)
        else:
            cur = conn.cursor()
            cur.execute("""
                SELECT COUNT(*) FROM alerts a
                LEFT JOIN traffic_logs t ON a.log_id = t.log_id
                WHERE t.log_id IS NULL
            """)
            n = cur.fetchone()[0]
            if n:
                log.error("  ❌  %d orphaned alert(s) with missing log_id", n)
                ok = False
            else:
                log.info("  ✅  No orphaned alerts (log_id)")

        # Orphaned alerts (user_id missing)
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM alerts a
            LEFT JOIN users u ON a.user_id = u.user_id
            WHERE u.user_id IS NULL
        """)
        n = cur.fetchone()[0]
        if n:
            log.error("  ❌  %d orphaned alert(s) with missing user_id", n)
            ok = False
        else:
            log.info("  ✅  No orphaned alerts (user_id)")

        # Orphaned alerts (model_id missing)
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM alerts a
            LEFT JOIN models m ON a.model_id = m.model_id
            WHERE m.model_id IS NULL
        """)
        n = cur.fetchone()[0]
        if n:
            log.error("  ❌  %d orphaned alert(s) with missing model_id", n)
            ok = False
        else:
            log.info("  ✅  No orphaned alerts (model_id)")

        # Duplicate unique fields
        cur.execute("SELECT COUNT(*) FROM (SELECT username FROM users GROUP BY username HAVING COUNT(*)>1)")
        if cur.fetchone()[0]:
            log.error("  ❌  Duplicate usernames detected in users table")
            ok = False
        else:
            log.info("  ✅  No duplicate usernames")

        cur.execute("SELECT COUNT(*) FROM (SELECT model_name FROM models GROUP BY model_name HAVING COUNT(*)>1)")
        if cur.fetchone()[0]:
            log.error("  ❌  Duplicate model_names detected in models table")
            ok = False
        else:
            log.info("  ✅  No duplicate model names")

    finally:
        conn.close()

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Row counts summary
# ══════════════════════════════════════════════════════════════════════════════

def step_row_counts() -> None:
    import database as db
    log.info("Step 4 — Row counts:")
    conn = db.get_conn(); cur = conn.cursor()
    for table in EXPECTED_TABLES:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        n = cur.fetchone()[0]
        log.info("  %-14s  %d row(s)", table, n)
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — End-to-end entity save test (with full rollback)
# ══════════════════════════════════════════════════════════════════════════════

def step_e2e_integrity_test() -> bool:
    """
    Insert one of each entity, verify all constraints fire correctly,
    then delete the test rows.  Returns True if all checks pass.
    """
    import database as db
    from database import (
        create_user, register_model, save_log, save_alert,
        get_user_id_by_username, get_model_id_by_name, IntegrityError,
    )

    log.info("Step 5 — End-to-end integrity test …")
    ok     = True
    ts     = datetime.datetime.now().strftime("%H%M%S")
    u_name = f"_setup_test_{ts}"
    m_name = f"_test_model_{ts}"

    # — User ——————————————————————————————————————————————
    try:
        r = create_user(u_name, "testpass99", "analyst",
                        "Setup Tester", f"{u_name}@test.ctms")
        assert r["status"] == "success" and r["user_id"]
        log.info("  ✅  User save OK — user_id=%s", r["user_id"])
        test_uid = r["user_id"]
    except Exception as e:
        log.error("  ❌  User save FAILED: %s", e); ok = False; return ok

    # — User validation: bad role —
    try:
        create_user(f"bad_{ts}", "pass123", "god")
        log.error("  ❌  Bad role was not rejected"); ok = False
    except IntegrityError:
        log.info("  ✅  Bad role rejected correctly")

    # — User validation: short password —
    try:
        create_user(f"badpw_{ts}", "abc", "analyst")
        log.error("  ❌  Short password was not rejected"); ok = False
    except IntegrityError:
        log.info("  ✅  Short password rejected correctly")

    # — Model ——————————————————————————————————————————————
    try:
        r = register_model(m_name, 0.912)
        assert r["status"] == "success" and r["model_id"]
        log.info("  ✅  Model save OK — model_id=%s", r["model_id"])
        test_mid = r["model_id"]
    except Exception as e:
        log.error("  ❌  Model save FAILED: %s", e); ok = False; return ok

    # — Model validation: bad accuracy —
    try:
        register_model(f"bad_acc_{ts}", 1.5)
        log.error("  ❌  Bad accuracy was not rejected"); ok = False
    except IntegrityError:
        log.info("  ✅  Bad accuracy rejected correctly")

    # — TrafficLog ——————————————————————————————————————————
    try:
        features = {
            "duration":0.4,"protocol_type":0,"src_bytes":512,"dst_bytes":1024,
            "flag":1,"land":0,"wrong_fragment":0,"urgent":0,"hot":2,"num_failed_logins":0
        }
        r = save_log(features, "anomaly", 0.971, "setup_test",
                     "192.168.99.1", "10.0.99.1")
        assert r["status"] == "success" and r["log_id"]
        log.info("  ✅  TrafficLog save OK — log_id=%s", r["log_id"])
        test_lid = r["log_id"]
    except Exception as e:
        log.error("  ❌  TrafficLog save FAILED: %s", e); ok = False; return ok

    # — TrafficLog validation: bad confidence —
    try:
        save_log(features, "normal", 2.0, "setup_test")
        log.error("  ❌  Bad confidence was not rejected"); ok = False
    except IntegrityError:
        log.info("  ✅  Bad confidence rejected correctly")

    # — Alert ——————————————————————————————————————————————
    try:
        r = save_alert(test_lid, test_uid, test_mid,
                       "setup_test_alert", confidence=0.971)
        assert r["status"] == "success" and r["alert_id"]
        log.info("  ✅  Alert save OK — alert_id=%s severity=%s",
                 r["alert_id"], r["severity"])
        test_aid = r["alert_id"]
    except Exception as e:
        log.error("  ❌  Alert save FAILED: %s", e); ok = False

    # — Alert FK: bad log_id —
    try:
        save_alert(999999, test_uid, test_mid, "bad_fk_log")
        log.error("  ❌  Bad log_id FK was not rejected"); ok = False
    except IntegrityError as e:
        log.info("  ✅  Bad log_id FK rejected: %s", e)

    # — Alert FK: bad user_id —
    try:
        save_alert(test_lid, 999999, test_mid, "bad_fk_user")
        log.error("  ❌  Bad user_id FK was not rejected"); ok = False
    except IntegrityError as e:
        log.info("  ✅  Bad user_id FK rejected: %s", e)

    # — Alert FK: bad model_id —
    try:
        save_alert(test_lid, test_uid, 999999, "bad_fk_model")
        log.error("  ❌  Bad model_id FK was not rejected"); ok = False
    except IntegrityError as e:
        log.info("  ✅  Bad model_id FK rejected: %s", e)

    # — Alert: empty alert_type —
    try:
        save_alert(test_lid, test_uid, test_mid, "")
        log.error("  ❌  Empty alert_type was not rejected"); ok = False
    except IntegrityError:
        log.info("  ✅  Empty alert_type rejected correctly")

    # — Cleanup test rows ——————————————————————————————————
    conn = db.get_conn(); ph = db._ph()
    try:
        # alerts first (FK constraint)
        conn.execute(f"DELETE FROM alerts       WHERE alert_id={ph}", (test_aid,))
        conn.execute(f"DELETE FROM traffic_logs WHERE log_id={ph}",   (test_lid,))
        conn.execute(f"DELETE FROM models       WHERE model_id={ph}", (test_mid,))
        conn.execute(f"DELETE FROM users        WHERE user_id={ph}",  (test_uid,))
        conn.commit()
        log.info("  🧹  Test rows cleaned up")
    except Exception as e:
        log.warning("  ⚠️   Cleanup partial: %s", e)
        conn.rollback()
    finally:
        conn.close()

    return ok


# ══════════════════════════════════════════════════════════════════════════════
# OPTIONAL — seed demo data
# ══════════════════════════════════════════════════════════════════════════════

def step_seed_demo() -> None:
    from database import (
        create_user, register_model, save_log, save_alert,
        get_user_id_by_username, get_active_model, IntegrityError,
    )
    log.info("Step 6 — Seeding demo data …")
    try:
        create_user("dr_smith",  "securepass1", "analyst",
                    "Dr. Alice Smith",   "dr.smith@hospital.ctms")
        log.info("  ✅  Demo user 'dr_smith' created")
    except IntegrityError:
        log.info("  ℹ️   Demo user 'dr_smith' already exists — skipped")

    try:
        register_model("SVC_RBF_v2", 0.982)
        log.info("  ✅  Demo model 'SVC_RBF_v2' registered")
    except IntegrityError:
        log.info("  ℹ️   Demo model 'SVC_RBF_v2' already exists — skipped")

    uid = get_user_id_by_username("admin")
    m   = get_active_model()
    mid = m["model_id"] if m else 1

    pairs = [
        ({"duration":0.5,"protocol_type":0,"src_bytes":512,"dst_bytes":1024,
          "flag":1,"land":0,"wrong_fragment":0,"urgent":0,"hot":1,"num_failed_logins":0},
         "normal", 0.946, "192.168.1.10", "10.0.0.5"),
        ({"duration":0,"protocol_type":1,"src_bytes":0,"dst_bytes":0,
          "flag":3,"land":0,"wrong_fragment":3,"urgent":0,"hot":0,"num_failed_logins":9},
         "anomaly", 0.986, "10.0.0.99", "192.168.1.1"),
        ({"duration":0,"protocol_type":0,"src_bytes":9999,"dst_bytes":0,
          "flag":2,"land":0,"wrong_fragment":0,"urgent":1,"hot":90,"num_failed_logins":5},
         "anomaly", 0.993, "172.16.0.55", "192.168.1.254"),
    ]
    for feat, label, conf, src, dst in pairs:
        try:
            lr = save_log(feat, label, conf, "demo", src, dst)
            log.info("  ✅  Demo TrafficLog saved — log_id=%s status=%s",
                     lr["log_id"], label)
            if label == "anomaly":
                ar = save_alert(lr["log_id"], uid, mid,
                                "demo_anomaly", confidence=conf)
                log.info("  ✅  Demo Alert saved — alert_id=%s severity=%s",
                         ar["alert_id"], ar["severity"])
        except Exception as e:
            log.warning("  ⚠️   Demo row skipped: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# RESET (SQLite only)
# ══════════════════════════════════════════════════════════════════════════════

def step_reset() -> bool:
    import database as db
    if db._engine == "mysql":
        log.error("--reset is only supported for SQLite. Use MySQL DROP/CREATE manually.")
        return False
    db_file = db.SQLITE_PATH
    if os.path.exists(db_file):
        os.remove(db_file)
        log.info("Deleted existing SQLite database: %s", db_file)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hospital CTMS — Database setup and verification"
    )
    parser.add_argument("--verify",    action="store_true",
                        help="Verify schema + referential integrity after setup")
    parser.add_argument("--seed-demo", action="store_true",
                        help="Insert demo users, models, traffic logs, and alerts")
    parser.add_argument("--reset",     action="store_true",
                        help="Delete and recreate the SQLite database (SQLite only)")
    args = parser.parse_args()

    print(BANNER)
    print()
    all_ok = True

    # Optional: reset first
    if args.reset:
        log.info("── RESET ──────────────────────────────────────────────")
        if not step_reset():
            return 1

    # Always: init
    log.info("── INIT ───────────────────────────────────────────────")
    if not step_init():
        return 1

    # Verify schema
    if args.verify or args.reset:
        print()
        log.info("── SCHEMA VERIFICATION ────────────────────────────────")
        if not step_verify_schema():
            all_ok = False

        print()
        log.info("── INTEGRITY CHECK ────────────────────────────────────")
        if not step_verify_integrity():
            all_ok = False

        print()
        log.info("── ROW COUNTS ─────────────────────────────────────────")
        step_row_counts()

        print()
        log.info("── END-TO-END ENTITY TESTS ────────────────────────────")
        if not step_e2e_integrity_test():
            all_ok = False

    # Optional: seed demo data
    if args.seed_demo:
        print()
        log.info("── DEMO DATA ──────────────────────────────────────────")
        step_seed_demo()

    print()
    if all_ok:
        log.info("══ ALL CHECKS PASSED ✅ ════════════════════════════════")
        print("\n✅  Database is ready. Run:  python start.py\n")
    else:
        log.error("══ SOME CHECKS FAILED ❌ ═══════════════════════════════")
        print("\n❌  Fix the errors above before starting the server.\n")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
