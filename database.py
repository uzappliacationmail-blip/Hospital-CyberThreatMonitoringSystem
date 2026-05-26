"""
database.py — Hospital CTMS  |  Dual-Engine Database Layer
===========================================================
Strategy
  1. On startup, probe MySQL silently (5-second timeout).
  2. If MySQL is available  → use it as primary.
  3. If MySQL is missing/unreachable → fall back to SQLite automatically,
     with NO warning printed to stderr (only logged at DEBUG level).

Entities & integrity rules
  users        — unique user_id, username, name, role, email
  models       — unique model_id, model_name, accuracy, created_on
  traffic_logs — unique log_id, source_ip, destination_ip,
                 protocol, status, timestamp
  alerts       — unique alert_id, FK→log_id, FK→user_id, FK→model_id,
                 alert_type, severity, timestamp
  audit_log    — append-only event log
  kdd_runs / kdd_logs — KDDTest+ simulation results

Every save() function:
  • validates required fields & value constraints before touching the DB
  • enforces FK existence for alerts
  • returns {"status":"success","message":…, "<entity>_id":…} on success
  • raises IntegrityError (a ValueError subclass) with a precise message on failure
  • writes a structured INFO log line on every successful insert
"""

import sqlite3, json, hashlib, os, logging
from typing import Optional, Any

# ── Logger ────────────────────────────────────────────────────────────────────
log = logging.getLogger("ctms.db")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG  —  edit these or set env-vars
# ══════════════════════════════════════════════════════════════════════════════
MYSQL_CONFIG: dict = {
    "host":            os.getenv("CTMS_DB_HOST",     "localhost"),
    "port":            int(os.getenv("CTMS_DB_PORT", "3306")),
    "user":            os.getenv("CTMS_DB_USER",     "root"),
    "password":        os.getenv("CTMS_DB_PASSWORD", ""),
    "database":        os.getenv("CTMS_DB_NAME",     "hospital_ctms"),
    "charset":         "utf8mb4",
    "autocommit":      False,
    "connect_timeout": 5,
}

SQLITE_PATH: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "hospital_ctms.db"
)

# ══════════════════════════════════════════════════════════════════════════════
# ENGINE DETECTION  —  silent MySQL probe
# ══════════════════════════════════════════════════════════════════════════════
_engine: str = "sqlite"   # "mysql" | "sqlite"


def _try_mysql() -> bool:
    """
    Probe MySQL completely silently.
    Returns True and sets _engine="mysql" only when the full handshake succeeds.
    Any failure (missing driver, wrong host, wrong credentials, timeout, …)
    results in _engine staying "sqlite" — no output, no exception propagated.
    """
    global _engine
    try:
        import mysql.connector                      # type: ignore
        # First connect without specifying the database so we can CREATE it
        base_cfg = {k: v for k, v in MYSQL_CONFIG.items()
                if k not in ("database", "autocommit")}
        tmp = mysql.connector.connect(**base_cfg)
        cur = tmp.cursor()
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{MYSQL_CONFIG['database']}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        tmp.commit(); tmp.close()

        # Now connect to the database itself to confirm it is usable
        test = mysql.connector.connect(**MYSQL_CONFIG)
        test.close()

        _engine = "mysql"
        log.info("🐬  MySQL available — using MySQL as primary database")
        return True

    except ImportError as exc:
        _engine = "sqlite"
        log.warning(
            "MySQL connector not found — SQLite will be used. "
            "Install mysql-connector-python or run with a SQLite-only setup. "
            "Reason: %s",
            exc,
        )
        return False
    except Exception as exc:                         # ANY other failure → silent fallback
        _engine = "sqlite"
        log.warning(
            "MySQL probe failed — SQLite will be used. "
            "Check CTMS_DB_HOST/CTMS_DB_USER/CTMS_DB_PASSWORD and MySQL connectivity. "
            "Reason: %s",
            exc,
        )
        return False


# ══════════════════════════════════════════════════════════════════════════════
# CONNECTION FACTORY
# ══════════════════════════════════════════════════════════════════════════════

def get_conn():
    """Return an open connection for the active engine."""
    if _engine == "mysql":
        import mysql.connector                      # type: ignore
        return mysql.connector.connect(**MYSQL_CONFIG)
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _ph() -> str:
    """SQL placeholder for the active engine."""
    return "%s" if _engine == "mysql" else "?"


def _rows(cursor) -> list[dict]:
    """Normalise cursor output to list[dict] for both engines."""
    if _engine == "mysql":
        cols = [d[0] for d in cursor.description] if cursor.description else []
        return [dict(zip(cols, row)) for row in (cursor.fetchall() or [])]
    return [dict(r) for r in cursor.fetchall()]


def _one(cursor) -> Optional[dict]:
    rows = _rows(cursor)
    return rows[0] if rows else None


def _ts(v) -> str:
    return str(v) if v else ""


def hash_password(pw: str) -> str:
    return hashlib.sha256(("ctms_salt_" + pw).encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA  —  DDL for both engines
# ══════════════════════════════════════════════════════════════════════════════

_SQLITE_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    name       TEXT    NOT NULL DEFAULT '',
    role       TEXT    NOT NULL DEFAULT 'analyst'
                       CHECK(role IN ('admin','analyst','viewer')),
    email      TEXT    NOT NULL UNIQUE DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS models (
    model_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT    NOT NULL UNIQUE,
    accuracy   REAL    NOT NULL CHECK(accuracy >= 0 AND accuracy <= 1),
    created_on DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    log_id         INTEGER  PRIMARY KEY AUTOINCREMENT,
    source_ip      TEXT     NOT NULL DEFAULT '0.0.0.0',
    destination_ip TEXT     NOT NULL DEFAULT '0.0.0.0',
    protocol       TEXT     NOT NULL DEFAULT 'tcp'
                            CHECK(protocol IN ('tcp','udp','icmp','other')),
    status         TEXT     NOT NULL DEFAULT 'normal'
                            CHECK(status IN ('normal','anomaly','pending')),
    features       TEXT     NOT NULL,
    confidence     REAL     NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
    source         TEXT     NOT NULL DEFAULT 'manual',
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id   INTEGER  PRIMARY KEY AUTOINCREMENT,
    log_id     INTEGER  NOT NULL,
    user_id    INTEGER  NOT NULL,
    model_id   INTEGER  NOT NULL,
    alert_type TEXT     NOT NULL DEFAULT 'anomaly_detected',
    severity   TEXT     NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high','critical')),
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved   INTEGER  NOT NULL DEFAULT 0,
    FOREIGN KEY (log_id)   REFERENCES traffic_logs(log_id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id)  REFERENCES users(user_id)       ON DELETE RESTRICT,
    FOREIGN KEY (model_id) REFERENCES models(model_id)     ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER  PRIMARY KEY AUTOINCREMENT,
    username  TEXT     NOT NULL,
    action    TEXT     NOT NULL,
    detail    TEXT,
    ip        TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS kdd_runs (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    filename    TEXT,
    total_rows  INTEGER  DEFAULT 0,
    anomalies   INTEGER  DEFAULT 0,
    normals     INTEGER  DEFAULT 0,
    accuracy    REAL,
    precision_s REAL,
    recall      REAL,
    f1          REAL,
    started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME
);

CREATE TABLE IF NOT EXISTS kdd_logs (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER  NOT NULL,
    row_index   INTEGER,
    predicted   TEXT,
    actual      TEXT,
    confidence  REAL,
    response_ms REAL,
    correct     INTEGER,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES kdd_runs(id) ON DELETE CASCADE
);
"""

_MYSQL_TABLES: list[str] = [
    """CREATE TABLE IF NOT EXISTS users (
        user_id    INT AUTO_INCREMENT PRIMARY KEY,
        username   VARCHAR(80)  NOT NULL UNIQUE,
        password   VARCHAR(255) NOT NULL,
        name       VARCHAR(120) NOT NULL DEFAULT '',
        role       ENUM('admin','analyst','viewer') NOT NULL DEFAULT 'analyst',
        email      VARCHAR(255) NOT NULL UNIQUE DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS models (
        model_id   INT AUTO_INCREMENT PRIMARY KEY,
        model_name VARCHAR(120) NOT NULL UNIQUE,
        accuracy   FLOAT        NOT NULL,
        created_on DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active  TINYINT(1) NOT NULL DEFAULT 1,
        CONSTRAINT chk_model_acc CHECK (accuracy >= 0 AND accuracy <= 1)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS traffic_logs (
        log_id         INT AUTO_INCREMENT PRIMARY KEY,
        source_ip      VARCHAR(45)  NOT NULL DEFAULT '0.0.0.0',
        destination_ip VARCHAR(45)  NOT NULL DEFAULT '0.0.0.0',
        protocol       ENUM('tcp','udp','icmp','other') NOT NULL DEFAULT 'tcp',
        status         ENUM('normal','anomaly','pending') NOT NULL DEFAULT 'normal',
        features       TEXT         NOT NULL,
        confidence     FLOAT        NOT NULL,
        source         VARCHAR(20)  NOT NULL DEFAULT 'manual',
        timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT chk_log_conf CHECK (confidence >= 0 AND confidence <= 1)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS alerts (
        alert_id   INT AUTO_INCREMENT PRIMARY KEY,
        log_id     INT NOT NULL,
        user_id    INT NOT NULL,
        model_id   INT NOT NULL,
        alert_type VARCHAR(60) NOT NULL DEFAULT 'anomaly_detected',
        severity   ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
        timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved   TINYINT(1) NOT NULL DEFAULT 0,
        FOREIGN KEY (log_id)   REFERENCES traffic_logs(log_id) ON DELETE RESTRICT,
        FOREIGN KEY (user_id)  REFERENCES users(user_id)       ON DELETE RESTRICT,
        FOREIGN KEY (model_id) REFERENCES models(model_id)     ON DELETE RESTRICT
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS audit_log (
        id        INT AUTO_INCREMENT PRIMARY KEY,
        username  VARCHAR(80) NOT NULL,
        action    VARCHAR(80) NOT NULL,
        detail    TEXT,
        ip        VARCHAR(45),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS kdd_runs (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        filename    VARCHAR(255),
        total_rows  INT   DEFAULT 0,
        anomalies   INT   DEFAULT 0,
        normals     INT   DEFAULT 0,
        accuracy    FLOAT,
        precision_s FLOAT,
        recall      FLOAT,
        f1          FLOAT,
        started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        finished_at DATETIME
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS kdd_logs (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        run_id      INT NOT NULL,
        row_index   INT,
        predicted   VARCHAR(20),
        actual      VARCHAR(20),
        confidence  FLOAT,
        response_ms FLOAT,
        correct     TINYINT(1),
        timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (run_id) REFERENCES kdd_runs(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM EXCEPTION
# ══════════════════════════════════════════════════════════════════════════════

class IntegrityError(ValueError):
    """Raised by every save_*() on validation or FK failure."""
    def __init__(self, entity: str, message: str):
        self.entity  = entity
        self.message = message
        super().__init__(f"[{entity}] {message}")


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _require(entity: str, data: dict, fields: list[str]) -> None:
    """Raise IntegrityError if any required field is blank / None."""
    missing = [f for f in fields if not str(data.get(f) or "").strip()]
    if missing:
        raise IntegrityError(entity,
            f"Missing required fields: {', '.join(missing)}")


def _fk_exists(entity: str, table: str, col: str, val: Any) -> None:
    """Raise IntegrityError if the referenced FK row does not exist."""
    conn = get_conn(); cur = conn.cursor(); ph = _ph()
    try:
        cur.execute(f"SELECT 1 FROM {table} WHERE {col}={ph}", (val,))
        exists = cur.fetchone() is not None
    finally:
        conn.close()
    if not exists:
        raise IntegrityError("Alert",
            f"Referential integrity violation — {entity} "
            f"with {col}={val!r} does not exist in '{table}'")


def _severity_from_confidence(conf: float) -> str:
    if conf >= 0.95: return "critical"
    if conf >= 0.85: return "high"
    if conf >= 0.70: return "medium"
    return "low"


def _protocol_from_int(pt: int) -> str:
    return {0: "tcp", 1: "udp", 2: "icmp"}.get(int(pt), "other")


# ══════════════════════════════════════════════════════════════════════════════
# INIT  —  probe MySQL, fall back silently, create schema, seed defaults
# ══════════════════════════════════════════════════════════════════════════════

def init_db() -> None:
    """
    Initialise the database.
    Probes MySQL first; if unavailable, SQLite is used with zero noise.
    Creates all tables, seeds the default admin user and the SVC model entry.
    """
    _try_mysql()          # sets _engine; any failure is absorbed silently

    conn = get_conn()
    try:
        if _engine == "sqlite":
            conn.executescript(_SQLITE_SCHEMA)
            conn.commit()
        else:
            cur = conn.cursor()
            for ddl in _MYSQL_TABLES:
                cur.execute(ddl)
            conn.commit()
    finally:
        conn.close()

    _seed_defaults()

    eng = "MySQL" if _engine == "mysql" else "SQLite"
    print(f"✅  Database ready ({eng}).")
    log.info("Database initialised using %s", eng)


def _seed_defaults() -> None:
    """Insert admin user and default SVC model if not yet present."""
    ph = _ph(); conn = get_conn()
    try:
        cur = conn.cursor()

        # ── admin user ──────────────────────────────────────────────────────
        cur.execute("SELECT COUNT(*) FROM users")
        if (cur.fetchone()[0] if _engine == "mysql" else cur.fetchone()[0]) == 0:
            cur.execute(
                f"INSERT INTO users (username,password,name,role,email) "
                f"VALUES ({ph},{ph},{ph},{ph},{ph})",
                ("admin", hash_password("admin123"),
                 "System Administrator", "admin", "admin@hospital.ctms")
            )
            conn.commit()
            log.info("Seeded default admin user (admin / admin123)")
            print("🔑  Default admin  →  admin / admin123")

        # ── default model ────────────────────────────────────────────────────
        cur.execute("SELECT COUNT(*) FROM models")
        if (cur.fetchone()[0] if _engine == "mysql" else cur.fetchone()[0]) == 0:
            cur.execute(
                f"INSERT INTO models (model_name,accuracy,is_active) VALUES ({ph},{ph},1)",
                ("best_model_SVC", 0.97)
            )
            conn.commit()
            log.info("Seeded default model: best_model_SVC (accuracy=0.97)")

    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════════════════════

def create_user(username: str, password: str, role: str = "analyst",
                name: str = "", email: str = "") -> dict:
    """
    Insert a new user.  All fields are validated before the INSERT.
    Returns {"status":"success","message":…,"user_id":…,"entity":"User"}.
    Raises IntegrityError on validation or DB failure.
    """
    entity = "User"
    name  = name.strip()  or username
    email = email.strip() or f"{username}@hospital.ctms"

    _require(entity, {"username": username, "password": password, "role": role},
             ["username", "password", "role"])

    if role not in ("admin", "analyst", "viewer"):
        raise IntegrityError(entity,
            f"Invalid role '{role}'. Allowed: admin | analyst | viewer.")
    if len(password) < 6:
        raise IntegrityError(entity, "Password must be at least 6 characters.")

    ph = _ph(); conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO users (username,password,name,role,email) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph})",
            (username, hash_password(password), name, role, email)
        )
        conn.commit()
        uid = cur.lastrowid
        log.info("✅ User saved — user_id=%s username=%s role=%s email=%s",
                 uid, username, role, email)
        return {
            "status":  "success",
            "message": f"User '{username}' created successfully.",
            "user_id": uid,
            "entity":  entity,
        }
    except IntegrityError:
        conn.rollback(); raise
    except Exception as exc:
        conn.rollback()
        msg = str(exc)
        if "UNIQUE" in msg.upper() or "Duplicate" in msg:
            raise IntegrityError(entity,
                f"Username or email already exists: '{username}'")
        raise IntegrityError(entity, f"Database error: {msg}")
    finally:
        conn.close()


def verify_user(username: str, password: str) -> Optional[dict]:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(
        f"SELECT user_id, username, role FROM users "
        f"WHERE username={ph} AND password={ph}",
        (username, hash_password(password))
    )
    row = _one(cur); conn.close()
    if row:
        row["id"] = row["user_id"]   # backward-compat alias
    return row


def get_all_users() -> list[dict]:
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT user_id AS id, username, name, role, email, created_at "
        "FROM users ORDER BY created_at DESC"
    )
    rows = _rows(cur); conn.close()
    for r in rows:
        r["created_at"] = _ts(r.get("created_at"))
    return rows


def get_user_id_by_username(username: str) -> Optional[int]:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(f"SELECT user_id FROM users WHERE username={ph}", (username,))
    row = cur.fetchone(); conn.close()
    if row is None: return None
    return row["user_id"] if _engine == "sqlite" else row[0]


def delete_user(user_id: int) -> None:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(f"DELETE FROM users WHERE user_id={ph}", (user_id,))
        conn.commit()
    finally:
        conn.close()
    log.info("User deleted — user_id=%s", user_id)


# ══════════════════════════════════════════════════════════════════════════════
# MODELS
# ══════════════════════════════════════════════════════════════════════════════

def register_model(model_name: str, accuracy: float) -> dict:
    """
    Register an ML model entry.
    Returns {"status":"success","message":…,"model_id":…,"entity":"Model"}.
    Raises IntegrityError on validation or DB failure.
    """
    entity = "Model"
    _require(entity, {"model_name": model_name}, ["model_name"])
    if not (0.0 <= float(accuracy) <= 1.0):
        raise IntegrityError(entity,
            f"Accuracy {accuracy} is out of range [0.0, 1.0].")

    ph = _ph(); conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO models (model_name,accuracy,is_active) VALUES ({ph},{ph},1)",
            (model_name.strip(), float(accuracy))
        )
        conn.commit()
        mid = cur.lastrowid
        log.info("✅ Model saved — model_id=%s model_name=%s accuracy=%.4f",
                 mid, model_name, accuracy)
        return {
            "status":   "success",
            "message":  f"Model '{model_name}' registered successfully.",
            "model_id": mid,
            "entity":   entity,
        }
    except IntegrityError:
        conn.rollback(); raise
    except Exception as exc:
        conn.rollback()
        msg = str(exc)
        if "UNIQUE" in msg.upper() or "Duplicate" in msg:
            raise IntegrityError(entity,
                f"Model name already registered: '{model_name}'")
        raise IntegrityError(entity, f"Database error: {msg}")
    finally:
        conn.close()


def get_active_model() -> Optional[dict]:
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT model_id, model_name, accuracy, created_on FROM models "
        "WHERE is_active=1 ORDER BY created_on DESC LIMIT 1"
    )
    row = _one(cur); conn.close()
    if row:
        row["created_on"] = _ts(row.get("created_on"))
    return row


def get_all_models() -> list[dict]:
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT model_id, model_name, accuracy, created_on, is_active "
        "FROM models ORDER BY created_on DESC"
    )
    rows = _rows(cur); conn.close()
    for r in rows:
        r["created_on"] = _ts(r.get("created_on"))
    return rows


def get_model_id_by_name(model_name: str) -> Optional[int]:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(f"SELECT model_id FROM models WHERE model_name={ph}", (model_name,))
    row = cur.fetchone(); conn.close()
    if row is None: return None
    return row["model_id"] if _engine == "sqlite" else row[0]


# ══════════════════════════════════════════════════════════════════════════════
# TRAFFIC LOGS
# ══════════════════════════════════════════════════════════════════════════════

def save_log(features: dict, label: str, confidence: float,
             source: str = "manual",
             source_ip: str = "0.0.0.0",
             destination_ip: str = "0.0.0.0") -> dict:
    """
    Persist one classified traffic record.
    Every row gets: unique log_id (AUTO), source_ip, destination_ip,
    protocol (derived from features), status (=label), timestamp (DEFAULT).
    Returns {"status":"success","message":…,"log_id":…,"entity":"TrafficLog"}.
    Raises IntegrityError on validation or DB failure.
    """
    entity   = "TrafficLog"
    protocol = _protocol_from_int(features.get("protocol_type", 0))
    status   = label if label in ("normal", "anomaly") else "pending"

    _require(entity,
             {"source_ip": source_ip, "destination_ip": destination_ip,
              "protocol": protocol,   "status": status},
             ["source_ip", "destination_ip", "protocol", "status"])

    if not (0.0 <= float(confidence) <= 1.0):
        raise IntegrityError(entity,
            f"Confidence {confidence} is out of range [0.0, 1.0].")

    ph = _ph(); conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO traffic_logs "
            f"(source_ip,destination_ip,protocol,status,features,confidence,source) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (source_ip, destination_ip, protocol, status,
             json.dumps(features), float(confidence), source)
        )
        conn.commit()
        log_id = cur.lastrowid
        log.info(
            "✅ TrafficLog saved — log_id=%s src=%s dst=%s "
            "protocol=%s status=%s confidence=%.1f%%",
            log_id, source_ip, destination_ip, protocol, status, confidence * 100
        )
        return {
            "status":  "success",
            "message": f"TrafficLog #{log_id} saved successfully.",
            "log_id":  log_id,
            "entity":  entity,
        }
    except IntegrityError:
        conn.rollback(); raise
    except Exception as exc:
        conn.rollback()
        raise IntegrityError(entity, f"Database error: {exc}")
    finally:
        conn.close()


def get_traffic_summary() -> list[dict]:
    conn = get_conn(); cur = conn.cursor()
    if _engine == "mysql":
        cur.execute("""
            SELECT DATE_FORMAT(timestamp,'%H:00') AS hour,
                   SUM(status='normal')  AS normal,
                   SUM(status='anomaly') AS anomaly
            FROM traffic_logs
            WHERE timestamp >= NOW() - INTERVAL 24 HOUR
            GROUP BY hour ORDER BY hour
        """)
    else:
        cur.execute("""
            SELECT strftime('%H:00', timestamp) AS hour,
                   SUM(CASE WHEN status='normal'  THEN 1 ELSE 0 END) AS normal,
                   SUM(CASE WHEN status='anomaly' THEN 1 ELSE 0 END) AS anomaly
            FROM traffic_logs
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour
        """)
    rows = _rows(cur); conn.close()
    
    # Ensure all 24 hours are present, even if empty
    hours_dict = {f"{h:02d}:00": {"hour": f"{h:02d}:00", "normal": 0, "anomaly": 0} for h in range(24)}
    for r in rows:
        hour_key = str(r.get("hour", "00:00"))
        hours_dict[hour_key] = {
            "hour": hour_key,
            "normal":  int(r.get("normal")  or 0),
            "anomaly": int(r.get("anomaly") or 0)
        }
    
    return sorted(hours_dict.values(), key=lambda x: x["hour"])


def get_total_counts() -> dict:
    conn = get_conn(); cur = conn.cursor()
    if _engine == "mysql":
        cur.execute("""
            SELECT COUNT(*) AS total,
                   SUM(status='normal')  AS normal,
                   SUM(status='anomaly') AS anomaly
            FROM traffic_logs
        """)
    else:
        cur.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='normal'  THEN 1 ELSE 0 END) AS normal,
                   SUM(CASE WHEN status='anomaly' THEN 1 ELSE 0 END) AS anomaly
            FROM traffic_logs
        """)
    row = _one(cur); conn.close()
    return {k: int(row[k] or 0) for k in row} if row else \
           {"total": 0, "normal": 0, "anomaly": 0}


def get_log_id_latest() -> Optional[int]:
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT log_id FROM traffic_logs ORDER BY log_id DESC LIMIT 1")
    row = cur.fetchone(); conn.close()
    if row is None: return None
    return row["log_id"] if _engine == "sqlite" else row[0]


# ══════════════════════════════════════════════════════════════════════════════
# ALERTS  —  full referential integrity enforcement
# ══════════════════════════════════════════════════════════════════════════════

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


def save_alert(log_id: int, user_id: int, model_id: int,
               alert_type: str = "anomaly_detected",
               severity: Optional[str] = None,
               confidence: float = 0.0) -> dict:
    """
    Persist a new Alert with full referential integrity checks.

    Validates before any INSERT:
      ① alert_type is non-empty
      ② severity is a recognised value
      ③ log_id   → traffic_logs.log_id  row exists
      ④ user_id  → users.user_id        row exists
      ⑤ model_id → models.model_id      row exists

    Returns {"status":"success","message":…,"alert_id":…, …,"entity":"Alert"}.
    Raises IntegrityError (entity="Alert") with a precise message on any failure.
    """
    entity = "Alert"

    # ── ① alert_type ─────────────────────────────────────────────────────────
    if not str(alert_type or "").strip():
        raise IntegrityError(entity, "alert_type must not be empty.")

    # ── ② severity ───────────────────────────────────────────────────────────
    sev = (severity or _severity_from_confidence(float(confidence))).strip()
    if sev not in _VALID_SEVERITIES:
        raise IntegrityError(entity,
            f"Invalid severity '{sev}'. Allowed: {_VALID_SEVERITIES}.")

    # ── ③ ④ ⑤  FK existence ──────────────────────────────────────────────────
    _fk_exists("TrafficLog", "traffic_logs", "log_id",  log_id)
    _fk_exists("User",       "users",        "user_id", user_id)
    _fk_exists("Model",      "models",       "model_id", model_id)

    # ── INSERT ────────────────────────────────────────────────────────────────
    ph = _ph(); conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"INSERT INTO alerts (log_id,user_id,model_id,alert_type,severity) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph})",
            (log_id, user_id, model_id, alert_type.strip(), sev)
        )
        conn.commit()
        aid = cur.lastrowid
        log.info(
            "✅ Alert saved — alert_id=%s log_id=%s user_id=%s model_id=%s "
            "type=%s severity=%s",
            aid, log_id, user_id, model_id, alert_type, sev
        )
        return {
            "status":     "success",
            "message":    f"Alert #{aid} saved successfully.",
            "alert_id":   aid,
            "log_id":     log_id,
            "user_id":    user_id,
            "model_id":   model_id,
            "alert_type": alert_type.strip(),
            "severity":   sev,
            "entity":     entity,
        }
    except IntegrityError:
        conn.rollback(); raise
    except Exception as exc:
        conn.rollback()
        raise IntegrityError(entity, f"Database error: {exc}")
    finally:
        conn.close()


def get_alerts(limit: int = 100) -> list[dict]:
    """Alert list joined with traffic_logs, users, models. Only unresolved alerts."""
    conn = get_conn(); cur = conn.cursor(); ph = _ph()
    cur.execute(f"""
        SELECT
            a.alert_id, a.alert_type, a.severity, a.timestamp, a.resolved,
            t.log_id, t.source_ip, t.destination_ip, t.protocol, t.status,
            t.confidence, t.source,
            u.username, u.user_id,
            m.model_name, m.model_id
        FROM alerts a
        JOIN traffic_logs t ON a.log_id   = t.log_id
        JOIN users         u ON a.user_id  = u.user_id
        JOIN models        m ON a.model_id = m.model_id
        WHERE a.resolved = 0
        ORDER BY a.timestamp DESC LIMIT {ph}
    """, (limit,))
    rows = _rows(cur); conn.close()
    for r in rows:
        r["timestamp"]  = _ts(r.get("timestamp"))
        r["confidence"] = round(float(r.get("confidence", 0)) * 100, 1)
    return rows


def get_all_alerts_admin(limit: int = 200) -> list[dict]:
    conn = get_conn(); cur = conn.cursor(); ph = _ph()
    cur.execute(f"""
        SELECT
            a.alert_id, a.alert_type, a.severity, a.resolved,
            a.timestamp AS alert_ts,
            t.log_id, t.source_ip, t.destination_ip, t.protocol,
            t.status, t.confidence, t.source, t.timestamp AS log_ts,
            u.user_id, u.username, u.name AS user_name, u.role,
            m.model_id, m.model_name, m.accuracy AS model_accuracy
        FROM alerts a
        JOIN traffic_logs t ON a.log_id   = t.log_id
        JOIN users         u ON a.user_id  = u.user_id
        JOIN models        m ON a.model_id = m.model_id
        ORDER BY a.alert_id DESC LIMIT {ph}
    """, (limit,))
    rows = _rows(cur); conn.close()
    for r in rows:
        r["alert_ts"]   = _ts(r.get("alert_ts"))
        r["log_ts"]     = _ts(r.get("log_ts"))
        r["confidence"] = round(float(r.get("confidence", 0)) * 100, 1)
    return rows


def resolve_alert(alert_id: int) -> dict:
    """Mark an alert as resolved/reviewed."""
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            f"UPDATE alerts SET resolved=1 WHERE alert_id={ph}",
            (alert_id,)
        )
        conn.commit()
        log.info("✅ Alert resolved — alert_id=%s", alert_id)
        return {"status": "success", "message": f"Alert #{alert_id} marked as resolved."}
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

def write_audit(username: str, action: str,
                detail: str = "", ip: str = "") -> None:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            f"INSERT INTO audit_log (username,action,detail,ip) "
            f"VALUES ({ph},{ph},{ph},{ph})",
            (username, action, detail, ip)
        )
        conn.commit()
    finally:
        conn.close()


def get_audit_log(limit: int = 60) -> list[dict]:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(
        f"SELECT username,action,detail,ip,timestamp FROM audit_log "
        f"ORDER BY timestamp DESC LIMIT {ph}", (limit,)
    )
    rows = _rows(cur); conn.close()
    for r in rows:
        r["timestamp"] = _ts(r.get("timestamp"))
    return rows


# ══════════════════════════════════════════════════════════════════════════════
# KDD SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

def kdd_start_run(filename: str) -> int:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(f"INSERT INTO kdd_runs (filename) VALUES ({ph})", (filename,))
    conn.commit(); run_id = cur.lastrowid; conn.close()
    return run_id


def kdd_log_row(run_id: int, row_index: int, predicted: str, actual: str,
                confidence: float, response_ms: float) -> None:
    correct = 1 if predicted == actual else 0
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            f"INSERT INTO kdd_logs "
            f"(run_id,row_index,predicted,actual,confidence,response_ms,correct) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (run_id, row_index, predicted, actual, confidence, response_ms, correct)
        )
        conn.commit()
    finally:
        conn.close()


def kdd_finish_run(run_id: int, total: int, anomalies: int, normals: int,
                   accuracy: float, precision: float,
                   recall: float, f1: float) -> None:
    ph = _ph()
    now = "NOW()" if _engine == "mysql" else "datetime('now')"
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            f"UPDATE kdd_runs SET total_rows={ph},anomalies={ph},normals={ph},"
            f"accuracy={ph},precision_s={ph},recall={ph},f1={ph},"
            f"finished_at={now} WHERE id={ph}",
            (total, anomalies, normals, accuracy, precision, recall, f1, run_id)
        )
        conn.commit()
    finally:
        conn.close()


def get_kdd_runs(limit: int = 10) -> list[dict]:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(
        f"SELECT * FROM kdd_runs ORDER BY started_at DESC LIMIT {ph}", (limit,)
    )
    rows = _rows(cur); conn.close()
    for r in rows:
        r["started_at"]  = _ts(r.get("started_at"))
        r["finished_at"] = _ts(r.get("finished_at"))
        for f in ("accuracy", "precision_s", "recall", "f1"):
            r[f] = round(float(r[f]), 4) if r.get(f) is not None else None
    return rows


def get_kdd_run_detail(run_id: int, limit: int = 200) -> list[dict]:
    ph = _ph(); conn = get_conn(); cur = conn.cursor()
    cur.execute(
        f"SELECT row_index,predicted,actual,confidence,response_ms,correct,timestamp "
        f"FROM kdd_logs WHERE run_id={ph} ORDER BY row_index LIMIT {ph}",
        (run_id, limit)
    )
    rows = _rows(cur); conn.close()
    for r in rows:
        r["timestamp"] = _ts(r.get("timestamp"))
    return rows
