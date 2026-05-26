"""
database.py — Hospital CTMS  |  Supabase REST API Database Layer
==================================================================
Strategy
  Connect to Supabase via REST API (PostgREST) using the anon key.
  All tables are already created via migration.

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

import os
import json
import hashlib
import logging
import urllib.request
import urllib.error
from typing import Optional, Any

# ── Logger ────────────────────────────────────────────────────────────────────
log = logging.getLogger("ctms.db")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG  —  Supabase REST API connection
# ══════════════════════════════════════════════════════════════════════════════

_engine: str = "supabase"

# Load from .env
SUPABASE_URL: str = ""
SUPABASE_ANON_KEY: str = ""

_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("VITE_SUPABASE_URL="):
                SUPABASE_URL = line.split("=", 1)[1]
            elif line.startswith("VITE_SUPABASE_ANON_KEY="):
                SUPABASE_ANON_KEY = line.split("=", 1)[1]


def _get_headers() -> dict:
    """Return headers for Supabase REST API calls."""
    return {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def _request(method: str, table: str, data: dict = None, query: str = "") -> list[dict]:
    """Make a REST API request to Supabase PostgREST."""
    url = f"{SUPABASE_URL}/rest/v1/{table}{query}"
    headers = _get_headers()

    req_data = None
    if data:
        req_data = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            if body:
                return json.loads(body)
            return []
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        log.error("HTTP %d: %s", e.code, body)
        raise
    except Exception as e:
        log.error("Request failed: %s", e)
        raise


def _request_one(method: str, table: str, data: dict = None, query: str = "") -> Optional[dict]:
    """Make a REST API request expecting a single result."""
    results = _request(method, table, data, query)
    if results and len(results) > 0:
        return results[0]
    return None


def _ts(v) -> str:
    return str(v) if v else ""


def hash_password(pw: str) -> str:
    return hashlib.sha256(("ctms_salt_" + pw).encode()).hexdigest()


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
    try:
        result = _request_one("GET", table, query=f'?{col}=eq.{val}&select={col}')
        if not result:
            raise IntegrityError("Alert",
                f"Referential integrity violation — {entity} "
                f"with {col}={val!r} does not exist in '{table}'")
    except Exception as e:
        if "IntegrityError" in str(type(e)):
            raise
        raise IntegrityError(entity, f"Database error checking FK: {e}")


def _severity_from_confidence(conf: float) -> str:
    if conf >= 0.95: return "critical"
    if conf >= 0.85: return "high"
    if conf >= 0.70: return "medium"
    return "low"


def _protocol_from_int(pt: int) -> str:
    return {0: "tcp", 1: "udp", 2: "icmp"}.get(int(pt), "other")


# ══════════════════════════════════════════════════════════════════════════════
# INIT
# ══════════════════════════════════════════════════════════════════════════════

def init_db() -> None:
    """
    Initialise the database connection.
    Tables are already created in Supabase via migration.
    """
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env")

    try:
        _request("GET", "users", query="?limit=1")
        print("✅  Database ready (Supabase PostgreSQL).")
        log.info("Database initialised using Supabase PostgreSQL")
    except Exception as e:
        log.error("Failed to connect to Supabase: %s", e)
        raise


# ══════════════════════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════════════════════

def create_user(username: str, password: str, role: str = "analyst",
                name: str = "", email: str = "") -> dict:
    """
    Insert a new user.
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

    try:
        result = _request_one("POST", "users", data={
            "username": username,
            "password": hash_password(password),
            "name": name,
            "role": role,
            "email": email
        })
        uid = result.get("user_id")
        log.info("✅ User saved — user_id=%s username=%s role=%s email=%s",
                 uid, username, role, email)
        return {
            "status":  "success",
            "message": f"User '{username}' created successfully.",
            "user_id": uid,
            "entity":  entity,
        }
    except urllib.error.HTTPError as e:
        if e.code == 409:
            raise IntegrityError(entity,
                f"Username or email already exists: '{username}'")
        raise IntegrityError(entity, f"Database error: {e}")
    except Exception as exc:
        raise IntegrityError(entity, f"Database error: {exc}")


def verify_user(username: str, password: str) -> Optional[dict]:
    try:
        result = _request_one("GET", "users", query=
            f'?username=eq.{username}&password=eq.{hash_password(password)}&select=user_id,username,role')
        if result:
            result["id"] = result["user_id"]
        return result
    except:
        return None


def get_all_users() -> list[dict]:
    try:
        rows = _request("GET", "users", query="?select=user_id,username,name,role,email,created_at&order=created_at.desc")
        for r in rows:
            r["created_at"] = _ts(r.get("created_at"))
            r["id"] = r.get("user_id")
        return rows
    except:
        return []


def get_user_id_by_username(username: str) -> Optional[int]:
    try:
        result = _request_one("GET", "users", query=f'?username=eq.{username}&select=user_id')
        if result:
            return result.get("user_id")
    except:
        pass
    return None


def delete_user(user_id: int) -> None:
    try:
        _request("DELETE", "users", query=f"?user_id=eq.{user_id}")
        log.info("User deleted — user_id=%s", user_id)
    except Exception as e:
        log.error("Failed to delete user: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# MODELS
# ══════════════════════════════════════════════════════════════════════════════

def register_model(model_name: str, accuracy: float) -> dict:
    """
    Register an ML model entry.
    """
    entity = "Model"
    _require(entity, {"model_name": model_name}, ["model_name"])
    if not (0.0 <= float(accuracy) <= 1.0):
        raise IntegrityError(entity,
            f"Accuracy {accuracy} is out of range [0.0, 1.0].")

    try:
        result = _request_one("POST", "models", data={
            "model_name": model_name.strip(),
            "accuracy": float(accuracy),
            "is_active": True
        })
        mid = result.get("model_id")
        log.info("✅ Model saved — model_id=%s model_name=%s accuracy=%.4f",
                 mid, model_name, accuracy)
        return {
            "status":   "success",
            "message":  f"Model '{model_name}' registered successfully.",
            "model_id": mid,
            "entity":   entity,
        }
    except urllib.error.HTTPError as e:
        if e.code == 409:
            raise IntegrityError(entity,
                f"Model name already registered: '{model_name}'")
        raise IntegrityError(entity, f"Database error: {e}")
    except Exception as exc:
        raise IntegrityError(entity, f"Database error: {exc}")


def get_active_model() -> Optional[dict]:
    try:
        result = _request_one("GET", "models", query=
            "?is_active=eq.true&select=model_id,model_name,accuracy,created_on&order=created_on.desc&limit=1")
        if result:
            result["created_on"] = _ts(result.get("created_on"))
        return result
    except:
        return None


def get_all_models() -> list[dict]:
    try:
        rows = _request("GET", "models", query="?select=model_id,model_name,accuracy,created_on,is_active&order=created_on.desc")
        for r in rows:
            r["created_on"] = _ts(r.get("created_on"))
            r["is_active"] = bool(r.get("is_active"))
        return rows
    except:
        return []


def get_model_id_by_name(model_name: str) -> Optional[int]:
    try:
        result = _request_one("GET", "models", query=f'?model_name=eq.{model_name}&select=model_id')
        if result:
            return result.get("model_id")
    except:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# TRAFFIC LOGS
# ══════════════════════════════════════════════════════════════════════════════

def save_log(features: dict, label: str, confidence: float,
             source: str = "manual",
             source_ip: str = "0.0.0.0",
             destination_ip: str = "0.0.0.0") -> dict:
    """
    Persist one classified traffic record.
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

    try:
        result = _request_one("POST", "traffic_logs", data={
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "status": status,
            "features": json.dumps(features),
            "confidence": float(confidence),
            "source": source
        })
        log_id = result.get("log_id")
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
    except Exception as exc:
        raise IntegrityError(entity, f"Database error: {exc}")


def get_traffic_summary() -> list[dict]:
    try:
        rows = _request("GET", "traffic_logs", query=
            "?select=timestamp,status&timestamp=gte.24 hours ago&order=timestamp")
    except:
        rows = []

    hours_dict = {f"{h:02d}:00": {"hour": f"{h:02d}:00", "normal": 0, "anomaly": 0} for h in range(24)}

    for r in rows:
        ts = r.get("timestamp", "")
        if ts:
            hour = ts[11:16] if len(ts) > 16 else "00:00"
            hour = hour[:3] + "00" if len(hour) >= 3 else "00:00"
            hour_key = hour
            if r.get("status") == "normal":
                hours_dict[hour_key]["normal"] += 1
            elif r.get("status") == "anomaly":
                hours_dict[hour_key]["anomaly"] += 1

    return sorted(hours_dict.values(), key=lambda x: x["hour"])


def get_total_counts() -> dict:
    try:
        # Use the RPC function or manual count
        rows = _request("GET", "traffic_logs", query="?select=status")
        total = len(rows)
        normal = sum(1 for r in rows if r.get("status") == "normal")
        anomaly = sum(1 for r in rows if r.get("status") == "anomaly")
        return {"total": total, "normal": normal, "anomaly": anomaly}
    except:
        return {"total": 0, "normal": 0, "anomaly": 0}


def get_log_id_latest() -> Optional[int]:
    try:
        result = _request_one("GET", "traffic_logs", query="?select=log_id&order=log_id.desc&limit=1")
        if result:
            return result.get("log_id")
    except:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ══════════════════════════════════════════════════════════════════════════════

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


def save_alert(log_id: int, user_id: int, model_id: int,
               alert_type: str = "anomaly_detected",
               severity: Optional[str] = None,
               confidence: float = 0.0) -> dict:
    """
    Persist a new Alert with full referential integrity checks.
    """
    entity = "Alert"

    if not str(alert_type or "").strip():
        raise IntegrityError(entity, "alert_type must not be empty.")

    sev = (severity or _severity_from_confidence(float(confidence))).strip()
    if sev not in _VALID_SEVERITIES:
        raise IntegrityError(entity,
            f"Invalid severity '{sev}'. Allowed: {_VALID_SEVERITIES}.")

    _fk_exists("TrafficLog", "traffic_logs", "log_id", log_id)
    _fk_exists("User", "users", "user_id", user_id)
    _fk_exists("Model", "models", "model_id", model_id)

    try:
        result = _request_one("POST", "alerts", data={
            "log_id": log_id,
            "user_id": user_id,
            "model_id": model_id,
            "alert_type": alert_type.strip(),
            "severity": sev
        })
        aid = result.get("alert_id")
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
    except Exception as exc:
        raise IntegrityError(entity, f"Database error: {exc}")


def get_alerts(limit: int = 100) -> list[dict]:
    """
    Alert list joined with traffic_logs, users, models.
    Note: PostgREST doesn't support joins directly, so we fetch alerts
    and then manually join the data.
    """
    try:
        alerts = _request("GET", "alerts", query=
            f"?resolved=eq.false&select=alert_id,alert_type,severity,timestamp,resolved,log_id,user_id,model_id&order=timestamp.desc&limit={limit}")

        # Fetch related data
        for a in alerts:
            a["timestamp"] = _ts(a.get("timestamp"))

            # Get traffic log
            if a.get("log_id"):
                tl = _request_one("GET", "traffic_logs", query=
                    f'?log_id=eq.{a["log_id"]}&select=log_id,source_ip,destination_ip,protocol,status,confidence,source')
                if tl:
                    a["source_ip"] = tl.get("source_ip")
                    a["destination_ip"] = tl.get("destination_ip")
                    a["protocol"] = tl.get("protocol")
                    a["status"] = tl.get("status")
                    a["confidence"] = round(float(tl.get("confidence", 0)) * 100, 1)
                    a["source"] = tl.get("source")

            # Get user
            if a.get("user_id"):
                u = _request_one("GET", "users", query=
                    f'?user_id=eq.{a["user_id"]}&select=user_id,username')
                if u:
                    a["username"] = u.get("username")

            # Get model
            if a.get("model_id"):
                m = _request_one("GET", "models", query=
                    f'?model_id=eq.{a["model_id"]}&select=model_id,model_name')
                if m:
                    a["model_name"] = m.get("model_name")

        return alerts
    except:
        return []


def get_all_alerts_admin(limit: int = 200) -> list[dict]:
    try:
        logs = _request("GET", "traffic_logs", query="?select=log_id,source_ip,destination_ip,protocol,status,confidence,source,timestamp")
        alerts = _request("GET", "alerts", query=f"?select=alert_id,alert_type,severity,resolved,timestamp,log_id,user_id,model_id&order=alert_id.desc&limit={limit}")
        users = _request("GET", "users", query="?select=user_id,username,name,role")
        models = _request("GET", "models", query="?select=model_id,model_name,accuracy")

        log_map = {l["log_id"]: l for l in logs}
        user_map = {u["user_id"]: u for u in users}
        model_map = {m["model_id"]: m for m in models}

        for a in alerts:
            a["alert_ts"] = _ts(a.get("timestamp"))
            a["resolved"] = bool(a.get("resolved"))

            tl = log_map.get(a.get("log_id"), {})
            a["log_ts"] = _ts(tl.get("timestamp"))
            a["source_ip"] = tl.get("source_ip")
            a["destination_ip"] = tl.get("destination_ip")
            a["protocol"] = tl.get("protocol")
            a["status"] = tl.get("status")
            a["confidence"] = round(float(tl.get("confidence", 0)) * 100, 1)
            a["source"] = tl.get("source")

            u = user_map.get(a.get("user_id"), {})
            a["username"] = u.get("username")
            a["user_name"] = u.get("name")
            a["role"] = u.get("role")

            m = model_map.get(a.get("model_id"), {})
            a["model_name"] = m.get("model_name")
            a["model_accuracy"] = m.get("accuracy")

        return alerts
    except:
        return []


def resolve_alert(alert_id: int) -> dict:
    try:
        _request("PATCH", "alerts", query=f"?alert_id=eq.{alert_id}", data={"resolved": True})
        log.info("✅ Alert resolved — alert_id=%s", alert_id)
        return {"status": "success", "message": f"Alert #{alert_id} marked as resolved."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

def write_audit(username: str, action: str, detail: str = "", ip: str = "") -> None:
    try:
        _request_one("POST", "audit_log", data={
            "username": username,
            "action": action,
            "detail": detail,
            "ip": ip
        })
    except Exception as e:
        log.error("Failed to write audit log: %s", e)


def get_audit_log(limit: int = 60) -> list[dict]:
    try:
        rows = _request("GET", "audit_log", query=f"?select=username,action,detail,ip,timestamp&order=timestamp.desc&limit={limit}")
        for r in rows:
            r["timestamp"] = _ts(r.get("timestamp"))
        return rows
    except:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# KDD SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

def kdd_start_run(filename: str) -> int:
    try:
        result = _request_one("POST", "kdd_runs", data={"filename": filename})
        return result.get("id")
    except:
        return 0


def kdd_log_row(run_id: int, row_index: int, predicted: str, actual: str,
                confidence: float, response_ms: float) -> None:
    try:
        _request_one("POST", "kdd_logs", data={
            "run_id": run_id,
            "row_index": row_index,
            "predicted": predicted,
            "actual": actual,
            "confidence": confidence,
            "response_ms": response_ms,
            "correct": predicted == actual
        })
    except Exception as e:
        log.error("Failed to log KDD row: %s", e)


def kdd_finish_run(run_id: int, total: int, anomalies: int, normals: int,
                   accuracy: float, precision: float,
                   recall: float, f1: float) -> None:
    try:
        _request("PATCH", "kdd_runs", query=f"?id=eq.{run_id}", data={
            "total_rows": total,
            "anomalies": anomalies,
            "normals": normals,
            "accuracy": accuracy,
            "precision_s": precision,
            "recall": recall,
            "f1": f1
        })
    except Exception as e:
        log.error("Failed to finish KDD run: %s", e)


def get_kdd_runs(limit: int = 10) -> list[dict]:
    try:
        rows = _request("GET", "kdd_runs", query=f"?select=*&order=started_at.desc&limit={limit}")
        for r in rows:
            r["started_at"] = _ts(r.get("started_at"))
            r["finished_at"] = _ts(r.get("finished_at"))
            for f in ("accuracy", "precision_s", "recall", "f1"):
                r[f] = round(float(r[f]), 4) if r.get(f) is not None else None
        return rows
    except:
        return []


def get_kdd_run_detail(run_id: int, limit: int = 200) -> list[dict]:
    try:
        rows = _request("GET", "kdd_logs", query=f"?run_id=eq.{run_id}&select=row_index,predicted,actual,confidence,response_ms,correct,timestamp&order=row_index&limit={limit}")
        for r in rows:
            r["timestamp"] = _ts(r.get("timestamp"))
        return rows
    except:
        return []
