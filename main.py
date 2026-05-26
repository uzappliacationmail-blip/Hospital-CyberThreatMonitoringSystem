"""
Hospital Cyber Threat Monitoring System — main.py
Flask application: all routes, session handling, model inference, API endpoints.
"""

import os, sys, pickle, json, csv, io, time, secrets, datetime, logging
from collections import defaultdict
import numpy as np
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, g, send_from_directory)
from functools import wraps
from database import (
    init_db, IntegrityError,
    save_log, get_alerts, get_all_alerts_admin,
    get_traffic_summary, get_total_counts,
    verify_user, write_audit, get_audit_log,
    get_all_users, create_user, delete_user, get_user_id_by_username,
    register_model, get_active_model, get_all_models, get_model_id_by_name,
    save_alert, resolve_alert,
    kdd_start_run, kdd_log_row, kdd_finish_run, get_kdd_runs, get_kdd_run_detail,
    _severity_from_confidence,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S", stream=sys.stdout,
)
log = logging.getLogger("ctms.api")

# ── App ───────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
            template_folder=BASE_DIR,   # HTML files in root
            static_folder=BASE_DIR,     # CSS/JS files in root
            static_url_path="")

app.secret_key = os.getenv("CTMS_SECRET", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(hours=1)

# ── Model ─────────────────────────────────────────────────────────────────────
_model = None

def load_model():
    global _model
    for fname in ("best_model_SVC.pkl", "model.pkl"):
        path = os.path.join(BASE_DIR, fname)
        if not os.path.exists(path):
            continue
        for enc in (None, "latin1"):
            try:
                with open(path, "rb") as f:
                    _model = pickle.load(f) if enc is None else pickle.load(f, encoding=enc)
                log.info("✅  Model loaded: %s", fname)
                return
            except Exception as e:
                log.debug("Load %s enc=%s failed: %s", fname, enc, e)
    log.warning("No model file found — generating demo SVC")
    _generate_demo_model()

def _generate_demo_model():
    global _model
    from sklearn.svm import SVC
    rng = np.random.default_rng(42)
    normal = np.column_stack([
        rng.uniform(0,5,400), rng.integers(0,2,400).astype(float),
        rng.uniform(0,5000,400), rng.uniform(0,10000,400),
        np.ones(400), np.zeros(400), np.zeros(400), np.zeros(400),
        rng.integers(0,10,400).astype(float), np.zeros(400)])
    attack = np.column_stack([
        rng.uniform(0,.01,200), rng.integers(0,3,200).astype(float),
        rng.uniform(0,100,200), np.zeros(200),
        rng.integers(2,6,200).astype(float), rng.integers(0,2,200).astype(float),
        rng.integers(0,4,200).astype(float), rng.integers(0,3,200).astype(float),
        rng.integers(50,100,200).astype(float), rng.integers(3,10,200).astype(float)])
    X = np.vstack([normal, attack]); y = np.array([0]*400+[1]*200)
    clf = SVC(kernel="rbf", C=1.0, gamma="scale", probability=True, random_state=42)
    clf.fit(X, y)
    path = os.path.join(BASE_DIR, "best_model_SVC.pkl")
    with open(path, "wb") as f: pickle.dump(clf, f, protocol=2)
    _model = clf
    log.info("✅  Demo SVC model generated: best_model_SVC.pkl")

load_model()

# ── Rate limiting ─────────────────────────────────────────────────────────────
_rate: dict = defaultdict(list)
RATE_LIMIT, RATE_WINDOW = 120, 60

def _check_rate(ip: str):
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < RATE_WINDOW]
    if len(_rate[ip]) >= RATE_LIMIT:
        return False
    _rate[ip].append(now)
    return True

# ── KDD helpers ───────────────────────────────────────────────────────────────
_PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2}
_FLAG_MAP  = {"SF":1,"S0":2,"REJ":3,"RSTO":4,"RSTR":5,"SH":6,"S1":7,"S2":8,"S3":9,"OTH":0}

def _kdd_features(row):
    try:
        return {
            "duration":          float(row[0]),
            "protocol_type":     _PROTO_MAP.get(str(row[1]).strip().lower(), 0),
            "src_bytes":         float(row[4]),
            "dst_bytes":         float(row[5]),
            "flag":              _FLAG_MAP.get(str(row[3]).strip(), 0),
            "land":              int(row[6]),
            "wrong_fragment":    float(row[7]),
            "urgent":            float(row[8]),
            "hot":               float(row[22]),
            "num_failed_logins": float(row[10]),
        }
    except (IndexError, ValueError):
        return None

def _kdd_label(row):
    try:
        return "normal" if str(row[-1]).strip().lower().rstrip(".") == "normal" else "anomaly"
    except IndexError:
        return "anomaly"

# ── Model inference ───────────────────────────────────────────────────────────
def run_model(feat: dict) -> tuple:
    if _model is None:
        raise RuntimeError("Model not loaded.")
    X = np.array([[
        feat["duration"],       feat["protocol_type"],
        feat["src_bytes"],      feat["dst_bytes"],
        feat["flag"],           feat["land"],
        feat["wrong_fragment"], feat["urgent"],
        feat["hot"],            feat["num_failed_logins"],
    ]], dtype=float)
    pred  = int(_model.predict(X)[0])
    label = "anomaly" if pred == 1 else "normal"
    try:    prob = float(_model.predict_proba(X)[0][pred])
    except: prob = 0.97 if pred == 1 else 0.95
    return label, round(prob, 4)

# ── Auth decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            if request.is_json or request.path.startswith("/api"):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper

def _client_ip():
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET"])
def login_page():
    if "username" in session:
        return redirect(url_for("dashboard"))
    error = request.args.get("error", "")
    return render_template("login.html", error=error)


@app.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = _client_ip()

    if not username or not password:
        return redirect(url_for("login_page", error="Username and password are required"))

    user = verify_user(username, password)
    if not user:
        write_audit(username, "LOGIN_FAILED", "Bad credentials", ip)
        return redirect(url_for("login_page", error="Invalid username or password"))

    session.permanent = True
    session["username"] = user["username"]
    session["role"]     = user["role"]
    session["user_id"]  = user["user_id"]
    write_audit(user["username"], "LOGIN", f"from {ip}", ip)
    log.info("Login: %s (%s) from %s", user["username"], user["role"], ip)
    return redirect(url_for("dashboard"))


@app.route("/logout")
def do_logout():
    if "username" in session:
        write_audit(session["username"], "LOGOUT", "", _client_ip())
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def dashboard():
    return render_template("index.html",
                           username=session["username"],
                           role=session["role"])

# ══════════════════════════════════════════════════════════════════════════════
# API ROUTES — all return JSON
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health")
@login_required
def health():
    import database as _db
    return jsonify({
        "status":  "ok",
        "engine":  _db._engine,
        "model":   "loaded" if _model else "missing",
        "version": "3.1",
    })


# ── POST /predict ─────────────────────────────────────────────────────────────
@app.route("/predict", methods=["POST"])
@login_required
def predict():
    ip = _client_ip()
    if not _check_rate(ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

    body = request.get_json(silent=True) or {}

    # Required feature keys
    required = ["duration","protocol_type","src_bytes","dst_bytes",
                "flag","land","wrong_fragment","urgent","hot","num_failed_logins"]
    missing = [k for k in required if k not in body]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    try:
        feat = {k: float(body[k]) for k in required}
        feat["protocol_type"] = int(feat["protocol_type"])
        feat["land"]          = int(feat["land"])
        feat["flag"]          = int(feat["flag"])
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid numeric value: {e}"}), 400

    source_ip      = str(body.get("source_ip",      "0.0.0.0"))
    destination_ip = str(body.get("destination_ip", "0.0.0.0"))

    try:
        label, prob = run_model(feat)
    except Exception as e:
        return jsonify({"error": f"Model error: {e}"}), 500

    # Save TrafficLog
    try:
        lr = save_log(feat, label, prob, "manual", source_ip, destination_ip)
        log_id = lr["log_id"]
    except IntegrityError as e:
        log.error("TrafficLog save failed: %s", e)
        return jsonify({"error": str(e), "entity": e.entity}), 500

    # Save Alert if anomaly
    alert_result = None
    if label == "anomaly":
        uid = session.get("user_id") or get_user_id_by_username(session["username"])
        m   = get_active_model()
        mid = m["model_id"] if m else 1
        try:
            alert_result = save_alert(log_id, uid, mid,
                                      "anomaly_detected", confidence=prob)
        except IntegrityError as e:
            log.warning("Alert save failed: %s", e)
            alert_result = {"status": "error", "message": str(e)}

    write_audit(session["username"], "PREDICT",
                f"log_id={log_id} {label} ({round(prob*100,1)}%)", ip)

    return jsonify({
        "status":         "success",
        "classification": label,
        "confidence":     round(prob * 100, 1),
        "timestamp":      datetime.datetime.now().isoformat(),
        "log_id":         log_id,
        "log_saved":      lr,
        "alert_saved":    alert_result,
    })


# ── GET /alerts ───────────────────────────────────────────────────────────────
@app.route("/alerts")
@login_required
def alerts():
    rows = get_alerts()
    return jsonify({"status": "success", "count": len(rows), "alerts": rows})


@app.route("/alerts/resolve/<int:alert_id>", methods=["POST"])
@login_required
def resolve_alert_route(alert_id: int):
    result = resolve_alert(alert_id)
    write_audit(session.get("username", "unknown"), "resolve_alert",
               f"Alert #{alert_id} marked as resolved", request.remote_addr)
    return jsonify(result)


@app.route("/alerts/all")
@admin_required
def alerts_all():
    rows = get_all_alerts_admin()
    return jsonify({"status": "success", "count": len(rows), "alerts": rows})


# ── GET /summary ──────────────────────────────────────────────────────────────
@app.route("/summary")
@login_required
def summary():
    return jsonify({"status": "success", "summary": get_traffic_summary()})


# ── GET /counts ───────────────────────────────────────────────────────────────
@app.route("/counts")
@login_required
def counts():
    return jsonify({"status": "success", **get_total_counts()})


# ── GET/POST /models ──────────────────────────────────────────────────────────
@app.route("/models", methods=["GET"])
@login_required
def list_models():
    return jsonify({"status": "success", "models": get_all_models()})


@app.route("/models", methods=["POST"])
@admin_required
def add_model():
    body = request.get_json(silent=True) or {}
    name = str(body.get("model_name", "")).strip()
    try:
        acc = float(body.get("accuracy", -1))
    except (ValueError, TypeError):
        return jsonify({"error": "accuracy must be a number"}), 400
    try:
        result = register_model(name, acc)
        write_audit(session["username"], "MODEL_REGISTERED",
                    f"model_id={result['model_id']} name={name}")
        return jsonify(result), 201
    except IntegrityError as e:
        return jsonify({"error": str(e), "entity": e.entity}), 400


# ── GET /kdd/runs  ·  GET /kdd/run/<id> ──────────────────────────────────────
@app.route("/kdd/runs")
@login_required
def kdd_runs():
    return jsonify({"status": "success", "runs": get_kdd_runs()})


@app.route("/kdd/run/<int:run_id>")
@login_required
def kdd_run_detail(run_id):
    return jsonify({"status": "success", "rows": get_kdd_run_detail(run_id)})


# ── POST /simulate ────────────────────────────────────────────────────────────
@app.route("/simulate", methods=["POST"])
@login_required
def simulate():
    rows_limit = min(int(request.form.get("rows", 50)), 500)
    file       = request.files.get("file")
    samples    = []

    if file and file.filename:
        text   = file.read().decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            feat = _kdd_features(row)
            if feat:
                samples.append((feat, _kdd_label(row)))
            if len(samples) >= rows_limit:
                break
        filename = file.filename
    else:
        filename = "synthetic"
        rng = np.random.default_rng(99)
        for _ in range(int(rows_limit * 0.6)):
            samples.append(({
                "duration": float(rng.uniform(0,5)),
                "protocol_type": int(rng.integers(0,2)),
                "src_bytes": float(rng.uniform(100,8000)),
                "dst_bytes": float(rng.uniform(100,12000)),
                "flag":1,"land":0,"wrong_fragment":0,"urgent":0,
                "hot": float(rng.integers(0,8)), "num_failed_logins":0.0,
            }, "normal"))
        attacks = [
            {"duration":0,"protocol_type":1,"src_bytes":0,"dst_bytes":0,
             "flag":0,"land":0,"wrong_fragment":0,"urgent":0,"hot":0,"num_failed_logins":0},
            {"duration":0,"protocol_type":0,"src_bytes":0,"dst_bytes":0,
             "flag":3,"land":0,"wrong_fragment":3,"urgent":0,"hot":0,"num_failed_logins":0},
            {"duration":0,"protocol_type":0,"src_bytes":100,"dst_bytes":0,
             "flag":2,"land":0,"wrong_fragment":0,"urgent":0,"hot":0,"num_failed_logins":5},
            {"duration":0,"protocol_type":0,"src_bytes":200,"dst_bytes":100,
             "flag":1,"land":0,"wrong_fragment":0,"urgent":0,"hot":77,"num_failed_logins":3},
            {"duration":0,"protocol_type":0,"src_bytes":99999,"dst_bytes":0,
             "flag":1,"land":0,"wrong_fragment":0,"urgent":1,"hot":90,"num_failed_logins":0},
        ]
        for i in range(int(rows_limit * 0.4)):
            samples.append((dict(attacks[i % len(attacks)]), "anomaly"))

    if not samples:
        return jsonify({"error": "No valid rows found"}), 400

    run_id      = kdd_start_run(filename)
    tp=tn=fp=fn = 0
    total_ms    = 0.0
    anomalies   = 0

    uid = session.get("user_id") or get_user_id_by_username(session["username"])
    m   = get_active_model()
    mid = m["model_id"] if m else 1

    for idx, (feat, actual) in enumerate(samples):
        t0 = time.time()
        predicted, prob = run_model(feat)
        ms = round((time.time() - t0) * 1000, 2)
        total_ms += ms

        try:
            lr = save_log(feat, predicted, prob, "kdd")
            log_id = lr["log_id"]
        except IntegrityError:
            log_id = None

        kdd_log_row(run_id, idx, predicted, actual, prob, ms)

        if predicted == "anomaly":
            anomalies += 1
            if log_id and uid and mid:
                try:
                    save_alert(log_id, uid, mid, "kdd_anomaly", confidence=prob)
                except IntegrityError as ae:
                    log.debug("KDD alert skipped: %s", ae)

        if predicted=="anomaly" and actual=="anomaly": tp += 1
        if predicted=="normal"  and actual=="normal":  tn += 1
        if predicted=="anomaly" and actual=="normal":  fp += 1
        if predicted=="normal"  and actual=="anomaly": fn += 1

    total     = tp+tn+fp+fn
    accuracy  = round((tp+tn)/total, 4) if total else 0
    precision = round(tp/(tp+fp),    4) if (tp+fp) else 0
    recall    = round(tp/(tp+fn),    4) if (tp+fn) else 0
    f1        = round(2*precision*recall/(precision+recall), 4) if (precision+recall) else 0
    avg_ms    = round(total_ms/total, 2) if total else 0

    kdd_finish_run(run_id, total, anomalies, total-anomalies,
                   accuracy, precision, recall, f1)
    write_audit(session["username"], "KDD_SIM",
                f"run_id={run_id} rows={total} accuracy={accuracy}", _client_ip())

    return jsonify({
        "status": "success", "run_id": run_id, "total": total,
        "anomalies": anomalies, "normals": total-anomalies,
        "accuracy":  round(accuracy*100,2),  "precision": round(precision*100,2),
        "recall":    round(recall*100,2),     "f1_score":  round(f1*100,2),
        "avg_response_ms": avg_ms,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    })


# ── GET/POST/DELETE /users ────────────────────────────────────────────────────
@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    return jsonify({"status": "success", "users": get_all_users()})


@app.route("/users", methods=["POST"])
@admin_required
def add_user():
    body = request.get_json(silent=True) or {}
    try:
        result = create_user(
            username = str(body.get("username", "")).strip(),
            password = str(body.get("password", "")),
            role     = str(body.get("role", "analyst")),
            name     = str(body.get("name", "")),
            email    = str(body.get("email", "")),
        )
        write_audit(session["username"], "USER_CREATED",
                    f"user_id={result['user_id']} username={body.get('username')}")
        return jsonify(result), 201
    except IntegrityError as e:
        return jsonify({"error": str(e), "entity": e.entity}), 400


@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def del_user(user_id):
    try:
        delete_user(user_id)
        write_audit(session["username"], "USER_DELETED", f"id={user_id}")
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── GET /audit ────────────────────────────────────────────────────────────────
@app.route("/audit")
@admin_required
def audit():
    return jsonify({"status": "success", "logs": get_audit_log()})


# ══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    if request.is_json:
        return jsonify({"error": "Not found"}), 404
    return redirect(url_for("dashboard"))

@app.errorhandler(500)
def server_error(e):
    log.exception("Unhandled server error")
    if request.is_json:
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500
    return f"<h2>Internal Server Error</h2><pre>{e}</pre>", 500

# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

with app.app_context():
    init_db()

if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║   Hospital Cyber Threat Monitoring System  v3.1     ║")
    print("╚══════════════════════════════════════════════════════╝\n")
    app.run(host="0.0.0.0", port=8000, debug=False)
