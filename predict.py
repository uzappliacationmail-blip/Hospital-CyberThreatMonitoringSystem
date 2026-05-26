#!/usr/bin/env python3
"""
Simple ML prediction server for external hosting.
Run this on any cloud platform (Render, Fly.io, Railway, etc.)
"""
import os
import sys
import pickle
import json
import hashlib
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import numpy as np

# Load environment
SUPABASE_URL = os.getenv("SUPABASE_URL", os.getenv("VITE_SUPABASE_URL", ""))
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", os.getenv("VITE_SUPABASE_ANON_KEY", ""))

# Password hashing
def hash_password(pw: str) -> str:
    return hashlib.sha256(("ctms_salt_" + pw).encode()).hexdigest()

# ── Model ─────────────────────────────────────────────────────────────────────
_model = None

def load_model():
    global _model
    model_path = "best_model_SVC.pkl"
    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            _model = pickle.load(f)
        print(f"Model loaded: {model_path}")
        return
    # Generate demo model
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
    _model = clf
    print("Demo model generated")

load_model()

# ── Supabase REST API helpers ────────────────────────────────────────────────
import urllib.request
import urllib.error

def _request(method: str, table: str, data: dict = None, query: str = ""):
    url = f"{SUPABASE_URL}/rest/v1/{table}{query}"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    req_data = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else []
    except Exception as e:
        print(f"Request error: {e}")
        return None

def _request_one(method: str, table: str, data: dict = None, query: str = ""):
    results = _request(method, table, data, query)
    return results[0] if results else None

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class CTMSHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Client-Info, Apikey")

    def _json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/login":
            self._handle_login()
        elif path == "/api/predict":
            self._handle_predict()
        elif path == "/api/traffic":
            self._handle_traffic()
        else:
            self._json({"error": "Not found"}, 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/health":
            self._json({"status": "ok", "model": "loaded"})
        elif path == "/api/stats":
            self._handle_stats()
        elif path == "/api/alerts":
            self._handle_alerts(query.get("limit", [100]))
        else:
            self._json({"error": "Not found"}, 404)

    def _handle_login(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)
            username = data.get("username", "")
            password = data.get("password", "")

            pw_hash = hash_password(password)
            result = _request_one("GET", "users",
                query=f"?username=eq.{username}&password=eq.{pw_hash}&select=user_id,username,role,name")

            if result:
                self._json({"success": True, "user": result})
            else:
                self._json({"success": False, "error": "Invalid credentials"}, 401)
        except Exception as e:
            self._json({"success": False, "error": str(e)}, 500)

    def _handle_predict(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            # Extract features
            features = np.array([[
                float(data.get("duration", 0)),
                float(data.get("protocol_type", 0)),
                float(data.get("src_bytes", 0)),
                float(data.get("dst_bytes", 0)),
                float(data.get("flag", 0)),
                float(data.get("wrong_fragment", 0)),
                float(data.get("urgent", 0)),
                float(data.get("hot", 0)),
                float(data.get("num_failed_logins", 0)),
                float(data.get("root_shell", 0))
            ]])

            start = time.time()
            pred = _model.predict(features)[0]
            proba = _model.predict_proba(features)[0]
            elapsed = (time.time() - start) * 1000

            label = "normal" if pred == 0 else "anomaly"
            confidence = float(max(proba))
            anomaly_confidence = float(proba[1]) if len(proba) > 1 else confidence

            self._json({
                "prediction": label,
                "confidence": round(confidence, 4),
                "anomaly_confidence": round(anomaly_confidence, 4),
                "response_ms": round(elapsed, 2)
            })
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def _handle_traffic(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            result = _request_one("POST", "traffic_logs", data={
                "source_ip": data.get("source_ip", "0.0.0.0"),
                "destination_ip": data.get("destination_ip", "0.0.0.0"),
                "protocol": data.get("protocol", "tcp"),
                "status": data.get("status", "normal"),
                "features": json.dumps(data.get("features", {})),
                "confidence": float(data.get("confidence", 0)),
                "source": data.get("source", "api")
            })

            self._json({"success": True, "log_id": result.get("log_id") if result else None})
        except Exception as e:
            self._json({"success": False, "error": str(e)}, 500)

    def _handle_stats(self):
        try:
            logs = _request("GET", "traffic_logs", query="?select=status")
            total = len(logs)
            normal = sum(1 for l in logs if l.get("status") == "normal")
            anomaly = sum(1 for l in logs if l.get("status") == "anomaly")
            self._json({"total": total, "normal": normal, "anomaly": anomaly})
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def _handle_alerts(self, limit):
        try:
            alerts = _request("GET", "alerts",
                query=f"?resolved=eq.false&select=alert_id,alert_type,severity,timestamp,log_id&order=timestamp.desc&limit={limit[0]}")
            self._json({"alerts": alerts or []})
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8001"))
    server = HTTPServer(("0.0.0.0", port), CTMSHandler)
    print(f"CTMS API Server running on port {port}")
    print(f"Endpoints: /api/login, /api/predict, /api/traffic, /api/stats, /api/alerts")
    server.serve_forever()
