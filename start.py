#!/usr/bin/env python3
"""
start.py — Hospital CTMS one-command launcher.
Run:  python start.py
"""
import os, sys, logging

# Set UTF-8 encoding on Windows for emoji support
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-7s]  %(name)s: %(message)s",
    datefmt="%H:%M:%S", stream=sys.stdout,
)
logging.getLogger("ctms.db").setLevel(logging.INFO)

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   Hospital Cyber Threat Monitoring System  v3.2     ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    from main import app
    import database as _db

    eng = "MySQL ✅" if _db._engine == "mysql" else "SQLite ✅ (MySQL not available — using SQLite)"
    print(f"  Database : {eng}")
    print(f"  Server   : http://localhost:8000")
    print(f"  Login    : admin / admin123")
    print()

    app.run(host="127.0.0.1", port=8000, debug=False)
