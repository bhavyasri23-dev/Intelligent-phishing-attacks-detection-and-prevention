# app.py
"""Flask API + tiny web UI.   Run:  python app.py"""
import sys
from pathlib import Path

from flask import Flask, jsonify, request, render_template

# Make sibling modules importable even when launched from another directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import database
from risk_engine import assess

app = Flask(__name__)
database.init_db()

@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    url = ((request.get_json(silent=True) or {}).get("url") or "").strip()
    if not url or len(url) > 2048:
        return jsonify(error="Provide a URL (max 2048 chars)"), 400

    result = assess(url, deep=request.args.get("deep", "1") != "0")
    status = database.list_status(result["host"])
    if status == "allow":
        result.update(verdict="SAFE", reasons=["Host is on your allow-list"] + result["reasons"])
    elif status == "block":
        result.update(verdict="DANGEROUS", score=100, reasons=["Host is on your block-list"] + result["reasons"])
    database.save_scan(result)
    return jsonify(result)


@app.get("/api/history")
def history():
    return jsonify(database.recent_scans())


@app.post("/api/list")
def update_list():
    body = request.get_json(silent=True) or {}
    host, kind = (body.get("host") or "").strip(), body.get("kind")
    if not host or kind not in ("allow", "block"):
        return jsonify(error="Need 'host' and kind='allow'|'block'"), 400
    database.set_list(host, kind)
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=False, port=5000)