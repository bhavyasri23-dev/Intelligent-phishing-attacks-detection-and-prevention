# database.py
"""SQLite storage for scan history, plus user allow/block lists (the 'prevention' layer)."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime

DB_PATH = "phishguard.db"


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with closing(_conn()) as c, c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL, host TEXT, score INTEGER, verdict TEXT,
            reasons TEXT, scanned_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
        CREATE TABLE IF NOT EXISTS lists (
            host TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('allow','block')),
            added_at TEXT NOT NULL
        );
        """)


def save_scan(result):
    with closing(_conn()) as c, c:
        c.execute("INSERT INTO scans (url, host, score, verdict, reasons, scanned_at) VALUES (?,?,?,?,?,?)",
                  (result["url"], result["host"], result["score"], result["verdict"],
                   json.dumps(result["reasons"]), datetime.utcnow().isoformat()))


def recent_scans(limit=50):
    with closing(_conn()) as c:
        rows = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "reasons": json.loads(r["reasons"] or "[]")} for r in rows]


def set_list(host, kind):
    with closing(_conn()) as c, c:
        c.execute("INSERT OR REPLACE INTO lists (host, kind, added_at) VALUES (?,?,?)",
                  (host.lower(), kind, datetime.utcnow().isoformat()))


def list_status(host):
    """Return 'allow', 'block' or None."""
    with closing(_conn()) as c:
        row = c.execute("SELECT kind FROM lists WHERE host = ?", (host.lower(),)).fetchone()
    return row["kind"] if row else None
