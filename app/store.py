import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS targets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, url)
);
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    options TEXT,
    status TEXT DEFAULT 'running',
    total INTEGER DEFAULT 0,
    alive INTEGER DEFAULT 0,
    done INTEGER DEFAULT 0,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS results(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    url TEXT,
    alive INTEGER,
    status_code INTEGER,
    final_url TEXT,
    title TEXT,
    server TEXT,
    elapsed_ms INTEGER,
    fingerprints TEXT,
    screenshot TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_id);
"""


def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    conn = _conn()
    conn.executescript(SCHEMA)
    conn.close()


# ---------- projects ----------

def create_project(name: str, description: str = "") -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO projects(name, description) VALUES(?,?)", (name, description)
    )
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return pid


def list_projects() -> list:
    conn = _conn()
    rows = conn.execute(
        """SELECT p.*,
                  (SELECT COUNT(*) FROM targets t WHERE t.project_id = p.id) AS target_count,
                  (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) AS scan_count
           FROM projects p ORDER BY p.id DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_project(pid: int) -> dict | None:
    conn = _conn()
    row = conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------- targets ----------

def add_targets(project_id: int, urls: list[str]) -> dict:
    conn = _conn()
    added, dup = 0, 0
    for u in urls:
        try:
            conn.execute(
                "INSERT INTO targets(project_id, url) VALUES(?,?)", (project_id, u)
            )
            added += 1
        except sqlite3.IntegrityError:
            dup += 1
    conn.commit()
    conn.close()
    return {"added": added, "duplicates": dup}


def list_targets(project_id: int) -> list:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM targets WHERE project_id=? ORDER BY id", (project_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_target(target_id: int):
    conn = _conn()
    conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
    conn.commit()
    conn.close()


def alive_targets(project_id: int) -> list:
    """Targets whose latest scan result was alive — used for 二次扫描."""
    conn = _conn()
    rows = conn.execute(
        """SELECT t.* FROM targets t
           WHERE t.project_id=? AND (
               SELECT r.alive FROM results r WHERE r.target_id=t.id
               ORDER BY r.id DESC LIMIT 1
           )=1""",
        (project_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------- scans ----------

def create_scan(project_id: int, kind: str, options: dict, total: int) -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO scans(project_id, kind, options, total) VALUES(?,?,?,?)",
        (project_id, kind, json.dumps(options), total),
    )
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return sid


def finish_scan(scan_id: int, alive: int):
    conn = _conn()
    conn.execute(
        "UPDATE scans SET status='done', alive=?, finished_at=CURRENT_TIMESTAMP WHERE id=?",
        (alive, scan_id),
    )
    conn.commit()
    conn.close()


def fail_scan(scan_id: int):
    conn = _conn()
    conn.execute(
        "UPDATE scans SET status='failed', finished_at=CURRENT_TIMESTAMP WHERE id=?",
        (scan_id,),
    )
    conn.commit()
    conn.close()


def bump_done(scan_id: int):
    conn = _conn()
    conn.execute("UPDATE scans SET done = done + 1 WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()


def get_scan(scan_id: int) -> dict | None:
    conn = _conn()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_scans(project_id: int) -> list:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM scans WHERE project_id=? ORDER BY id DESC", (project_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def running_scan(project_id: int) -> dict | None:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM scans WHERE project_id=? AND status='running' ORDER BY id DESC LIMIT 1",
        (project_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------- results ----------

def save_result(r: dict) -> int:
    conn = _conn()
    cur = conn.execute(
        """INSERT INTO results(scan_id, target_id, url, alive, status_code, final_url,
                               title, server, elapsed_ms, fingerprints, screenshot, error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            r.get("scan_id"),
            r.get("target_id"),
            r.get("url"),
            r.get("alive"),
            r.get("status_code"),
            r.get("final_url"),
            r.get("title"),
            r.get("server"),
            r.get("elapsed_ms"),
            json.dumps(r.get("fingerprints", []), ensure_ascii=False),
            r.get("screenshot"),
            r.get("error"),
        ),
    )
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return rid


def update_result(rid: int, fields: dict):
    if "fingerprints" in fields:
        fields["fingerprints"] = json.dumps(fields["fingerprints"], ensure_ascii=False)
    conn = _conn()
    sets = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE results SET {sets} WHERE id=?", (*fields.values(), rid))
    conn.commit()
    conn.close()


def list_results(scan_id: int, alive_only: bool = False) -> list:
    conn = _conn()
    q = "SELECT * FROM results WHERE scan_id=?"
    if alive_only:
        q += " AND alive=1"
    rows = conn.execute(q + " ORDER BY id", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_result(rid: int) -> dict | None:
    conn = _conn()
    row = conn.execute("SELECT * FROM results WHERE id=?", (rid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def latest_results_by_target(project_id: int) -> dict:
    """target_id -> latest result row (for showing current state in target table)."""
    conn = _conn()
    rows = conn.execute(
        """SELECT r.* FROM results r
           JOIN targets t ON t.id = r.target_id
           WHERE t.project_id=? AND r.id = (
               SELECT MAX(r2.id) FROM results r2 WHERE r2.target_id = r.target_id
           )""",
        (project_id,),
    ).fetchall()
    conn.close()
    return {r["target_id"]: dict(r) for r in rows}
