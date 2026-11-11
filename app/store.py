import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit, unquote

DB_PATH = Path(__file__).resolve().parent.parent / "data.db"

# DB engine: default SQLite file; set SCAN_DB_URL=postgres://user:pass@host:5432/db
# to switch to PostgreSQL (long-term multi-writer storage).
DB_URL = os.environ.get("SCAN_DB_URL", "").strip()
PG = DB_URL.startswith(("postgres://", "postgresql://", "pgsql://"))

if PG:
    import psycopg2
    import psycopg2.extras

    _u = urlsplit(DB_URL)
    _PG_CFG = {
        "host": _u.hostname or "127.0.0.1",
        "port": _u.port or 5432,
        "user": unquote(_u.username or "postgres"),
        "password": unquote(_u.password or ""),
        "dbname": (_u.path or "/scan").lstrip("/") or "scan",
    }
    IntegrityError = psycopg2.IntegrityError
    SchemaError = (psycopg2.ProgrammingError, psycopg2.OperationalError)
else:
    IntegrityError = sqlite3.IntegrityError
    SchemaError = (sqlite3.OperationalError,)


class _Compat:
    """sqlite3-style facade over a psycopg2 connection.

    Translates '?' placeholders to '%s', returns dict rows (RealDictCursor),
    exposes commit/rollback/close."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=None):
        cur = self._conn.cursor()
        cur.execute(sql.replace("?", "%s"), params if params else None)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

SCHEMA_SQLITE = """
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
    protection TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_id);

CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS exposure_runs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    options TEXT,
    status TEXT DEFAULT 'running',
    total INTEGER DEFAULT 0,
    done INTEGER DEFAULT 0,
    found INTEGER DEFAULT 0,
    deep_status TEXT DEFAULT 'none',
    deep_total INTEGER DEFAULT 0,
    deep_done INTEGER DEFAULT 0,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS exposure_results(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    target_id INTEGER,
    kind TEXT,
    url TEXT,
    source TEXT,
    status_code INTEGER,
    title TEXT,
    length INTEGER,
    hint TEXT,
    alive INTEGER,
    surface INTEGER,
    final_url TEXT,
    server TEXT,
    fingerprints TEXT,
    screenshot TEXT,
    protection TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_exposure_run ON exposure_results(run_id);
"""

# PostgreSQL schema = sqlite schema with SERIAL instead of AUTOINCREMENT.
# Everything else (TEXT, TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE,
# CREATE INDEX IF NOT EXISTS, unquoted key/length) is already valid in PG.
SCHEMA_PG = SCHEMA_SQLITE.replace(
    "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")

DEFAULT_SETTINGS = {
    "concurrency": 50,          # 目标并发（探测）
    "browser_concurrency": 4,   # 浏览器并发（抓包/截图）
    "active_probe": True,       # 扫描默认开启主动探测
    "screenshot": True,         # 扫描默认开启截图
    "connect_timeout": 8,       # httpx 连接超时（秒）
    "read_timeout": 15,         # httpx 读取超时（秒）
    "proxy": "",                # 出站代理 http:// / https:// / socks5://（留空直连）
    # 网络空间测绘 API keys（可选配置，配置后暴露面扫描可勾选）
    "fofa_email": "",           # FOFA 账号邮箱
    "fofa_key": "",             # FOFA API key
    "hunter_key": "",           # 奇安信鹰图 API key
    "quake_key": "",            # 360 Quake API key
}


def _conn():
    if PG:
        conn = psycopg2.connect(
            **_PG_CFG, cursor_factory=psycopg2.extras.RealDictCursor)
        return _Compat(conn)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    if PG:
        # create database first: connect to the maintenance db, check catalog
        cfg = dict(_PG_CFG)
        db = cfg.pop("dbname")
        boot = psycopg2.connect(dbname="postgres", **cfg)
        boot.autocommit = True
        with boot.cursor() as c:
            c.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db,))
            if not c.fetchone():
                c.execute(f'CREATE DATABASE "{db}"')
        boot.close()
        conn = _conn()
        for stmt in SCHEMA_PG.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)
    else:
        conn = _conn()
        conn.executescript(SCHEMA_SQLITE)
    conn.commit()  # PG: persist schema before ALTERs — a rollback below
                   # would otherwise discard the CREATE TABLEs too
    # idempotent column migrations: commit each success, rollback each
    # dup-column failure (PG aborts the whole txn on error otherwise)
    for table, col in (
        ("results", "protection TEXT"),
        ("exposure_results", "alive INTEGER"),
        ("exposure_results", "surface INTEGER"),
        ("exposure_results", "final_url TEXT"),
        ("exposure_results", "server TEXT"),
        ("exposure_results", "fingerprints TEXT"),
        ("exposure_results", "screenshot TEXT"),
        ("exposure_results", "protection TEXT"),
        ("exposure_results", "shot_sig TEXT"),
        ("exposure_results", "response TEXT"),
        ("exposure_runs", "deep_status TEXT DEFAULT 'none'"),
        ("exposure_runs", "deep_total INTEGER DEFAULT 0"),
        ("exposure_runs", "deep_done INTEGER DEFAULT 0"),
    ):
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col}")
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
    conn.commit()
    conn.close()


# psycopg2 has no lastrowid — PG inserts get RETURNING id appended
_INS_SUFFIX = " RETURNING id" if PG else ""


def _insert_id(cur) -> int:
    return cur.fetchone()["id"] if PG else cur.lastrowid


# ---------- projects ----------

def create_project(name: str, description: str = "") -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO projects(name, description) VALUES(?,?)" + _INS_SUFFIX,
        (name, description),
    )
    pid = _insert_id(cur)
    conn.commit()
    conn.close()
    return pid


def list_projects() -> list:
    conn = _conn()
    rows = conn.execute(
        """SELECT p.*,
                  (SELECT COUNT(*) FROM targets t WHERE t.project_id = p.id) AS target_count,
                  (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) AS scan_count,
                  COALESCE(s.alive, 0) AS alive_count,
                  COALESCE(s.dead, 0) AS dead_count
           FROM projects p
           LEFT JOIN (
               SELECT t.project_id,
                      SUM(CASE WHEN lr.alive = 1 THEN 1 ELSE 0 END) AS alive,
                      SUM(CASE WHEN lr.alive = 0 THEN 1 ELSE 0 END) AS dead
               FROM targets t
               LEFT JOIN (
                   SELECT target_id, alive FROM results r
                   WHERE r.id = (SELECT MAX(r2.id) FROM results r2
                                 WHERE r2.target_id = r.target_id)
               ) lr ON lr.target_id = t.id
               GROUP BY t.project_id
           ) s ON s.project_id = p.id
           ORDER BY p.id DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_project(pid: int) -> dict | None:
    conn = _conn()
    row = conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_project(pid: int, name: str, description: str = ""):
    conn = _conn()
    conn.execute(
        "UPDATE projects SET name=?, description=? WHERE id=?",
        (name, description, pid),
    )
    conn.commit()
    conn.close()


def delete_project(pid: int):
    """Cascade: results (by scan and by target) -> scans -> targets -> project."""
    conn = _conn()
    conn.execute(
        """DELETE FROM results WHERE scan_id IN
               (SELECT id FROM scans WHERE project_id=?)
           OR target_id IN (SELECT id FROM targets WHERE project_id=?)""",
        (pid, pid),
    )
    conn.execute("DELETE FROM scans WHERE project_id=?", (pid,))
    conn.execute("DELETE FROM targets WHERE project_id=?", (pid,))
    conn.execute("DELETE FROM projects WHERE id=?", (pid,))
    conn.commit()
    conn.close()


# ---------- targets ----------

def add_targets(project_id: int, urls: list[str]) -> dict:
    conn = _conn()
    added, dup = 0, 0
    if PG:
        # ON CONFLICT keeps a duplicate from aborting the whole transaction
        # (a bare IntegrityError would poison every INSERT after it).
        for u in urls:
            cur = conn.execute(
                "INSERT INTO targets(project_id, url) VALUES(?,?)"
                " ON CONFLICT DO NOTHING",
                (project_id, u),
            )
            added += cur.rowcount
            dup += 1 - cur.rowcount
    else:
        for u in urls:
            try:
                conn.execute(
                    "INSERT INTO targets(project_id, url) VALUES(?,?)", (project_id, u)
                )
                added += 1
            except IntegrityError:
                dup += 1
    conn.commit()
    conn.close()
    return {"added": added, "duplicates": dup}


def delete_targets(ids: list[int]) -> int:
    if not ids:
        return 0
    conn = _conn()
    ph = ",".join("?" for _ in ids)
    cur = conn.execute(f"DELETE FROM targets WHERE id IN ({ph})", list(ids))
    n = cur.rowcount
    conn.commit()
    conn.close()
    return n


def list_targets(project_id: int) -> list:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM targets WHERE project_id=? ORDER BY id", (project_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_target(target_id: int, url: str) -> dict:
    """Change a target's URL. Past results keep their own url snapshot."""
    conn = _conn()
    t = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not t:
        conn.close()
        return {"ok": False, "error": "not found"}
    dup = conn.execute(
        "SELECT id FROM targets WHERE project_id=? AND url=? AND id!=?",
        (t["project_id"], url, target_id),
    ).fetchone()
    if dup:
        conn.close()
        return {"ok": False, "error": "duplicate"}
    conn.execute("UPDATE targets SET url=? WHERE id=?", (url, target_id))
    conn.commit()
    conn.close()
    return {"ok": True}


def delete_target(target_id: int):
    conn = _conn()
    conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
    conn.commit()
    conn.close()


# ---------- settings ----------

# upsert syntax is identical in SQLite and PostgreSQL
_SET_SQL = (
    "INSERT INTO settings(key, value) VALUES(?,?) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
)


def get_settings() -> dict:
    conn = _conn()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    out = dict(DEFAULT_SETTINGS)
    for r in rows:
        if r["key"] in DEFAULT_SETTINGS:
            try:
                out[r["key"]] = json.loads(r["value"])
            except Exception:
                pass
    return out


def set_settings(values: dict):
    conn = _conn()
    for k, v in values.items():
        if k in DEFAULT_SETTINGS:
            conn.execute(_SET_SQL, (k, json.dumps(v)))
    conn.commit()
    conn.close()


# ---------- auth (平台登录密码) ----------

DEFAULT_PASSWORD = "admin@scan123"


def _kv_get(key: str) -> str | None:
    conn = _conn()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else None


def _kv_set(key: str, value: str):
    conn = _conn()
    conn.execute(_SET_SQL, (key, value))
    conn.commit()
    conn.close()


def _hash_pw(password: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + password).encode()).hexdigest()


def password_hash() -> str:
    """'salt:digest' record; initialized to DEFAULT_PASSWORD on first use."""
    rec = _kv_get("password")
    if not rec:
        salt = secrets.token_hex(8)
        rec = f"{salt}:{_hash_pw(DEFAULT_PASSWORD, salt)}"
        _kv_set("password", rec)
    return rec


def verify_password(password: str) -> bool:
    try:
        salt, digest = password_hash().split(":", 1)
    except ValueError:
        return False
    return secrets.compare_digest(_hash_pw(password or "", salt), digest)


def set_password(password: str):
    salt = secrets.token_hex(8)
    _kv_set("password", f"{salt}:{_hash_pw(password, salt)}")


def auth_secret() -> str:
    s = _kv_get("auth_secret")
    if not s:
        s = secrets.token_hex(24)
        _kv_set("auth_secret", s)
    return s


# ---------- exposure runs (暴露面) ----------

def create_exposure_run(project_id: int, options: dict, total: int) -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO exposure_runs(project_id, options, total) VALUES(?,?,?)"
        + _INS_SUFFIX,
        (project_id, json.dumps(options), total),
    )
    rid = _insert_id(cur)
    conn.commit()
    conn.close()
    return rid


def get_exposure_run(rid: int) -> dict | None:
    conn = _conn()
    row = conn.execute("SELECT * FROM exposure_runs WHERE id=?", (rid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_exposure_runs(project_id: int | None = None) -> list:
    conn = _conn()
    q = """SELECT e.*, p.name AS project_name,
                  (SELECT COUNT(*) FROM exposure_results r WHERE r.run_id=e.id) AS found
           FROM exposure_runs e JOIN projects p ON p.id=e.project_id"""
    if project_id:
        rows = conn.execute(q + " WHERE e.project_id=? ORDER BY e.id DESC",
                            (project_id,)).fetchall()
    else:
        rows = conn.execute(q + " ORDER BY e.id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_exposure_result(run_id: int, target_id: int, r: dict):
    conn = _conn()
    conn.execute(
        """INSERT INTO exposure_results(run_id, target_id, kind, url, source,
               status_code, title, length, hint, surface)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (run_id, target_id, r.get("kind"), _txt(r.get("url")),
         _txt(r.get("source")), r.get("status_code"), _txt(r.get("title")),
         r.get("length"), _txt(r.get("hint")), r.get("surface")),
    )
    conn.execute(
        "UPDATE exposure_runs SET found=(SELECT COUNT(*) FROM exposure_results WHERE run_id=?) WHERE id=?",
        (run_id, run_id),
    )
    conn.commit()
    conn.close()


def bump_exposure_done(run_id: int):
    conn = _conn()
    conn.execute("UPDATE exposure_runs SET done=done+1 WHERE id=?", (run_id,))
    conn.commit()
    conn.close()


def finish_exposure(run_id: int):
    conn = _conn()
    conn.execute(
        "UPDATE exposure_runs SET status='done', finished_at=CURRENT_TIMESTAMP WHERE id=?",
        (run_id,),
    )
    conn.commit()
    conn.close()


def fail_exposure(run_id: int):
    conn = _conn()
    conn.execute(
        "UPDATE exposure_runs SET status='failed', finished_at=CURRENT_TIMESTAMP WHERE id=?",
        (run_id,),
    )
    conn.commit()
    conn.close()


def list_exposure_results(run_id: int) -> list:
    conn = _conn()
    rows = conn.execute(
        """SELECT r.id, r.run_id, r.target_id, r.kind, r.url, r.source,
                  r.status_code, r.title, r.length, r.hint, r.alive,
                  r.surface, r.final_url, r.server, r.fingerprints,
                  r.screenshot, r.protection, r.shot_sig, r.created_at,
                  (r.response IS NOT NULL AND r.response != '')
                      AS has_response,
                  t.url AS target_url
           FROM exposure_results r
           LEFT JOIN targets t ON t.id=r.target_id
           WHERE r.run_id=? ORDER BY r.kind, r.hint, r.url""",
        (run_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def exposure_row_response(row_id: int) -> dict | None:
    conn = _conn()
    r = conn.execute(
        "SELECT url, response, fingerprints FROM exposure_results WHERE id=?",
        (row_id,),
    ).fetchone()
    conn.close()
    return dict(r) if r else None


def delete_exposure_run(rid: int):
    conn = _conn()
    conn.execute("DELETE FROM exposure_results WHERE run_id=?", (rid,))
    conn.execute("DELETE FROM exposure_runs WHERE id=?", (rid,))
    conn.commit()
    conn.close()


def exposure_stats() -> dict:
    """Aggregate counters for the exposure overview strip."""
    conn = _conn()
    def one(q):
        return conn.execute(q).fetchone()["n"]
    d = {
        "runs": one("SELECT COUNT(*) AS n FROM exposure_runs"),
        "findings": one("SELECT COUNT(*) AS n FROM exposure_results"),
        "surfaces": one(
            "SELECT COUNT(*) AS n FROM exposure_results WHERE surface=1"),
        "projects": one(
            "SELECT COUNT(DISTINCT project_id) AS n FROM exposure_runs"),
    }
    conn.close()
    d["infos"] = d["findings"] - d["surfaces"]
    return d


# ---------- exposure deep scan (攻击面深扫: 指纹+截图) ----------

def exposure_deep_start(rid: int, total: int):
    conn = _conn()
    conn.execute(
        "UPDATE exposure_runs SET deep_status='running', deep_total=?, deep_done=0 WHERE id=?",
        (total, rid),
    )
    conn.commit()
    conn.close()


def bump_exposure_deep(rid: int):
    conn = _conn()
    conn.execute("UPDATE exposure_runs SET deep_done=deep_done+1 WHERE id=?", (rid,))
    conn.commit()
    conn.close()


def finish_exposure_deep(rid: int):
    conn = _conn()
    conn.execute(
        "UPDATE exposure_runs SET deep_status='done' WHERE id=?", (rid,))
    conn.commit()
    conn.close()


def fail_exposure_deep(rid: int):
    conn = _conn()
    conn.execute(
        "UPDATE exposure_runs SET deep_status='failed' WHERE id=?", (rid,))
    conn.commit()
    conn.close()


def _txt(v):
    """Postgres refuses NUL bytes in string literals — strip them."""
    if isinstance(v, str) and "\x00" in v:
        return v.replace("\x00", "")
    return v


def update_exposure_deep_result(rid: int, url: str, fields: dict):
    """Fill probe/fingerprint/screenshot columns on every row of `url`."""
    conn = _conn()
    conn.execute(
        """UPDATE exposure_results SET status_code=?, alive=?, surface=?,
               final_url=?, server=?, fingerprints=?, screenshot=?, protection=?,
               shot_sig=?, response=?, title=COALESCE(?, title),
               hint=CASE WHEN ? IS NOT NULL AND (hint IS NULL OR hint='other')
                         THEN ? ELSE hint END
           WHERE run_id=? AND url=?""",
        (fields.get("status_code"), fields.get("alive"), fields.get("surface"),
         _txt(fields.get("final_url")), _txt(fields.get("server")),
         _txt(fields.get("fingerprints")), fields.get("screenshot"),
         _txt(fields.get("protection")), fields.get("shot_sig"),
         _txt(fields.get("response")), _txt(fields.get("title")),
         _txt(fields.get("hint")), _txt(fields.get("hint")),
         rid, url),
    )
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
        "INSERT INTO scans(project_id, kind, options, total) VALUES(?,?,?,?)"
        + _INS_SUFFIX,
        (project_id, kind, json.dumps(options), total),
    )
    sid = _insert_id(cur)
    conn.commit()
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
                               title, server, elapsed_ms, fingerprints, screenshot, protection, error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""" + _INS_SUFFIX,
        (
            r.get("scan_id"),
            r.get("target_id"),
            _txt(r.get("url")),
            r.get("alive"),
            r.get("status_code"),
            _txt(r.get("final_url")),
            _txt(r.get("title")),
            _txt(r.get("server")),
            r.get("elapsed_ms"),
            json.dumps(r.get("fingerprints", []), ensure_ascii=False),
            r.get("screenshot"),
            _txt(r.get("protection")),
            _txt(r.get("error")),
        ),
    )
    rid = _insert_id(cur)
    conn.commit()
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


def overview() -> dict:
    conn = _conn()
    def one(q):
        return conn.execute(q).fetchone()["n"]
    d = {
        "projects": one("SELECT COUNT(*) AS n FROM projects"),
        "targets": one("SELECT COUNT(*) AS n FROM targets"),
        "scans": one("SELECT COUNT(*) AS n FROM scans"),
        "running": one("SELECT COUNT(*) AS n FROM scans WHERE status='running'"),
        "alive": one(
            """SELECT COUNT(*) AS n FROM (
                   SELECT r.target_id, r.alive FROM results r
                   WHERE r.id = (SELECT MAX(r2.id) FROM results r2
                                 WHERE r2.target_id = r.target_id)
               ) t WHERE alive=1"""
        ),
    }
    d["recent_scans"] = [
        dict(r) for r in conn.execute(
            """SELECT s.*, p.name AS project_name FROM scans s
               JOIN projects p ON p.id = s.project_id
               ORDER BY s.id DESC LIMIT 8"""
        ).fetchall()
    ]
    d["fp_rows"] = [
        r["fingerprints"] for r in conn.execute(
            """SELECT fingerprints FROM results
               WHERE fingerprints != '[]' ORDER BY id DESC LIMIT 3000"""
        ).fetchall()
    ]
    # latest-result view per target: alive / dead / unscanned + status code dist
    d["dead"] = conn.execute(
        """SELECT COUNT(*) AS n FROM (
               SELECT r.target_id, r.alive FROM results r
               WHERE r.id = (SELECT MAX(r2.id) FROM results r2
                             WHERE r2.target_id = r.target_id)
           ) t WHERE alive=0"""
    ).fetchone()["n"]
    d["unscanned"] = conn.execute(
        """SELECT COUNT(*) AS n FROM targets t WHERE NOT EXISTS (
               SELECT 1 FROM results r WHERE r.target_id = t.id
           )"""
    ).fetchone()["n"]
    d["status_dist"] = {
        str(r["status_code"]): r["n"]
        for r in conn.execute(
            """SELECT status_code, COUNT(*) AS n FROM results r
               WHERE r.id = (SELECT MAX(r2.id) FROM results r2
                             WHERE r2.target_id = r.target_id)
               AND status_code IS NOT NULL
               GROUP BY status_code ORDER BY n DESC"""
        ).fetchall()
    }
    conn.close()
    return d


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


def pg_size_mb() -> float:
    """Total size of the scan database (PostgreSQL only)."""
    if not PG:
        return 0.0
    conn = _conn()
    row = conn.execute(
        "SELECT pg_database_size(current_database()) AS n"
    ).fetchone()
    conn.close()
    return float(row["n"] or 0) / 1048576
