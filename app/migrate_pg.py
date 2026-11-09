"""One-shot migration: copy all data from the SQLite data.db into PostgreSQL.

Usage:
    set SCAN_DB_URL=postgres://scan:PASS@127.0.0.1:5432/scan
    python -m app.migrate_pg

Idempotent — ON CONFLICT DO NOTHING so re-runs never duplicate rows.
Primary keys are preserved so all foreign references stay valid,
and sequences are re-based to MAX(id)+1 afterwards.
"""

import sqlite3
import sys
from urllib.parse import unquote, urlsplit

import psycopg2

from .store import DB_PATH, DB_URL

TABLES = [
    "projects", "targets", "scans", "results",
    "settings", "exposure_runs", "exposure_results",
]


def pg_conn():
    u = urlsplit(DB_URL)
    return psycopg2.connect(
        host=u.hostname or "127.0.0.1",
        port=u.port or 5432,
        user=unquote(u.username or "postgres"),
        password=unquote(u.password or ""),
        dbname=(u.path or "/scan").lstrip("/") or "scan",
    )


def main():
    if not DB_URL.startswith(("postgres", "pgsql")):
        sys.exit("SCAN_DB_URL must be set to postgres://... first")
    if not DB_PATH.exists():
        sys.exit(f"no sqlite database at {DB_PATH}")

    # ensure schema exists
    from . import store
    store.init()

    sq = sqlite3.connect(DB_PATH)
    sq.row_factory = sqlite3.Row
    pg = pg_conn()
    cur = pg.cursor()

    total = 0
    for table in TABLES:
        rows = sq.execute(f"SELECT * FROM {table}").fetchall()
        if not rows:
            print(f"{table}: 0 rows (skip)")
            continue
        cols = [d[0] for d in sq.execute(f"SELECT * FROM {table} LIMIT 0").description]
        col_sql = ", ".join(f'"{c}"' for c in cols)
        ph = ", ".join(["%s"] * len(cols))
        sql = (f'INSERT INTO {table}({col_sql}) VALUES({ph}) '
               "ON CONFLICT DO NOTHING")
        data = [tuple(r[c] for c in cols) for r in rows]
        cur.executemany(sql, data)
        print(f"{table}: {cur.rowcount} inserted / {len(rows)} read")
        total += cur.rowcount
    pg.commit()

    # re-base SERIAL sequences above migrated ids
    for table in ("projects", "targets", "scans", "results",
                  "exposure_runs", "exposure_results"):
        cur.execute(
            "SELECT setval(pg_get_serial_sequence(%s, 'id'), "
            "COALESCE((SELECT MAX(id) FROM " + table + "), 0) + 1, false)",
            (table,),
        )
    pg.commit()
    pg.close()
    sq.close()
    print(f"done — {total} rows migrated")


if __name__ == "__main__":
    main()
