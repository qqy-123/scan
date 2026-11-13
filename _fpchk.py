import os, sys, json
os.environ["SCAN_DB_URL"] = "postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan"
sys.path.insert(0, "/opt/scan")
from app import store

conn = store._conn()
print("=== aj scans + options ===")
for r in conn.execute(
    "SELECT id, kind, status, total, alive, options FROM scans"
    " WHERE project_id=8 ORDER BY id DESC LIMIT 8"
).fetchall():
    print(r["id"], r["kind"], r["status"], f"alive={r['alive']}/{r['total']}",
          (r["options"] or "")[:140])

# pick the most recent done scan with fingerprint on
sid = None
for r in conn.execute(
    "SELECT id, options FROM scans WHERE project_id=8 AND status='done'"
    " ORDER BY id DESC"
).fetchall():
    o = json.loads(r["options"] or "{}")
    if o.get("fingerprint", True):
        sid = r["id"]; break
print("=== chosen fp scan:", sid, "===")
if sid:
    rows = conn.execute(
        "SELECT id, url, status_code, title, server, fingerprints"
        " FROM results WHERE scan_id=? AND alive=1 ORDER BY id", (sid,)
    ).fetchall()
    withfp = 0
    for r in rows:
        fps = json.loads(r["fingerprints"] or "[]")
        if fps: withfp += 1
        names = [f.get("name") for f in fps]
        print(f"{r['id']:5} {str(r['status_code']):4} {r['url'][:60]:60} "
              f"fp={names}")
    print(f"alive={len(rows)} withfp={withfp}")
conn.close()
