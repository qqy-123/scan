import os
import sys
sys.path.insert(0, '.')
os.environ.setdefault(
    'SCAN_DB_URL',
    'postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan')
from app import store

conn = store._conn()
print('=== projects (latest) ===')
for row in conn.execute(
        'SELECT id,name,created_at FROM projects ORDER BY id DESC LIMIT 8'
        ).fetchall():
    print(row['id'], row['name'], row['created_at'])

print('=== souqappfree targets ===')
for row in conn.execute(
        "SELECT * FROM targets WHERE url LIKE '%souqappfree%'").fetchall():
    print({k: row[k] for k in row.keys()})

print('=== souqappfree in scan results ===')
for row in conn.execute(
        "SELECT id,scan_id,target_id,url,alive,status_code,title,error,final_url "
        "FROM results WHERE url LIKE '%souqappfree%' ORDER BY id DESC LIMIT 5"
        ).fetchall():
    print({k: row[k] for k in row.keys()})
