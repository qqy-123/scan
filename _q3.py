import os
import sys
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan')
from app import store
from collections import Counter

print('scan18:', store.get_scan(18))
rows = store.scan_results(18) if hasattr(store, 'scan_results') else None
if rows is None:
    conn = store._conn()
    rows = conn.execute(
        'SELECT url,alive,status_code,error FROM results WHERE scan_id=18 '
        'ORDER BY id').fetchall()
    rows = [dict(r) for r in rows]
dead = [r for r in rows if not r['alive']]
print('total', len(rows), 'alive', len(rows) - len(dead), 'dead', len(dead))
print('errors:', Counter((r['error'] or '').split(':')[0] for r in dead))
for r in dead:
    print(r['url'], '|', r['error'])
