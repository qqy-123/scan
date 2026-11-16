import asyncio
import os
import sys
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:' + open('/root/.scan_dbpw').read().strip()
    + '@127.0.0.1:5432/scan')
from app import store, probe

conn = store._conn()
rows = [dict(r) for r in conn.execute(
    "SELECT id,target_id,url FROM results WHERE scan_id=1 AND alive=0 "
    "ORDER BY id").fetchall()]
conn.close()

# EXACT reverify conditions: sem=50, retry=False, one shared client
sem = asyncio.Semaphore(50)


async def one(client, row):
    async with sem:
        r = await probe.fetch(client, row['url'], retry=False)
        return row['url'], r


async def main():
    client = probe.make_client()
    res = await asyncio.gather(*(one(client, r) for r in rows))
    await client.aclose()
    from collections import Counter
    alive = [x for x in res if x[1]['alive']]
    dead = [x for x in res if not x[1]['alive']]
    print(f"alive: {len(alive)} dead: {len(dead)}")
    for u, r in alive[:20]:
        print(' ', r['status_code'], u[:85])
    print(Counter((r['error'] or '').split(':')[0] for _, r in dead))

asyncio.run(main())
