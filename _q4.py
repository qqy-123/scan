import asyncio
import os
import sys
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan')
from app import store, probe

conn = store._conn()
rows = conn.execute(
    "SELECT url,error FROM results WHERE scan_id=18 AND alive=0 "
    "ORDER BY id").fetchall()
dead = [dict(r) for r in rows]
print(f"re-checking {len(dead)} dead targets", flush=True)

sem = asyncio.Semaphore(30)


async def one(client, r):
    async with sem:
        resp = await probe.fetch(client, r['url'])
        return r['url'], resp


async def main():
    client = probe.make_client()
    tasks = [one(client, r) for r in dead]
    alive, still = [], []
    for fut in asyncio.as_completed(tasks):
        url, resp = await fut
        if resp['alive']:
            alive.append((url, resp['status_code'], resp['title'][:30]))
        else:
            still.append((url, resp['error']))
    print(f"\n=== now-alive: {len(alive)} ===")
    for u, s, t in alive:
        print(f"  {s}  {u}  {t}")
    print(f"\n=== still dead: {len(still)} ===")
    from collections import Counter
    print(Counter((e or '').split(':')[0] for _, e in still))

asyncio.run(main())
