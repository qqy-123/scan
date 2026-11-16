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
    "SELECT url FROM results WHERE scan_id=1 AND alive=0 "
    "ORDER BY id").fetchall()]
conn.close()
print(f"re-probing {len(rows)} dead (default dual-stack client)", flush=True)
sem = asyncio.Semaphore(30)


async def one(client, url):
    async with sem:
        r = await probe.fetch(client, url, retry=False)
        return url, r


async def main():
    client = probe.make_client()
    alive, dead = [], []
    for fut in asyncio.as_completed([one(client, r['url']) for r in rows]):
        url, r = await fut
        (alive if r['alive'] else dead).append(
            (url, r.get('status_code'), r.get('error')))
    await client.aclose()
    from collections import Counter
    print(f"\nALIVE now: {len(alive)}")
    for u, s, _ in alive[:30]:
        print(f"  {s} {u[:90]}")
    print(f"still dead: {len(dead)}",
          Counter((e or '').split(':')[0] for _, _, e in dead))

asyncio.run(main())
