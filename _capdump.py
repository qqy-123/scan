import os
import sys
import asyncio
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:' + open('/root/.scan_dbpw').read().strip()
    + '@127.0.0.1:5432/scan')
from app import traffic


async def t():
    cap = await traffic.capture(
        'https://souqappfree.top/wap/', None, [], {})
    print('ok:', cap.get('ok'), 'err:', cap.get('error'))
    print('final:', cap.get('final_url'))
    pkts = cap.get('packets') or []
    print('packets:', len(pkts))
    for p in pkts:
        t = p.get('type')
        if t in ('xhr', 'fetch'):
            print(' XHR:', p.get('url'))
    import collections
    paths = collections.Counter()
    for p in pkts:
        u = p.get('url') or ''
        if 'souqappfree' in u:
            path = u.split('souqappfree.top', 1)[1].split('?')[0]
            paths[path] += 1
    other = [u for u in (p.get('url') for p in pkts)
             if u and 'souqappfree' not in u]
    print('--- same-host paths (top40):')
    for k, v in paths.most_common(40):
        print(f'  {v:3d} {k}')
    print('--- off-host:', len(other))
    for u in other[:15]:
        print('  ', u[:120])


asyncio.run(t())
