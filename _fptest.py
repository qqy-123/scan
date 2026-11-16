import os
import sys
import asyncio
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:' + open('/root/.scan_dbpw').read().strip()
    + '@127.0.0.1:5432/scan')
from app import fingerprint as fp, probe


async def t():
    client = probe.make_client()
    resp = await probe.fetch(client, 'https://souqappfree.top')
    sig = fp.signals_from_response(resp, None)
    res = fp.match(sig)
    for h in res['hits'][:8]:
        print(h['name'], '|', h['category'], '|', h['confidence'])


asyncio.run(t())
