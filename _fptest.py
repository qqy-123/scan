import os
import sys
import asyncio
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:' + open('/root/.scan_dbpw').read().strip()
    + '@127.0.0.1:5432/scan')
from app import fingerprint as fp, probe, bypass


async def t():
    client = probe.make_client()
    resp = await probe.fetch(client, 'https://souqappfree.top')
    sig = fp.signals_from_response(resp, None)
    res = fp.match(sig)
    prot = [h['name'] for h in fp.postprocess(list(res['hits']))
            if h['category'] == '防护页']
    print('gate hits:', [h['name'] for h in res['hits'][:4]])
    print('protection:', prot)
    if prot:
        bp = await bypass.find_bypass(client, resp['final_url'],
                                      resp.get('html', ''))
        print('bypass:', bp['mode'] if bp else None)
        if bp:
            bresp = bypass.resp_to_dict(bp['resp'], bp['url'])
            bfps = await bypass.refingerprint(client, bresp)
            for h in bfps[:8]:
                print(' ', h['name'], '|', h['category'], '|',
                      h['confidence'])


asyncio.run(t())
