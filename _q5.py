import asyncio
import os
import socket
import sys
from urllib.parse import urlsplit
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan')
import httpx
from app import store, probe

conn = store._conn()
rows = conn.execute(
    "SELECT id,url,error FROM results WHERE scan_id=18 AND alive=0 "
    "ORDER BY id").fetchall()
dead = [dict(r) for r in rows]
conn.close()
print(f"{len(dead)} dead rows to triage", flush=True)

UA = probe.UA
sem = asyncio.Semaphore(40)


async def dns_check(host):
    try:
        infos = await asyncio.get_event_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except Exception as e:
        return f"DNS:{type(e).__name__}"


async def tcp_check(ip, port, host=None):
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port), 6)
        w.close()
        return True
    except Exception:
        return False


async def http_check(client, url):
    try:
        r = await client.get(url, timeout=httpx.Timeout(
            connect=8, read=10, write=8, pool=30))
        return f"HTTP {r.status_code}"
    except Exception as e:
        return f"HTTP:{type(e).__name__}"


async def one(client, row):
    url = row['url']
    p = urlsplit(url if '://' in url else 'https://' + url)
    host = p.hostname or ''
    port = p.port or (443 if p.scheme == 'https' else 80)
    async with sem:
        ips = await dns_check(host)
        if isinstance(ips, str):
            return url, 'DNS_FAIL', ips
        tcp = await tcp_check(ips[0], port)
        if not tcp and port != 80:
            tcp = await tcp_check(ips[0], 80)
        if not tcp:
            return url, 'TCP_FAIL', ','.join(ips[:2])
        http = await http_check(client, url)
        if http.startswith('HTTP:'):
            # try alternate scheme once before declaring dead
            alt = ('http://' if p.scheme == 'https' else 'https://') + p.netloc + p.path
            http2 = await http_check(client, alt)
            if http2.startswith('HTTP '):
                http = http2 + ' (alt-scheme)'
            else:
                return url, 'HTTP_FAIL', http[5:]
        return url, 'ALIVE', http


async def main():
    client = httpx.AsyncClient(verify=False, follow_redirects=True,
                               headers={'User-Agent': UA},
                               limits=httpx.Limits(max_connections=60))
    from collections import Counter
    out = []
    for fut in asyncio.as_completed([one(client, r) for r in dead]):
        out.append(await fut)
    await client.aclose()
    cnt = Counter(x[1] for x in out)
    print('\n=== verdicts ===', dict(cnt))
    for url, v, d in sorted(out, key=lambda x: x[1]):
        print(f"{v:10} {d[:38]:38} {url[:95]}")

asyncio.run(main())
