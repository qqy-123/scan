import asyncio
import sys
sys.path.insert(0, '.')
import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

URLS = [
    # flapped alive in triage but dead in reverify
    "https://cg51.com",
    "https://armed.czeemiefc.cc",
    "https://76.azureedge.net",
    "https://9353dd.ggowhyfbqp.top:2000",
    "http://155.985268.com/support",
    "https://vw.aagkfl.cn",
    "https://1.pmwgryyb.top",
    # TCP_FAIL / HTTP_FAIL samples
    "https://fq.12czz3.com",
    "https://239006.cc",
    "https://wsojei673.jxlsib.cn/DH194",
    "http://souqappfree.top",
]


async def try_url(client, url):
    try:
        r = await client.get(url, timeout=httpx.Timeout(
            connect=8, read=10, write=8, pool=20))
        return f"{r.status_code} {len(r.content)}b"
    except Exception as e:
        return f"{type(e).__name__}"


async def main():
    direct = httpx.AsyncClient(
        verify=False, follow_redirects=True,
        headers={'User-Agent': UA},
        limits=httpx.Limits(max_connections=30))
    proxied = httpx.AsyncClient(
        verify=False, follow_redirects=True, proxy="http://127.0.0.1:7777",
        headers={'User-Agent': UA},
        limits=httpx.Limits(max_connections=30))
    print(f"{'URL':55} {'DIRECT':22} {'PROXY':22}")
    res = await asyncio.gather(
        *[asyncio.gather(try_url(direct, u), try_url(proxied, u))
          for u in URLS])
    for u, (d, p) in zip(URLS, res):
        mark = "  <<<" if d != p and not p.endswith('Error') else ""
        print(f"{u[:55]:55} {d:22} {p:22}{mark}")
    await direct.aclose()
    await proxied.aclose()

asyncio.run(main())
