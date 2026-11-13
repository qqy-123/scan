import os, sys, json, asyncio, re
os.environ["SCAN_DB_URL"] = "postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan"
sys.path.insert(0, "/opt/scan")
import httpx
from app import fingerprint as fp, probe

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")

async def site_fps(url, do_probes=True):
    """Rebuild signals like the pipeline does (httpx-only path)."""
    client = httpx.AsyncClient(follow_redirects=True, timeout=15,
                               verify=False, headers={"User-Agent": UA})
    resp = await probe.fetch(client, url)
    if not resp["alive"]:
        return {"dead": True, "err": resp.get("error")}
    fav = await probe.fetch_favicon_hash(client, resp["final_url"])
    sig = fp.signals_from_response(resp, fav)
    m = fp.match(sig)
    hits = list(m["hits"])
    if do_probes and m["candidates"]:
        base = resp["final_url"]
        baseline = await probe.probe_baseline(client, base)
        for rule in m["candidates"]:
            for path in rule["probe"]:
                p_url = base.rstrip("/") + "/" + path.lstrip("/")
                try:
                    r = await client.get(p_url)
                    if r.status_code >= 400 or \
                            probe.probe_is_fallback(path, r) or \
                            (baseline is not None and
                             probe.probe_matches_baseline(
                                 r.text[:300_000],
                                 "/" + path.lstrip("/"), baseline)):
                        continue
                    h = fp.evaluate_probe(rule, r.text[:300_000])
                except Exception:
                    h = None
                if h:
                    hits.append(h); break
    await client.aclose()
    out = {}
    for h in fp.postprocess(hits):
        out[h["name"]] = (h["score"], h["level"],
                          {e["field"] for e in h.get("evidence") or []})
    return out

def show(url, expect_gone=None, expect_keep=None):
    r = asyncio.run(site_fps(url))
    if r.get("dead"):
        print(f"DEAD {url[:60]} {r['err']}")
        return
    print(f"\n== {url[:70]}")
    names = set(r)
    for n, (s, lv, fields) in sorted(r.items()):
        print(f"   {lv:9} {n}  score={s} via={sorted(fields)}")
    for g in (expect_gone or []):
        print(f"   [{'OK' if g not in names else 'FAIL'}] gone: {g}")
    for k in (expect_keep or []):
        print(f"   [{'OK' if k in names else 'MISS'}] keep: {k}")

# A. FP regression on live sites
show("https://c3.xmytwya1.shop/10-20/m8qz33.html?key=adnffnaqup",
     expect_gone=[], expect_keep=["Nginx", "jQuery"])
print("   (Jenkins should be low/absent now)")
show("https://qfile.qq.com/q/8G5Az3rl76",
     expect_gone=["Phoenix Cart"], expect_keep=["Nuxt.js", "Pinia"])
show("https://kcnampvj4ciw.feishu.link/app/app_17h2axnvpx3/call/e7b13b8fbc27902d55ad7bco",
     expect_gone=["Magento", "PHP", "MySQL"], expect_keep=[])
show("https://albbd.z11.web.core.windows.net/?flowT=1793639533771&flowSign=e0aed8cbdf&flow=flow",
     expect_keep=["Ant Design", "jQuery", "Azure"])
show("https://api.tyrbvfgd.site/api/config/clientConfig",
     expect_keep=["Cloudflare", "PHP"])

# B. unit: cookie anchoring
print("\n== B: cookie key anchoring")
sig = {"url": "https://x", "headers": {}, "meta": {}, "cookies": {"deviceId": "abc"},
       "html": "<html></html>", "title": "", "script_src": [], "scripts": "",
       "favicon": "", "js": {}, "dom": {}, "urls": [], "xhr_urls": []}
hits = fp.match(sig)["hits"]
names = {h["name"] for h in hits}
print("   deviceId cookie -> hits:", names or "(none)")
print("   [{'OK' if 'Phoenix Cart' not in names else 'FAIL'}]")
sig["cookies"] = {"ceid": "1"}
hits = fp.match(sig)["hits"]
names = {h["name"] for h in hits}
print("   ceid cookie -> hits:", names or "(none)")

# C. unit: new CN rules on synthetic pages
print("\n== C: CN stack rules")
cases = [
    ("uni-app", '<html><head><script>window.__uniConfig={pages:[]}</script></head></html>'),
    ("layui", '<link href="/static/layui/css/layui.css"><div class="layui-layer">'),
    ("宝塔面板", '<html><title>宝塔Linux面板</title></html>'),
    ("微信 JS-SDK", '<script src="https://res.wx.qq.com/open/js/jweixin-1.6.0.js"></script>'),
    ("混淆页面", '<script>document.write(decodeURIComponent("%3Chtml%3E"))</script>'),
    ("JS 跳转", '<script>window.location.href="https://x.com/";</script>'),
    ("流量分发", '<script>var targetSites=["a.com"];location=targetSites[0]</script>'),
    ("uView UI", '<body><u-navbar title="x"></u-navbar><u-button>go</u-button></body>'),
    ("蓝奏云", '<meta name="Copyright" content="Woozooo"><title>蓝奏·云存储</title>'),
    ("友盟+", '<script src="https://s9.cnzz.com/z_stat.php?id=1"></script>'),
    ("Mint UI", '<div class="mint-swipe"><div class="mint-swipe-item">'),
]
for want, html in cases:
    sig = {"url": "https://t.com", "headers": {}, "meta": {}, "cookies": {},
           "html": html, "title": "", "script_src": [
               s for s in re.findall(r'src="([^"]+)"', html)],
           "scripts": html, "favicon": "", "js": {}, "dom": {},
           "urls": [], "xhr_urls": []}
    names = {h["name"] for h in fp.postprocess(fp.match(sig)["hits"])}
    print(f"   [{'OK' if want in names else 'FAIL'}] {want}: {sorted(names)}")

# D. baseline normalization
print("\n== D: catch-all baseline")
async def _bl():
    c = httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False,
                          headers={"User-Agent": UA})
    base = "https://kcnampvj4ciw.feishu.link/app/app_17h2axnvpx3/call/e7b13b8fbc27902d55ad7bco"
    bl = await probe.probe_baseline(c, base)
    r = await c.get(base + "/magento_version")
    same = probe.probe_matches_baseline(r.text[:300_000], "/magento_version", bl) if bl else None
    print(f"   baseline={'<none>' if bl is None else len(bl)} "
          f"magento_version_is_catchall={same}")
    # real-wordpress-like case: baseline vs DIFFERENT body must not match
    fake = "<html><body>TOTALLY DIFFERENT wp-login form</body></html>"
    print(f"   distinct_body_is_catchall={probe.probe_matches_baseline(fake, '/wp-login.php', bl) if bl else 'n/a'}")
    await c.aclose()
asyncio.run(_bl())
