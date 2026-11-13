import os, sys, json, re
os.environ["SCAN_DB_URL"] = "postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan"
sys.path.insert(0, "/opt/scan")
import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
MUA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
       "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1")

def get(url, ua=UA, timeout=15):
    with httpx.Client(follow_redirects=True, timeout=timeout, verify=False,
                      headers={"User-Agent": ua}) as c:
        r = c.get(url)
    return r

def show(url, ua=UA, label="", limit=700):
    try:
        r = get(url, ua)
        print(f"\n##### {label} {url[:70]}")
        print(f"  {r.status_code} server={r.headers.get('server','')} "
              f"ct={r.headers.get('content-type','')[:40]} len={len(r.text)}")
        body = re.sub(r"\s+", " ", r.text)[:limit]
        print(f"  {body}")
    except Exception as e:
        print(f"\n##### {label} {url[:70]}  ERR {e}")

# 1. xmytwya1.shop — what triggered Jenkins /static/[0-9a-f]{8}?
print("=== A: xmytwya1.shop body + asset urls ===")
r = get("https://c3.xmytwya1.shop/10-20/m8qz33.html?key=adnffnaqup")
print(r.text[:1200])
print("  SRC/HREF:", re.findall(r'(?:src|href)="([^"]+)"', r.text)[:15])

# 2. SPA fallback test on feishu (magento probe FP source)
print("\n=== B: feishu.link probe path ===")
for p in ["/magento_version", "/nonexistent_xyz_123"]:
    show(f"https://kcnampvj4ciw.feishu.link/app/app_17h2axnvpx3/call/e7b13b8fbc27902d55ad7bco{p}", label="probe")

# 3. tiny shells — what are they really
for u, lb in [
    ("https://v6d8.top", "v6d8"),
    ("https://qkc001.com", "qkc001"),
    ("https://sj1020a135.q2xv1b.top", "sj1020"),
    ("https://9986541.cn", "9986541"),
    ("https://www.hm2023t.vip:9527/?zme01J3GYbsmBeIC+L1va3ks4TG8T51JQ%3DQ==", "hm2023"),
    ("http://riwigra8.cardlist.youliyouhuo.com/?ek=ziVpkBV2f0_JbhD", "riwigra"),
    ("https://9.2179xiu.cc", "2179xiu"),
    ("https://11p5hankandapian5688.cc", "hankandapian"),
    ("https://wwapu.lanzouq.com", "lanzouq"),
]:
    show(u, label=lb, limit=500)

# 4. mobile UA differential on a couple
print("\n=== C: mobile UA ===")
for u in ["https://v6d8.top", "https://qkc001.com", "https://9.2179xiu.cc"]:
    show(u, ua=MUA, label="MUA", limit=400)
