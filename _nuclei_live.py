"""Live-check: run the real fingerprint probe pipeline against product
demo/vendor sites and report which hits come from nuclei-converted rules."""
import asyncio
import sys
sys.path.insert(0, ".")
from app import fingerprint as fp, probe

TARGETS = [
    "https://www.discuz.net/",          # Discuz forum
    "https://demo.phpmyadmin.net/",     # phpMyAdmin demo
    "https://wordpress.org/",           # WordPress
    "https://gitlab.com/users/sign_in", # GitLab signin
    "https://www.seeyon.com/",          # 致远 OA vendor
    "https://www.sangfor.com.cn/",      # 深信服
    "https://www.zentao.net/",          # 禅道 vendor
]


async def test(client, url):
    resp = await probe.fetch(client, url)
    if not resp["alive"]:
        print(f"\n== {url}  unreachable: {resp['error']}", flush=True)
        return
    fav = await probe.fetch_favicon_hash(client, resp["final_url"])
    signals = fp.signals_from_response(resp, fav)
    matched = fp.match(signals)
    hits = list(matched["hits"])
    home, deep = fp.probe_plan(matched["candidates"], 60)
    home_resp = {"status": resp["status_code"], "headers": resp["headers"],
                 "body": resp["html"]}
    for rule, p in home:
        h = fp.evaluate_probe(rule, p, home_resp)
        if h:
            hits.append(h)
    print(f"\n== {url}  {resp['status_code']} {resp['title'][:40]} "
          f"(probing {len(deep[:40])} paths)", flush=True)
    for path, rules in deep[:40]:
        try:
            r = await client.get(
                f"{resp['final_url'].split('//')[0]}//{resp['final_url'].split('/')[2]}/{path.lstrip('/')}",
                timeout=8)
            print(".", end="", flush=True)
            if r.status_code >= 400:
                continue
            presp = {"status": r.status_code, "headers": dict(r.headers),
                     "body": r.text[:300_000]}
            for rule in rules:
                h = fp.evaluate_probe(rule, path, presp)
                if h:
                    hits.append(h)
        except Exception:
            print("x", end="", flush=True)
            continue
    fps = fp.postprocess(hits)
    src = {r["name"]: r.get("_file") for r in fp.load_rules()}
    names = [(h["name"], h["level"]) for h in fps]
    nuc = [n for n, _ in names if src.get(n) == "nuclei_tech.json"]
    print(f"\n   all: {[n for n,_ in names]}", flush=True)
    print(f"   nuclei: {nuc}", flush=True)


async def main():
    client = probe.make_client()
    for u in TARGETS:
        try:
            await test(client, u)
        except Exception as e:
            print(f"\n== {u}  ERROR {e}", flush=True)
    print("\nDONE", flush=True)

asyncio.run(main())
