import asyncio
import json
import uuid
from urllib.parse import urlsplit

from . import fingerprint as fp
from . import probe, screenshot, store

PROBE_CONCURRENCY = 50
SHOT_CONCURRENCY = 4


async def run_scan(scan_id: int):
    """Full pipeline: probe liveness -> fingerprint (passive + active probe)
    -> screenshot (+ rendered signals, second-pass fingerprint)."""
    scan = store.get_scan(scan_id)
    opts = json.loads(scan["options"])
    project_id = scan["project_id"]

    if opts.get("scope") == "alive":
        targets = store.alive_targets(project_id)
    else:
        targets = store.list_targets(project_id)

    probe_sem = asyncio.Semaphore(opts.get("concurrency") or PROBE_CONCURRENCY)
    shot_sem = asyncio.Semaphore(SHOT_CONCURRENCY)
    client = probe.make_client()
    alive_count = 0

    async def process(target):
        nonlocal alive_count
        url = target["url"]
        async with probe_sem:
            resp = await probe.fetch(client, url)

        result = {
            "scan_id": scan_id,
            "target_id": target["id"],
            "url": url,
            "alive": 1 if resp["alive"] else 0,
            "status_code": resp["status_code"],
            "final_url": resp["final_url"],
            "title": resp["title"],
            "server": resp["server"],
            "elapsed_ms": resp["elapsed_ms"],
            "fingerprints": [],
            "screenshot": None,
            "error": resp["error"],
        }
        if not resp["alive"]:
            store.save_result(result)
            store.bump_done(scan_id)
            return

        alive_count += 1
        favicon_hash = await probe.fetch_favicon_hash(client, resp["final_url"])
        signals = fp.signals_from_response(resp, favicon_hash)

        # passive match
        first = fp.match(signals)
        hits = list(first["hits"])

        # active probe: candidate rules + probe-only rules
        if opts.get("active_probe", True):
            base = resp["final_url"]
            for rule in first["candidates"]:
                for path in rule["probe"]:
                    probe_url = base.rstrip("/") + "/" + path.lstrip("/")
                    try:
                        r = await client.get(probe_url)
                        h = fp.evaluate_probe(rule, r.text[:300_000])
                    except Exception:
                        h = None
                    if h:
                        hits.append(h)
                        break

        # screenshot + rendered second pass
        if opts.get("screenshot", True):
            async with shot_sem:
                shot_name = f"{scan_id}_{uuid.uuid4().hex[:10]}.png"
                rendered = await screenshot.capture(
                    resp["final_url"],
                    screenshot.SHOT_DIR / shot_name,
                    fp.js_globals(),
                    fp.dom_selectors(),
                )
            if "error" not in rendered:
                result["screenshot"] = shot_name
                fp.merge_rendered(signals, rendered)
                second = fp.match(signals)
                seen = {h["name"] for h in hits}
                for h in second["hits"]:
                    if h["name"] not in seen:
                        hits.append(h)
            else:
                result["error"] = f"screenshot: {rendered['error']}"

        result["fingerprints"] = fp.postprocess(hits)
        store.save_result(result)
        store.bump_done(scan_id)

    try:
        await asyncio.gather(*(process(t) for t in targets))
        store.finish_scan(scan_id, alive_count)
    except Exception:
        store.fail_scan(scan_id)
        raise
    finally:
        await client.aclose()
