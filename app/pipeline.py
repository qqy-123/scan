import asyncio
import json
import uuid

from . import bypass
from . import fingerprint as fp
from . import probe, store, traffic

PROBE_CONCURRENCY = 50
BROWSER_CONCURRENCY = 4


async def run_scan(scan_id: int):
    """probe liveness -> browser traffic capture (+screenshot) -> fingerprint
    (passive signals + packet URLs + active probe) -> protection check."""
    scan = store.get_scan(scan_id)
    opts = json.loads(scan["options"])
    project_id = scan["project_id"]

    if opts.get("scope") == "alive":
        targets = store.alive_targets(project_id)
    else:
        targets = store.list_targets(project_id)

    cfg = store.get_settings()
    probe_sem = asyncio.Semaphore(
        opts.get("concurrency") or cfg["concurrency"] or PROBE_CONCURRENCY
    )
    shot_sem = asyncio.Semaphore(
        cfg["browser_concurrency"] or BROWSER_CONCURRENCY
    )
    client = probe.make_client()
    alive_count = 0

    def base_result(target, resp):
        return {
            "scan_id": scan_id,
            "target_id": target["id"],
            "url": target["url"],
            "alive": 1 if resp["alive"] else 0,
            "status_code": resp["status_code"],
            "final_url": resp["final_url"],
            "title": resp["title"],
            "server": resp["server"],
            "elapsed_ms": resp["elapsed_ms"],
            "fingerprints": [],
            "screenshot": None,
            "protection": None,
            "error": resp["error"],
        }

    async def finish_alive(target, resp, row_id=None):
        """Post-alive pipeline: capture + signals + fingerprints + protection.
        row_id given -> update an existing (previously dead) row in place."""
        result = base_result(target, resp)
        want_fp = opts.get("fingerprint", cfg["fingerprint"])
        # no fingerprint pass -> skip the rendered signal collection too
        js_g = fp.js_globals() if want_fp else []
        dom_s = fp.dom_selectors() if want_fp else {}
        signals = None
        shot_name = None

        # browser pass: traffic + rendered signals + screenshot.
        # capture is retried once — navigation races are the common
        # transient failure and a live target should always get its shot
        if opts.get("screenshot", cfg["screenshot"]):
            cap = {"ok": False, "error": "not attempted"}
            for attempt in range(2):
                async with shot_sem:
                    shot_name = f"{scan_id}_{uuid.uuid4().hex[:10]}.png"
                    cap = await traffic.capture(
                        resp["final_url"],
                        traffic.SHOT_DIR / shot_name,
                        js_g,
                        dom_s,
                        proxy=cfg.get("proxy") or None,
                    )
                if cap["ok"]:
                    break
            if cap["ok"]:
                result["screenshot"] = shot_name
                signals = fp.signals_from_capture(cap, resp)
                if cap.get("title"):
                    result["title"] = cap["title"]
            else:
                result["error"] = f"browser: {cap['error']}"
                shot_name = None

        if want_fp:
            # fallback: httpx signals only
            if signals is None:
                favicon_hash = await probe.fetch_favicon_hash(
                    client, resp["final_url"])
                signals = fp.signals_from_response(resp, favicon_hash)

            matched = fp.match(signals)
            hits = list(matched["hits"])

            # active probe: extra requests on characteristic paths
            if opts.get("active_probe", cfg["active_probe"]):
                base = resp["final_url"]
                for rule in matched["candidates"]:
                    for path in rule["probe"]:
                        probe_url = base.rstrip("/") + "/" + path.lstrip("/")
                        try:
                            r = await client.get(probe_url)
                            if r.status_code >= 400 or probe.probe_is_fallback(path, r):
                                continue  # 404/soft-404/html-fallback echoes would false-positive
                            h = fp.evaluate_probe(rule, r.text[:300_000])
                        except Exception:
                            h = None
                        if h:
                            hits.append(h)
                            break

            fps = fp.postprocess(hits)
            result["fingerprints"] = fps
            prot = [h["name"] for h in fps if h["category"] == "防护页"]
            result["protection"] = ",".join(prot) if prot else None

            # front protection detected? try alternate routes to the real service
            if prot:
                bp = await bypass.find_bypass(client, resp["final_url"])
                if bp:
                    bresp = bypass.resp_to_dict(bp["resp"], bp["url"])
                    result["protection"] += f"→bypass:{bp['mode']}"
                    bsignals = None
                    if opts.get("screenshot", cfg["screenshot"]):
                        shot_name = f"{scan_id}_{uuid.uuid4().hex[:10]}.png"
                        async with shot_sem:
                            cap = await traffic.capture(
                                bp["url"], traffic.SHOT_DIR / shot_name,
                                js_g, dom_s,
                                headers=bp["headers"],
                                proxy=cfg.get("proxy") or None)
                        if cap["ok"]:
                            result["screenshot"] = shot_name
                            bsignals = fp.signals_from_capture(cap, bresp)
                    bfps = await bypass.refingerprint(client, bresp, bsignals)
                    if bfps:
                        result["fingerprints"] = bfps
        if row_id:
            store.update_result(row_id, result)
        else:
            store.save_result(result)
            store.bump_done(scan_id)

    async def process(target):
        nonlocal alive_count
        async with probe_sem:
            resp = await probe.fetch(client, target["url"])

        if not resp["alive"]:
            store.save_result(base_result(target, resp))
            store.bump_done(scan_id)
            return

        alive_count += 1
        await finish_alive(target, resp)

    try:
        await asyncio.gather(*(process(t) for t in targets))

        # confirmation pass: a wave of DNS/connect flakes shouldn't condemn
        # live assets — re-probe every dead row once at lower concurrency and
        # revive survivors in place (result stays the latest row per target)
        dead = store.dead_results(scan_id)
        if dead:
            tmap = {t["id"]: t for t in targets}
            conf_client = probe.make_client()
            conf_sem = asyncio.Semaphore(20)

            async def confirm(row):
                nonlocal alive_count
                t = tmap.get(row["target_id"])
                if not t:
                    return
                async with conf_sem:
                    resp = await probe.fetch(conf_client, row["url"])
                if resp["alive"]:
                    alive_count += 1
                    await finish_alive(t, resp, row_id=row["id"])

            try:
                await asyncio.gather(*(confirm(r) for r in dead))
            finally:
                await conf_client.aclose()

        store.finish_scan(scan_id, alive_count)
    except Exception:
        store.fail_scan(scan_id)
        raise
    finally:
        await client.aclose()
