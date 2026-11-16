import asyncio
import json
import uuid
from urllib.parse import urlsplit

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

    async def probe_only(target):
        """Phase 1: pure liveness probe — cheap IO-bound connects get the
        box to themselves; no browser CPU competing to starve them into
        false ConnectTimeout verdicts."""
        async with probe_sem:
            resp = await probe.fetch(client, target["url"])
        if not resp["alive"]:
            store.save_result(_base_result(scan_id, target, resp))
            store.bump_done(scan_id)
            return None
        return target, resp

    async def enrich(survivor):
        """Phase 2: capture + fingerprint for a confirmed-alive target."""
        nonlocal alive_count
        target, resp = survivor
        alive_count += 1
        await _finish_alive(scan, opts, cfg, client, shot_sem, probe_sem,
                            target, resp)

    try:
        survivors = await asyncio.gather(
            *(probe_only(t) for t in targets))
        await asyncio.gather(*(enrich(s) for s in survivors if s))

        # confirmation pass: a wave of DNS/connect flakes shouldn't condemn
        # live assets — re-probe every dead row once at lower concurrency and
        # revive survivors in place (result stays the latest row per target)
        tmap = {t["id"]: t for t in targets}
        alive_count += await _reverify_dead(scan, opts, cfg, tmap)

        store.finish_scan(scan_id, alive_count)
    except Exception:
        store.fail_scan(scan_id)
        raise
    finally:
        await client.aclose()


def _base_result(scan_id, target, resp):
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


async def _finish_alive(scan, opts, cfg, client, shot_sem, probe_sem,
                        target, resp, row_id=None):
    """Post-alive pipeline: capture + signals + fingerprints + protection.
    row_id given -> update an existing (previously dead) row in place."""
    scan_id = scan["id"]
    result = _base_result(scan_id, target, resp)
    want_fp = opts.get("fingerprint", cfg["fingerprint"])
    # no fingerprint pass -> skip the rendered signal collection too
    js_g = fp.js_globals() if want_fp else []
    dom_s = fp.dom_selectors() if want_fp else {}
    signals = None
    shot_name = None
    cap = None

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
                client, resp["final_url"], resp.get("html", ""))
            signals = fp.signals_from_response(resp, favicon_hash)

        matched = fp.match(signals)
        hits = list(matched["hits"])

        # active probe: extra requests on characteristic paths
        if opts.get("active_probe", cfg["active_probe"]) and \
                matched["candidates"]:
            base = resp["final_url"]
            home, deep = fp.probe_plan(
                matched["candidates"],
                cfg.get("fp_probe_budget", 80))
            home_resp = {
                "status": resp["status_code"],
                "headers": resp["headers"],
                "body": (cap or {}).get("html") or resp["html"],
            }
            for rule, pth in home:
                h = fp.evaluate_probe(rule, pth, home_resp)
                if h:
                    hits.append(h)
            baseline = (await probe.probe_baseline(
                client, base, probe_sem)) if deep else None
            for path, rules in deep:
                if any(r.get("probe_root") for r in rules):
                    u = urlsplit(base)
                    root = f"{u.scheme}://{u.netloc}"
                else:
                    root = base.rstrip("/")
                probe_url = root + "/" + path.lstrip("/")
                try:
                    r = await client.get(probe_url)
                    if r.status_code >= 400 or \
                            probe.probe_is_fallback(path, r) or \
                            (baseline is not None and
                             probe.probe_matches_baseline(
                                 r.text[:300_000], path, baseline)):
                        continue  # 404/soft-404/catch-all echoes would false-positive
                    presp = {"status": r.status_code,
                             "headers": dict(r.headers),
                             "body": r.text[:300_000]}
                    for rule in rules:
                        h = fp.evaluate_probe(rule, path, presp)
                        if h:
                            hits.append(h)
                except Exception:
                    continue

        fps = fp.postprocess(hits)
        result["fingerprints"] = fps
        prot = [h["name"] for h in fps if h["category"] == "防护页"]
        result["protection"] = ",".join(prot) if prot else None

        # front protection detected? try alternate routes to the real service
        if prot:
            bp = await bypass.find_bypass(client, resp["final_url"],
                                          resp.get("html", ""))
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


async def _reverify_dead(scan, opts, cfg, tmap) -> int:
    """Re-probe this scan's dead rows; revive survivors through the full
    post-alive pipeline in place. Returns the number revived — used both
    by run_scan's confirmation pass and the manual reverify endpoint.

    Rounds: scam/phish targets flap on minute scales and this box's
    egress has short outage windows — a single wave can miss an entire
    up-cycle. Repeat up to 3 rounds while revivals keep coming, with a
    settle gap so the next round sees a different flap window."""
    client = probe.make_client()
    # dead re-probes are cheap TCP attempts (no body, no browser) — run them
    # at full scan concurrency, and skip fetch's built-in retry: this pass
    # IS the retry on top of the main wave's two attempts
    sem = asyncio.Semaphore(cfg["concurrency"] or 50)
    shot_sem = asyncio.Semaphore(
        cfg["browser_concurrency"] or BROWSER_CONCURRENCY)
    revived = 0

    async def confirm(row):
        """Re-probe only — no browser work inside, so revive captures
        can't starve the remaining dead-target checks."""
        t = tmap.get(row["target_id"])
        if not t:
            return None
        async with sem:
            resp = await probe.fetch(client, row["url"], retry=False)
        return (row, t, resp)

    async def revive(s):
        nonlocal revived
        row, t, resp = s
        revived += 1
        await _finish_alive(scan, opts, cfg, client, shot_sem, sem,
                            t, resp, row_id=row["id"])

    try:
        for rnd in range(3):
            dead = store.dead_results(scan["id"])
            if not dead:
                break
            # uplink sanity gate: if the scanner itself can't reach the net
            # the whole wave would re-condemn live targets — bail instead
            if not await probe.canary_ok(client):
                await asyncio.sleep(20)
                if not await probe.canary_ok(client):
                    break
            res = [x for x in
                   await asyncio.gather(*(confirm(r) for r in dead)) if x]
            hits = [x for x in res if x[2]["alive"]]
            # a wave that is mostly timeouts looks like congestion, not
            # death — refused/DNS-fail waves are genuinely dead
            timeoutish = sum(
                1 for x in res
                if not x[2]["alive"] and "Timeout" in (x[2]["error"] or "")
            ) > len(res) * 0.5
            if hits:
                await asyncio.gather(*(revive(s) for s in hits))
                await asyncio.sleep(15)  # let flapped-down hosts recover
            elif timeoutish and rnd == 0:
                await asyncio.sleep(15)  # one mulligan for a congested wave
            else:
                break
    finally:
        await client.aclose()
    return revived


async def reverify_scan(scan_id: int):
    """Manual dead-target re-verification for a finished/failed scan — the
    same confirmation pass the auto pipeline runs, on demand (e.g. after a
    scan was killed mid-confirm by a restart or ran during an outage)."""
    scan = store.get_scan(scan_id)
    if not scan or scan["status"] == "running":
        return
    targets = store.list_targets(scan["project_id"])
    store.set_scan_status(scan_id, "running", "reverify")
    try:
        await _reverify_dead(
            scan, json.loads(scan["options"]), store.get_settings(),
            {t["id"]: t for t in targets})
        store.finish_scan(scan_id, store.count_alive(scan_id))
    except Exception:
        store.fail_scan(scan_id)
        raise
