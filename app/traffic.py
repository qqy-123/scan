"""Browser traffic capture: visit a URL in playwright and collect every
request/response packet triggered by the page (document, scripts, xhr,
fetch, images...). These packets are the richest fingerprint source —
source-code products leak themselves in resource paths like /wui/, /seeyon/,
/wp-content/ regardless of what the homepage HTML says."""

import asyncio
import base64
from pathlib import Path

import mmh3

from .probe import UA

SHOT_DIR = Path(__file__).resolve().parent.parent / "screenshots"
VIEWPORT = {"width": 1366, "height": 900}
MAX_PACKETS = 200
MAX_BODY = 300_000

TEXT_CT = ("html", "javascript", "json", "xml", "text/", "ecmascript", "x-www-form")
# resource types whose URLs are strong fingerprint signals
KEEP_TYPES = {"document", "script", "stylesheet", "xhr", "fetch", "image",
              "font", "manifest", "media"}

_pw = None
_browser = None
_lock = asyncio.Lock()

CHALLENGE_HINTS = ("just a moment", "cf-chl", "challenge-platform", "安全检查中",
                   "window._cf_chl_opt", "safedog", "verify you are human")


async def get_browser():
    global _pw, _browser
    async with _lock:
        if _browser is None or not _browser.is_connected():
            from playwright.async_api import async_playwright

            _pw = await async_playwright().start()
            _browser = await _pw.chromium.launch()
        return _browser


async def _collect(resp, packets, tasks_done):
    try:
        req = resp.request
        rtype = req.resource_type
        entry = {
            "url": resp.url,
            "type": rtype,
            "status": resp.status,
            "headers": {k.lower(): v for k, v in (await resp.all_headers()).items()},
            "method": req.method,
            "body": "",
        }
        ct = entry["headers"].get("content-type", "")
        if rtype in ("document", "xhr", "fetch", "script") and any(
            t in ct for t in TEXT_CT
        ):
            try:
                entry["body"] = (await resp.text())[:MAX_BODY]
            except Exception:
                pass
        packets.append(entry)
    except Exception:
        pass
    finally:
        tasks_done.set()


async def capture(url: str, shot_path: Path | None, js_globals: list,
                  dom_selectors: list, headers: dict | None = None,
                  proxy: str | None = None) -> dict:
    """Visit url, capture traffic + rendered signals + optional screenshot.

    Returns dict:
      ok, error, packets[{url,type,status,headers,method,body}],
      main_doc (first document response), html (rendered),
      script_src, js{global: value}, dom{sel: info}, title,
      favicon_hash, challenge (bool: still on protection page)
    """
    out = {
        "ok": False,
        "packets": [],
        "html": "",
        "script_src": [],
        "js": {},
        "dom": {},
        "title": "",
        "favicon_hash": None,
        "challenge": False,
    }
    packets = out["packets"]
    done_events = []
    ctx = None
    try:
        browser = await get_browser()
        ctx = await browser.new_context(
            ignore_https_errors=True, viewport=VIEWPORT, user_agent=UA,
            extra_http_headers=headers or None,
            proxy={"server": proxy} if proxy else None,
        )
        page = await ctx.new_page()

        def on_response(resp):
            if len(packets) >= MAX_PACKETS:
                return
            ev = asyncio.Event()
            done_events.append(ev)
            asyncio.create_task(_collect(resp, packets, ev))

        page.on("response", on_response)

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=25000)
        except Exception:
            pass
        try:
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass

        # protection interstitial? give JS challenge time to auto-pass, then re-read
        html = await page.content()
        if any(h in html.lower() for h in CHALLENGE_HINTS):
            out["challenge"] = True
            await page.wait_for_timeout(7000)
            html = await page.content()
            if not any(h in html.lower() for h in CHALLENGE_HINTS):
                out["challenge"] = False  # challenge passed, real page now
            else:
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass

        out["html"] = html
        out["title"] = await page.title()
        out["script_src"] = await page.eval_on_selector_all(
            "script[src]", "els => els.map(e => e.src)"
        )
        # one evaluate per signal class — thousands of fingerprints make
        # per-item IPC calls prohibitive (was ~10ms × N globals/selectors)
        if js_globals:
            try:
                out["js"] = await page.evaluate(
                    """(globals) => { const out = {};
                    for (const g of globals) {
                        try { const v = eval(g);
                            if (v !== undefined && v !== null)
                                out[g] = String(v).slice(0, 300); }
                        catch (e) {} }
                    return out; }""", js_globals)
            except Exception:
                pass
        if dom_selectors:
            try:
                out["dom"] = await page.evaluate(
                    """(sels) => { const out = {};
                    for (const s of sels) {
                        try { const el = document.querySelector(s);
                            if (el) out[s] = {
                                exists: true,
                                text: (el.innerText || '').slice(0, 500),
                                attrs: {} }; }
                        catch (e) {} }
                    return out; }""", dom_selectors)
            except Exception:
                pass

        if shot_path is not None:
            shot_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                await page.screenshot(path=str(shot_path))
            except Exception:
                pass

        # favicon from the page's declared icon, fallback /favicon.ico
        icon_url = await page.evaluate(
            "() => { const l = document.querySelector('link[rel~=\"icon\"],link[rel=\"shortcut icon\"]');"
            " return l ? l.href : null; }"
        ) or (str(page.url).split("/")[0] + "//" + str(page.url).split("/")[2] + "/favicon.ico")
        try:
            icon_resp = await ctx.request.get(icon_url)
            if icon_resp.ok:
                body = await icon_resp.body()
                out["favicon_hash"] = mmh3.hash(base64.encodebytes(body))
        except Exception:
            pass
        out["final_url"] = page.url

        if done_events:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(e.wait() for e in done_events), return_exceptions=True),
                    timeout=10,
                )
            except Exception:
                pass  # packet tail-collection is auxiliary — never fail the capture
        out["ok"] = True
        out["error"] = None
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        if ctx:
            try:
                await ctx.close()
            except Exception:
                pass
    return out
