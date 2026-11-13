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
                   "window._cf_chl_opt", "safedog", "verify you are human",
                   "/_guard/", "security verification", "click in sequence",
                   "安全验证", "请依次点击")


# /_guard/-style click-captcha solver: the word sprite (a window into the same
# source image, positioned via background-position) is template-matched against
# the scene region — required icons are clicked in order.
_GUARD_SOLVER_JS = r"""
async () => {
  const scene = document.querySelector('.clickableImg');
  const word = document.querySelector('.word');
  if (!scene || !word) return { err: 'dom' };
  const cs = getComputedStyle(scene), cw = getComputedStyle(word);
  const urlOf = s => (s.match(/url\(["']?([^"')]+)/) || [])[1];
  const src = urlOf(cs.backgroundImage) || urlOf(cw.backgroundImage);
  if (!src) return { err: 'bg' };
  const im = new Image();
  im.src = new URL(src, location.href).href;
  try { await im.decode(); } catch (e) { return { err: 'decode' }; }
  const W = im.naturalWidth, H = im.naturalHeight;
  // only natural-size backgrounds handled (background-size: auto)
  if (!/^auto/.test(cs.backgroundSize)) return { err: 'bsize:' + cs.backgroundSize };
  const posCoord = (tok, imgLen, boxLen) => {
    tok = (tok || '0%').toLowerCase().trim();
    if (tok.endsWith('%')) return (imgLen - boxLen) * parseFloat(tok) / 100;
    if (tok.endsWith('px')) return -parseFloat(tok);
    const kw = { left: 0, top: 0, center: .5, right: 1, bottom: 1 };
    return (imgLen - boxLen) * (tok in kw ? kw[tok] : 0);
  };
  const sPos = cs.backgroundPosition.split(/\s+/);
  const wPos = cw.backgroundPosition.split(/\s+/);
  const sRect = scene.getBoundingClientRect();
  const wRect = word.getBoundingClientRect();
  const sx0 = Math.round(posCoord(sPos[0], W, sRect.width));
  const sy0 = Math.round(posCoord(sPos[1] || sPos[0], H, sRect.height));
  const sw = Math.round(sRect.width), sh = Math.round(sRect.height);
  const wx0 = Math.round(posCoord(wPos[0], W, wRect.width));
  const wy0 = Math.round(posCoord(wPos[1] || wPos[0], H, wRect.height));
  const ww = Math.round(wRect.width), wh = Math.round(wRect.height);
  if (wx0 < 0 || wy0 < 0 || wx0 + ww > W || wy0 + wh > H
      || sx0 < 0 || sy0 < 0 || sx0 + sw > W || sy0 + sh > H)
    return { err: 'win', dbg: [sx0, sy0, sw, sh, wx0, wy0, ww, wh, W, H] };
  const cvs = document.createElement('canvas');
  cvs.width = W; cvs.height = H;
  const g = cvs.getContext('2d', { willReadFrequently: true });
  g.drawImage(im, 0, 0);
  const sd = g.getImageData(sx0, sy0, sw, sh).data;
  // scan the full-width strip rows — icons near the visible window's edge
  // would otherwise be clipped
  const wd = g.getImageData(0, wy0, W, wh).data;
  const nonWhite = (d, i) => d[i] < 235 || d[i+1] < 235 || d[i+2] < 235;
  const gray = (d, i) => .299*d[i] + .587*d[i+1] + .114*d[i+2];
  const runs = [];
  let s0 = -1;
  for (let x = 0; x < W; x++) {
    let has = false;
    for (let y = 0; y < wh; y += 2)
      if (nonWhite(wd, (y * W + x) * 4)) { has = true; break; }
    if (has) { if (s0 < 0) s0 = x; }
    else if (s0 >= 0) { if (x - s0 > 6) runs.push([s0, x]); s0 = -1; }
  }
  if (s0 >= 0 && W - s0 > 6) runs.push([s0, W]);
  if (!runs.length || runs.length > 12) return { err: 'runs:' + runs.length };
  const icons = [];
  for (const [x0, x1] of runs) {
    let y0 = wh, y1 = 0;
    for (let x = x0; x < x1; x++)
      for (let y = 0; y < wh; y++)
        if (nonWhite(wd, (y * W + x) * 4)) {
          if (y < y0) y0 = y; if (y > y1) y1 = y; }
    // icons are ~square ~28px; separator arrows are flat (~7px tall)
    if (x1 - x0 >= 10 && x1 - x0 <= 80 && y1 - y0 >= 14)
      icons.push({ x0, x1, y0, y1: y1 + 1 });
  }
  if (!icons.length || icons.length > 8) return { err: 'icons:' + icons.length };
  // grayscale NCC over non-white template pixels (icon art may sit on a photo)
  const scoreAt = (ic, tw, th, px, py) => {
    let num = 0, a2 = 0, b2 = 0, n = 0;
    for (let y = 0; y < th; y++) for (let x = 0; x < tw; x++) {
      const ti = ((ic.y0 + y) * W + ic.x0 + x) * 4;
      if (!nonWhite(wd, ti)) continue;
      const si = ((py + y) * sw + px + x) * 4;
      const a = gray(wd, ti), b = gray(sd, si);
      num += a * b; a2 += a * a; b2 += b * b; n++;
    }
    return n < 30 ? -1 : num / (Math.sqrt(a2 * b2) || 1);
  };
  const clicks = [], scores = [];
  for (const ic of icons) {
    const tw = ic.x1 - ic.x0, th = ic.y1 - ic.y0;
    // visual center = centroid of non-white template pixels (asymmetric
    // icons like ☂️ have bbox center != clickable art center)
    let cx = 0, cy = 0, cn = 0;
    for (let y = 0; y < th; y++) for (let x = 0; x < tw; x++)
      if (nonWhite(wd, ((ic.y0 + y) * W + ic.x0 + x) * 4)) {
        cx += x; cy += y; cn++; }
    cx /= cn; cy /= cn;
    let best = -1, bx = 0, by = 0;
    for (let y = 0; y + th < sh; y += 2)
      for (let x = 0; x + tw < sw; x += 2) {
        const s = scoreAt(ic, tw, th, x, y);
        if (s > best) { best = s; bx = x; by = y; } }
    // fine pass: stride-1 rescan around the coarse peak
    for (let y = Math.max(0, by - 4); y + th < sh && y <= by + 4; y++)
      for (let x = Math.max(0, bx - 4); x + tw < sw && x <= bx + 4; x++) {
        const s = scoreAt(ic, tw, th, x, y);
        if (s > best) { best = s; bx = x; by = y; } }
    scores.push(+best.toFixed(3));
    if (best < 0.72) return { err: 'score', scores };
    clicks.push([sRect.left + bx + cx, sRect.top + by + cy]);
  }
  return { ok: clicks, scores };
}
"""


async def _solve_guard_captcha(page) -> bool:
    """Best-effort solver for /_guard/ click-in-order image captchas."""
    try:
        res = await page.evaluate(_GUARD_SOLVER_JS)
    except Exception:
        return False
    if not res or "ok" not in res:
        return False
    try:
        px = py = None
        for x, y in res["ok"]:
            if px is not None:  # human-ish cursor path between clicks
                steps = 6
                for i in range(1, steps):
                    await page.mouse.move(
                        px + (x - px) * i / steps,
                        py + (y - py) * i / steps,
                    )
                    await page.wait_for_timeout(30)
            await page.mouse.click(x, y)
            px, py = x, y
            await page.wait_for_timeout(350)
        # the gate reloads the page after the last click — poll until it
        # navigates away from the verification page
        await page.wait_for_timeout(1500)
        for _ in range(14):
            title = (await page.title() or "").lower()
            if not any(
                t in title for t in ("security verification", "安全验证")
            ):
                return True
            await page.wait_for_timeout(500)
        return False
    except Exception:
        return False


async def get_browser():
    global _pw, _browser
    async with _lock:
        if _browser is None or not _browser.is_connected():
            from playwright.async_api import async_playwright

            _pw = await async_playwright().start()
            _browser = await _pw.chromium.launch()
        return _browser


async def _safe_cancel(download):
    try:
        await download.cancel()
    except Exception:
        pass


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


CAPTURE_TIMEOUT = 150  # hard ceiling per target — redirect loops and
                       # unresponsive pages must not stall a scan forever


async def capture(url: str, shot_path: Path | None, js_globals: list,
                  dom_selectors: list, headers: dict | None = None,
                  proxy: str | None = None) -> dict:
    """Hard-bounded wrapper — individual awaits inside (content/evaluate/
    screenshot) have no playwright timeout and can hang indefinitely on
    redirect loops or wedged pages."""
    try:
        return await asyncio.wait_for(
            _capture_impl(url, shot_path, js_globals, dom_selectors,
                          headers, proxy),
            timeout=CAPTURE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return {"ok": False, "error": f"capture timeout {CAPTURE_TIMEOUT}s",
                "packets": [], "html": "", "script_src": [], "js": {},
                "dom": {}, "title": "", "favicon_hash": None,
                "challenge": False}


async def _capture_impl(url: str, shot_path: Path | None, js_globals: list,
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

        # landing pages that redirect into file downloads (APK/zip) would
        # make ctx.close() wait on the download — cancel them outright
        page.on("download",
                lambda d: asyncio.create_task(_safe_cancel(d)))

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
                # interactive captcha (/_guard/ click-in-order etc.) —
                # try solving it so signals/screenshot see the real page;
                # reload once for a fresh captcha if the first attempt fails
                for _attempt in range(2):
                    if await _solve_guard_captcha(page):
                        break
                    if _attempt == 0:
                        try:
                            await page.reload(
                                wait_until="domcontentloaded", timeout=30000
                            )
                        except Exception:
                            pass
                        await page.wait_for_timeout(8000)
                html = await page.content()
                out["challenge"] = any(
                    h in html.lower() for h in CHALLENGE_HINTS
                )
                if out["challenge"]:
                    try:
                        await page.wait_for_load_state(
                            "networkidle", timeout=8000
                        )
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
                    """(spec) => { const out = {};
                    const items = Array.isArray(spec)
                        ? spec.map(s => [s, {}]) : Object.entries(spec);
                    for (const it of items) {
                        const s = it[0], need = it[1] || {};
                        try { const el = document.querySelector(s);
                            if (!el) continue;
                            const attrs = {};
                            for (const a of (need.attrs || [])) {
                                const v = el.getAttribute(a);
                                if (v !== null) attrs[a] = v.slice(0, 200); }
                            const props = {};
                            for (const p of (need.props || [])) {
                                const v = el[p];
                                if (v !== undefined && v !== null)
                                    props[p] = String(v).slice(0, 200); }
                            out[s] = { exists: true,
                                text: (el.innerText || '').slice(0, 500),
                                attrs: attrs, props: props }; }
                        catch (e) {} }
                    return out; }""", dom_selectors)
            except Exception:
                pass

        if shot_path is not None:
            shot_path.parent.mkdir(parents=True, exist_ok=True)
            for _try in range(2):
                try:
                    await page.screenshot(path=str(shot_path))
                    # a solid-color page compresses to a few KB — give it one
                    # settle window (JS redirect / lazy render) and reshoot
                    if _try == 0 and shot_path.stat().st_size < 9_000:
                        await page.wait_for_timeout(3000)
                        continue
                    break
                except Exception:
                    break

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
                # context.close() can itself block on stuck pages —
                # bound it so cancellation actually completes
                await asyncio.wait_for(ctx.close(), 15)
            except Exception:
                pass
    return out
