import asyncio
from pathlib import Path

from .probe import UA

SHOT_DIR = Path(__file__).resolve().parent.parent / "screenshots"
VIEWPORT = {"width": 1366, "height": 900}

_pw = None
_browser = None
_lock = asyncio.Lock()


async def get_browser():
    global _pw, _browser
    async with _lock:
        if _browser is None or not _browser.is_connected():
            from playwright.async_api import async_playwright

            _pw = await async_playwright().start()
            _browser = await _pw.chromium.launch()
        return _browser


async def capture(url: str, path: Path, js_globals: list, dom_selectors: list) -> dict:
    """Screenshot a live URL and collect rendered signals (js globals, dom,
    rendered html + script srcs) for second-pass fingerprinting."""
    rendered = {"js": {}, "dom": {}, "html": "", "script_src": []}
    try:
        browser = await get_browser()
        ctx = await browser.new_context(
            ignore_https_errors=True, viewport=VIEWPORT, user_agent=UA
        )
        page = await ctx.new_page()
        try:
            try:
                await page.goto(url, wait_until="networkidle", timeout=25000)
            except Exception:
                try:
                    await page.goto(url, wait_until="load", timeout=15000)
                except Exception:
                    pass
            await page.wait_for_timeout(1200)

            rendered["html"] = await page.content()
            rendered["script_src"] = await page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)"
            )

            for g in js_globals:
                try:
                    val = await page.evaluate(
                        f"() => {{ try {{ return String({g}); }} catch(e) {{ return null; }} }}"
                    )
                    if val is not None:
                        rendered["js"][g] = str(val)[:300]
                except Exception:
                    pass

            for sel in dom_selectors:
                try:
                    el = await page.query_selector(sel)
                    if el:
                        text = await el.inner_text()
                        rendered["dom"][sel] = {
                            "exists": True,
                            "text": (text or "")[:500],
                            "attrs": {},
                        }
                except Exception:
                    pass

            path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(path))
        finally:
            await ctx.close()
    except Exception as e:
        rendered["error"] = f"{type(e).__name__}: {e}"
    return rendered
