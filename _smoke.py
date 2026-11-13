"""Smoke-test the new Next.js frontend: login + visit every page, collect JS errors."""
import asyncio, sys, json
from playwright.async_api import async_playwright

BASE = "http://127.0.0.1:8000"
PW = sys.argv[1] if len(sys.argv) > 1 else "scan123"

PAGES = [
    "/dashboard/", "/projects/", "/exposure/", "/fingerprints/", "/settings/",
    "/project/?id=1", "/scans/?id=17", "/result/?id=1089", "/exposure/?run=11",
]

async def main():
    errors = []
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1500, "height": 900})
        pg.on("pageerror", lambda e: errors.append(f"PAGEERROR {pg.url}: {e}"))
        pg.on("console", lambda m: errors.append(f"CONSOLE {pg.url}: {m.text[:200]}")
              if m.type == "error" and "401" not in m.text else None)
        # login via injected token (valid HMAC generated server-side)
        await pg.goto(BASE + "/login/")
        await pg.evaluate(f"localStorage.setItem('scan_token', '{PW}')")
        await pg.goto(BASE + "/dashboard/")
        await pg.wait_for_timeout(1500)
        print("after login url:", pg.url)
        for path in PAGES:
            await pg.goto(BASE + path)
            await pg.wait_for_timeout(3000)
            title = await pg.evaluate("document.body.innerText.slice(0,120)")
            print(f"\n=== {path} ===")
            print(title.replace("\n", " | ")[:160])
            # count rows in tables as sanity signal
            n = await pg.evaluate("document.querySelectorAll('table.dt tbody tr').length")
            print("table rows:", n)
        await pg.screenshot(path="/tmp/nx_dash.png", full_page=False)
        await b.close()
    print("\n---- JS errors ----")
    for e in errors[:30]:
        print(e)
    print(f"total {len(errors)}")

asyncio.run(main())
