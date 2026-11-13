"""Re-verify failed checks with correct selectors (round 2)."""
import asyncio, sys

BASE = "http://127.0.0.1:8000"
TOKEN = sys.argv[1]
results = []
js_errors = []

def check(name, ok, extra=""):
    results.append((name, bool(ok), extra))
    print(("PASS" if ok else "FAIL"), name, extra)

MODAL = "div.fixed.inset-0"

async def main():
    from playwright.async_api import async_playwright
    async with async_playwright() as pw:
        br = await pw.chromium.launch()
        ctx = await br.new_context(viewport={"width": 1600, "height": 950})
        pg = await ctx.new_page()
        pg.on("pageerror", lambda e: js_errors.append(str(e)))
        pg.on("console", lambda m: js_errors.append(m.text)
              if m.type == "error" and "favicon" not in m.text else None)
        await pg.goto(BASE + "/login/")
        await pg.evaluate(f"localStorage.setItem('scan_token','{TOKEN}')")

        await pg.goto(BASE + "/project/?id=8")
        await pg.wait_for_timeout(2500)

        # tabs are in div.border-b; toolbar buttons are NOT inside .border-b
        tabs = "main div.border-b button"
        await pg.locator(tabs, has_text="暴露面").first.click()
        await pg.wait_for_timeout(900)
        check("测绘 tab 同步 URL", "tab=exposure" in pg.url, pg.url)
        await pg.locator(tabs, has_text="目标").first.click()
        await pg.wait_for_timeout(900)
        check("目标 tab 回来", "tab=" not in pg.url or "tab=targets" in pg.url, pg.url)

        # scan modal open + Escape closes
        await pg.locator("main").get_by_text("发起扫描").first.click()
        await pg.wait_for_timeout(500)
        check("扫描弹窗", await pg.locator(MODAL).count() > 0)
        await pg.keyboard.press("Escape")
        await pg.wait_for_timeout(400)
        check("Esc 关闭弹窗", await pg.locator(MODAL).count() == 0)

        # exposure modal open + X closes
        await pg.locator("main").get_by_text("暴露面测绘", exact=True).first.click()
        await pg.wait_for_timeout(500)
        check("测绘弹窗", await pg.locator(MODAL).count() > 0)
        await pg.locator(f"{MODAL} button").first.click()
        await pg.wait_for_timeout(400)
        check("X 关闭弹窗", await pg.locator(MODAL).count() == 0)

        # overlay click closes
        await pg.locator("main").get_by_text("导入目标").first.click()
        await pg.wait_for_timeout(500)
        check("导入弹窗", await pg.locator(MODAL).count() > 0)
        await pg.mouse.click(30, 400)
        await pg.wait_for_timeout(400)
        check("遮罩点击关闭", await pg.locator(MODAL).count() == 0)

        # exposure page: run row stage/done + diff modal + export popover
        await pg.goto(BASE + "/exposure/")
        await pg.wait_for_timeout(2500)
        body = await pg.inner_text("body")
        check("测绘轮状态列含进度或完成", "done" in body or "/" in body)
        diff_btn = pg.locator("tbody button", has_text="对比").first
        if await diff_btn.count():
            await diff_btn.click()
            await pg.wait_for_timeout(1200)
            check("对比弹窗", await pg.locator(MODAL).count() > 0)
            await pg.keyboard.press("Escape")
        exp_btn = pg.locator("tbody button", has_text="导出").first
        if await exp_btn.count():
            await exp_btn.click()
            await pg.wait_for_timeout(500)
            check("导出选项", "CSV" in await pg.inner_text("body"))
            await pg.keyboard.press("Escape")

        # fingerprints: learn panel + rule edit
        await pg.goto(BASE + "/fingerprints/")
        await pg.wait_for_timeout(2500)
        learn = pg.locator("text=指纹学习").first
        if await learn.count():
            await learn.click()
            await pg.wait_for_timeout(600)
            check("指纹学习面板展开", await pg.locator("input[placeholder*='http']").count() > 0)

        # project targets: row ops — 编辑 modal
        await pg.goto(BASE + "/project/?id=8")
        await pg.wait_for_timeout(2500)
        edit = pg.locator("tbody button", has_text="编辑").first
        if await edit.count():
            await edit.click()
            await pg.wait_for_timeout(500)
            check("目标编辑弹窗", await pg.locator(MODAL).count() > 0)
            await pg.keyboard.press("Escape")

        print("\n==== SUMMARY ====")
        fails = [r for r in results if not r[1]]
        print(f"{len(results)-len(fails)}/{len(results)} PASS")
        for f in fails: print(" FAIL:", f[0], f[2])
        print("JS errors:", len(js_errors))
        for e in js_errors[:8]: print(" ", e[:160])
        await br.close()

asyncio.run(main())
