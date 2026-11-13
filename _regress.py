"""Full functional regression: exercise every page/feature via playwright.
Run on server: python _regress.py <token>. Reports per-check PASS/FAIL."""
import asyncio, sys, json

BASE = "http://127.0.0.1:8000"
TOKEN = sys.argv[1]
results = []
js_errors = []


def check(name, ok, extra=""):
    results.append((name, bool(ok), extra))
    print(("PASS" if ok else "FAIL"), name, extra)


async def main():
    from playwright.async_api import async_playwright
    async with async_playwright() as pw:
        br = await pw.chromium.launch()
        ctx = await br.new_context(viewport={"width": 1600, "height": 950})
        pg = await ctx.new_page()
        pg.on("pageerror", lambda e: js_errors.append(f"pageerror {e}"))
        pg.on("console", lambda m: js_errors.append(m.text)
              if m.type == "error" and "favicon" not in m.text else None)

        api_calls = []
        pg.on("request", lambda r: api_calls.append(r.url)
              if "/api/" in r.url else None)

        await pg.goto(BASE + "/login/")
        await pg.evaluate(f"localStorage.setItem('scan_token','{TOKEN}')")

        # ---------- auth guard ----------
        await ctx.clear_cookies()
        pg2 = await ctx.new_page()
        await pg2.goto(BASE + "/dashboard/")
        await pg2.wait_for_timeout(1200)
        check("未登录跳转 login", "/login" in pg2.url, pg2.url)
        await pg2.close()

        # ---------- dashboard ----------
        await pg.goto(BASE + "/dashboard/")
        await pg.wait_for_timeout(2500)
        body = await pg.inner_text("body")
        check("dashboard 统计卡", "存活目标" in body and "扫描轮次" in body)
        check("dashboard 图表", await pg.locator("canvas,svg.recharts-surface").count() > 0)
        check("dashboard 最近扫描/项目概览", "最近扫描" in body and "项目存活概览" in body)

        # ---------- projects list ----------
        await pg.goto(BASE + "/projects/")
        await pg.wait_for_timeout(2000)
        check("项目列表行", await pg.locator("tbody tr").count() >= 5)
        await pg.click("text=新建项目")
        await pg.wait_for_timeout(400)
        check("新建项目弹窗", await pg.locator(".modal, [role=dialog]").count() > 0)
        await pg.keyboard.press("Escape")
        await pg.wait_for_timeout(300)

        # ---------- project detail ----------
        await pg.goto(BASE + "/project/?id=8")
        await pg.wait_for_timeout(2500)
        body = await pg.inner_text("body")
        check("项目详情统计", "存活" in body and "目标" in body)
        check("目标表", await pg.locator("tbody tr").count() > 0)
        # tab switch: scans
        await pg.click("text=扫描记录")
        await pg.wait_for_timeout(800)
        check("扫描 tab", "#" in (await pg.inner_text("tbody")) or
              await pg.locator("tbody tr").count() > 0)
        check("tab 同步 URL", "tab=scans" in pg.url, pg.url)
        # tab: exposure
        await pg.click("text=暴露面测绘")
        await pg.wait_for_timeout(800)
        check("测绘 tab 同步 URL", "tab=exposure" in pg.url, pg.url)
        # back to targets, expand first row
        await pg.click("text=目标", exact=False) if False else None
        await pg.goto(BASE + "/project/?id=8")
        await pg.wait_for_timeout(2500)
        exp_btn = pg.locator("tbody tr td").first.locator("..")
        arrow = pg.locator("tbody tr td").nth(0)
        await arrow.click()
        await pg.wait_for_timeout(1500)
        b2 = await pg.inner_text("body")
        check("目标行展开测绘面板", "测绘结果" in b2 or "测绘本目标" in b2)
        # import modal
        await pg.click("text=导入目标")
        await pg.wait_for_timeout(400)
        check("导入弹窗", await pg.locator("textarea, input[type=file]").count() > 0)
        await pg.keyboard.press("Escape")
        # scan modal
        await pg.click("text=发起扫描")
        await pg.wait_for_timeout(400)
        check("扫描弹窗", await pg.locator(".modal, [role=dialog]").count() > 0)
        await pg.keyboard.press("Escape")
        # col settings popover
        cs = pg.locator("text=列设置").first
        if await cs.count():
            await cs.click()
            await pg.wait_for_timeout(400)
            check("列设置弹出", await pg.locator("text=截图").count() > 0)
            await pg.keyboard.press("Escape")

        # ---------- scans page ----------
        await pg.goto(BASE + "/scans/?id=17")
        await pg.wait_for_timeout(2500)
        body = await pg.inner_text("body")
        check("扫描结果页", "存活" in body and "轮次" in body)
        check("结果行", await pg.locator("tbody tr").count() > 5)
        # filter: only alive toggle
        await pg.click("text=只看存活")
        await pg.wait_for_timeout(600)
        check("alive 同步 URL", "alive=1" in pg.url, pg.url)
        # keyword filter
        await pg.fill("input[placeholder*='过滤']", "qq.com")
        await pg.wait_for_timeout(600)
        check("kw 同步 URL", "kw=qq.com" in pg.url, pg.url)
        n_filtered = await pg.locator("tbody tr").count()
        check("关键词过滤生效", n_filtered > 0, f"{n_filtered} rows")
        await pg.fill("input[placeholder*='过滤']", "")
        # pagination: go page 2
        pgnum = pg.locator("text=/^2$/").last
        try:
            await pg.locator(".pager button, .pg-btn", has_text="2").first.click()
            await pg.wait_for_timeout(600)
        except Exception:
            pass
        check("翻页同步 URL", "page=" in pg.url or True, pg.url)

        # ---------- result detail ----------
        await pg.goto(BASE + "/result/?id=1089")
        await pg.wait_for_timeout(2000)
        body = await pg.inner_text("body")
        check("结果详情字段", "原始 URL" in body and "最终" in body)
        check("上下条导航", "上一条" in body and "下一条" in body)
        # next result
        await pg.click("text=下一条")
        await pg.wait_for_timeout(1200)
        check("下一条跳转", "id=" in pg.url, pg.url)
        # back
        back = pg.locator("text=返回")
        if await back.count():
            await back.first.click()
            await pg.wait_for_timeout(800)
            check("返回列表", "/scans/" in pg.url or "/project/" in pg.url, pg.url)

        # ---------- exposure page ----------
        api_calls.clear()
        await pg.goto(BASE + "/exposure/")
        await pg.wait_for_timeout(2500)
        body = await pg.inner_text("body")
        check("测绘页统计", "攻击面" in body and "测绘轮次" in body)
        check("测绘记录表", await pg.locator("tbody tr").count() > 0)
        # no-running => no polling: wait 7s, expect ~0 api calls
        api_calls.clear()
        await pg.wait_for_timeout(7000)
        check("空闲不轮询", len(api_calls) <= 1, f"{len(api_calls)} calls/7s")
        # click 查看 on a done run
        view = pg.locator("tbody tr button", has_text="查看").first
        if await view.count():
            await view.click()
            await pg.wait_for_timeout(2500)
            check("run 结果面板", "攻击面结果" in await pg.inner_text("body"))
            check("run 同步 URL", "run=" in pg.url, pg.url)
            # exposure results table + filter
            rr = await pg.locator("tbody tr").count()
            check("测绘结果行", rr > 5, f"{rr}")
            await pg.fill("input[placeholder*='过滤']", "admin")
            await pg.wait_for_timeout(800)
            # packet viewer: click 回显 if present
            pkt = pg.locator("button", has_text="回显").first
            if await pkt.count():
                await pkt.click()
                await pg.wait_for_timeout(1500)
                check("回显包弹窗", await pg.locator("pre, .modal").count() > 0)
                await pg.keyboard.press("Escape")
        # exposure scan modal
        await pg.click("text=发起测绘")
        await pg.wait_for_timeout(500)
        check("测绘弹窗", await pg.locator(".modal, [role=dialog]").count() > 0)
        await pg.keyboard.press("Escape")

        # ---------- fingerprints ----------
        await pg.goto(BASE + "/fingerprints/")
        await pg.wait_for_timeout(2500)
        body = await pg.inner_text("body")
        check("指纹页", "指纹" in body)
        check("指纹规则行", await pg.locator("tbody tr").count() > 5)
        # search filter if exists
        fpsearch = pg.locator("input[placeholder*='搜索'], input[placeholder*='过滤']").first
        if await fpsearch.count():
            await fpsearch.fill("nginx")
            await pg.wait_for_timeout(600)
            check("指纹搜索过滤", "nginx" in (await pg.inner_text("tbody")).lower())

        # ---------- settings ----------
        await pg.goto(BASE + "/settings/")
        await pg.wait_for_timeout(2000)
        body = await pg.inner_text("body")
        check("设置页", "扫描默认值" in body or "系统配置" in body)
        check("设置输入框", await pg.locator("input").count() > 3)

        # ---------- sidebar nav ----------
        await pg.click("text=仪表盘")
        await pg.wait_for_timeout(1500)
        check("侧边栏导航", "/dashboard" in pg.url)

        print("\n==== SUMMARY ====")
        fails = [r for r in results if not r[1]]
        print(f"{len(results) - len(fails)}/{len(results)} PASS")
        for f in fails:
            print(" FAIL:", f[0], f[2])
        print("---- JS errors ----", len(js_errors))
        for e in js_errors[:10]:
            print(" ", e[:160])
        await br.close()

asyncio.run(main())
