import os, sys, json, re
os.environ["SCAN_DB_URL"] = "postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan"
sys.path.insert(0, "/opt/scan")
import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
MUA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
       "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
       "Mobile/15E148 Safari/604.1")

urls = [
    "http://b2.89435832.cc",
    "https://11.9985422.cn",
    "https://9986541.cn",
    "http://riwigra8.cardlist.youliyouhuo.com/?ek=ziVpkBV2f0_JbhD",
    "https://240mafy6099y.s3.ca-west-1.amazonaws.com/Dxxdd/avdboppy.html",
    "https://www.rmb469.com/video.html?typeId=29&typeMid=1",
    "https://v6d8.top",
    "https://qkc001.com",
    "https://liqiao.imbxnode.one",
    "https://xw5kw2g.top:4092",
    "https://www.hm2023t.vip:9527/?zme01J3GYbsmBeIC+L1va3ks4TG8T51JQ%3CQyBVJFx3NG5agxVbHvRe0reqrVBJVija9Km4xM0F1IAubHHX0VnogUXYr7NcOsiJ1LJcLlYboyZHTZP6hTYbeyDgaXt7y=MnuL",
    "https://3iin.5rl7pj.sbs",
    "https://c3.xmytwya1.shop/10-20/m8qz33.html?key=adnffnaqup",
    "https://albbd.z11.web.core.windows.net/?flowT=1793639533771&flowSign=e0aed8cbdf&flow=flow",
    "https://api.tyrbvfgd.site/api/config/clientConfig",
    "https://xndqiha.blob.core.windows.net/xnd/index.html",
    "https://9.2179xiu.cc",
    "https://wwapu.lanzouq.com",
    "https://qfile.qq.com/q/8G5Az3rl76",
    "https://sj1020a135.q2xv1b.top",
    "https://jifhsjgf.oo04.icu.cdn.cloudflare.net/nbcmjqtku/hjshf",
    "https://kcnampvj4ciw.feishu.link/app/app_17h2axnvpx3/call/e7b13b8fbc27902d55ad7bco",
    "https://abb99s.an98d.rkpsuq.cn/index.html?channelCode=E031",
    "https://jikj043.com:2619/11:54",
    "https://11p5hankandapian5688.cc",
]

def probe(url):
    out = {"url": url}
    try:
        with httpx.Client(follow_redirects=True, timeout=12, verify=False,
                          headers={"User-Agent": UA}) as c:
            r = c.get(url)
        out["status"] = r.status_code
        out["final"] = str(r.url)
        out["server"] = r.headers.get("server", "")
        out["powered"] = r.headers.get("x-powered-by", "")
        out["ct"] = r.headers.get("content-type", "")[:40]
        html = r.text
        out["hlen"] = len(html)
        t = re.search(r"<title[^>]*>([^<]{0,80})", html, re.I)
        out["title"] = (t.group(1).strip() if t else "")
        # identity hints
        hints = set()
        for pat, tag in [
            (r"__NUXT__", "nuxt"), (r"data-v-app|__VUE__", "vue"),
            (r"__NEXT_DATA__", "next"), (r"ng-version", "angular"),
            (r"/static/js/main\.[0-9a-f]+\.js", "cra/react"),
            (r"uni-app|__uniConfig|unipages", "uni-app"),
            (r"vant/nutui/uview", "mobileui"),
            (r"layui", "layui"), (r"element-ui|el-container", "element"),
            (r"ant-|antd", "antd"), (r"webpackJsonp|__webpack", "webpack"),
            (r"jquery[-.][\d.]+", "jquery"), (r"swiper", "swiper"),
            (r"clipboard\.js|\.apk\b", "apk-dl"),
            (r"hm\.baidu\.com", "baidu-stat"), (r"growingio", "gio"),
            (r"vconsole", "vconsole"), (r"amfe-flexible|flexible\.js", "flexible"),
            (r"chat|kefu|客服|im\.|websocket|webim", "im/chat"),
            (r"充值|提现|投注|开奖|彩票|棋牌|娱乐城|百家乐", "gambling-words"),
            (r"贷款|借款|额度|消费金融|分期", "loan-words"),
            (r"邀请码|推广|代理", "promo"),
        ]:
            if re.search(pat, html, re.I):
                hints.add(tag)
        out["hints"] = sorted(hints)
        out["scripts"] = [s for s in
                          re.findall(r'<script[^>]+src="([^"]+)"', html)][:6]
    except Exception as e:
        out["err"] = type(e).__name__ + ": " + str(e)[:60]
    return out

for u in urls:
    o = probe(u)
    if "err" in o:
        print(f"DEAD  {u[:65]:65} {o['err']}")
    else:
        print(f"{o['status']:4} {u[:62]:62} {o['server'][:20]:20} {o['powered'][:16]:16} h={o['hlen']:6} t={o['title'][:24]:24} {o['hints']}")
        if o.get("final") != u:
            print(f"      -> {o['final'][:90]}")
