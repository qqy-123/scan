"""Exposure scanning (资产测绘/暴露面): for alive targets,
  - js scan   : pull every same-host JS and extract embedded endpoints
                (hidden APIs, backend URLs, admin paths)
  - dirsearch : dictionary brute-force for admin/backup/api/config paths
                with soft-404 baseline to suppress noise.
"""

import asyncio
import hashlib
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import fingerprint as fp
from . import probe, store, traffic

DICT_PATH = Path(__file__).resolve().parent.parent / "rules" / "dirs.txt"
MAX_JS_FILES = 25
MAX_JS_SIZE = 400_000
MAX_DIR_HITS = 300
MAX_LEAK_HITS = 120

# quoted URL-ish strings inside JS bundles
JS_URL_RE = re.compile(
    r"""["'`]((?:https?:)?//[a-zA-Z0-9_\-.]+(?::\d+)?(?:/[a-zA-Z0-9_\-./?&=%~#]*)?|/[a-zA-Z0-9_\-/?&=%~#.]+)['"`]"""
)
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
TITLE_RE = probe.TITLE_RE

HINTS = {
    "admin": ("admin", "manage", "houtai", "manager", "console", "backend",
              "system", "login", "signin", "dashboard"),
    "api": ("api", "ajax", "json", "graphql", "rest", "rpc", "v1", "v2", "v3"),
    "upload": ("upload", "uploader", "file", "attach", "download", "import",
               "export"),
    "auth": ("auth", "oauth", "sso", "token", "session", "cas", "jwt",
             "password", "passwd", "secret", "credential"),
    "config": ("config", "setting", "env", "conf", "yml", "yaml", "properties"),
    "debug": ("actuator", "debug", "metrics", "health", "status", "info",
              "monitor", "trace", "druid"),
}
# extensions/prefixes that are almost never interesting endpoints
ASSET_EXT = re.compile(
    r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|mp3|map)$", re.I
)

# ------------------------------------------------------------------
# Attack-surface classification (absorbed from Rotor Goddess analysis)
# ------------------------------------------------------------------

# query-param name -> likely vuln point. Order matters: first hit wins.
PARAM_POINTS = [
    ("point:cmd", re.compile(
        r"(?i)(?:^|[?&])(cmd|exec|command|execute|ping|run|daemon|shell|"
        r"process|module|payload|do|func|arg|cli)\s*=")),
    ("point:file", re.compile(
        r"(?i)(?:^|[?&])(file|filename|filepath|path|download|readfile|openfile|"
        r"fread|include|require|src|doc|document|attach|template|view|dir|"
        r"folder|basepath|rootpath|localpath|_FilePath|menu|topic)\s*=")),
    ("point:ssrf", re.compile(
        r"(?i)(?:^|[?&])(url|uri|dest|target|domain|host|port|site|ip|server|"
        r"fetch|fetchurl|weburl|apiurl|geturl|linkurl|srcurl|request|load|"
        r"open|refer|ref|sudaref|out)\s*=")),
    ("point:redirect", re.compile(
        r"(?i)(?:^|[?&])(redirect|redirect_?to|redirect_?url|redirectUrl|jump|"
        r"jump_?to|goto|gotoUrl|returnUrl|backUrl|forward|forwardurl|"
        r"return_?uri|service|next|to|fromUrl|redUrl|oauth_callback|"
        r"urlredirect|redirecturl|returnurl|view)\s*=")),
    ("point:jsonp", re.compile(
        r"(?i)(?:^|[?&])(?:_?callback|_cb|_call|_?jsonp_?|jsonp_\w+)\s*=")),
    ("point:sqli", re.compile(
        r"(?i)(?:^|[?&])(search|keyword|key|searchkey|query|wd|word|input|"
        r"content|title|name|username|nickname|subject|desc|info|order|"
        r"sort|keywords|searchtext|searchword|id|cid|cat|typeid|s|q)\s*=")),
    ("point:dos", re.compile(
        r"(?i)(?:^|[?&])(limit|offset|pagesize|pageindex|pagenum|max|maxsize|"
        r"minsize|quantity|amount|count|num|start|end|size|length|wide|"
        r"width|height|batch|loop|range|total|step|interval|volume)\s*=")),
    ("point:upload", re.compile(
        r"(?i)(?:upload|uploader|upfile|file_upload|uploadfile|multipart|"
        r"uploadimg|upload_image|upload_video|uploadify|webupload|importfile|"
        r"exportfile|fileapi|uploadapi)(?:/|$|\?)")),
]

# content signatures -> secrets / sensitive data leaks
SECRET_RES = [
    ("leak:privkey", re.compile(
        r"-+BEGIN [^\s]+ PRIVATE KEY-+")),
    ("leak:aws_key", re.compile(
        r"(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    ("leak:github_token", re.compile(
        r"(?:ghp|ghu|gho|ghs|ghr)_[A-Za-z0-9]{36,}")),
    ("leak:sonar_token", re.compile(
        r"sonar[._-]?[a-z]{0,10}[\"'`]?[0-9a-f]{40}", re.I)),
    ("leak:jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}[A-Za-z0-9._-]{10,}")),
    ("leak:shiro", re.compile(r"rememberMe\s*=\s*deleteMe|rememberMe=[^&\s]{8,}", re.I)),
    ("leak:oss", re.compile(
        r"[\w.-]+\.oss\.aliyuncs\.com|[\w.-]+\.s3\.amazonaws\.com|"
        r"s3://[\w.-]+|oss://[\w.-]+", re.I)),
    ("leak:cloud_secret", re.compile(
        r"(?i)((?:access|secret|app|api|aws|aliyun|tencent|hw|obs)[-_]{0,5}"
        r"(?:key|token|secret|secretkey))\s*[:=]\s*[\"']?([A-Za-z0-9/+_=-]{16,})")),
    ("leak:credentials", re.compile(
        r"(?i)(password|passwd|pwd|secret|mima)\s*[:=]\s*[\"']([^\"'\s&,;]{6,})")),
    ("leak:idcard", re.compile(
        r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
        r"\d{3}[\dXx]\b")),
    ("leak:phone", re.compile(
        r"(?i)(?:phone|mobile|tel|手机|电话|联系方式)[^\d\n]{0,30}"
        r"1(?:3\d|4[5-79]|5[0-35-9]|6[5-7]|7[0-8]|8\d|9[189])\d{8}")),
    ("leak:internal_ip", re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}"
        r"\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("leak:jdbc", re.compile(
        r"jdbc:(?:mysql|oracle|postgresql|sqlserver|dm|kingbase)://[^\s\"'<)]+", re.I)),
    ("leak:map_apikey", re.compile(
        r"(?i)(?:maps\.googleapis\.com|restapi\.amap\.com|api\.map\.baidu\.com|"
        r"api\.mapbox\.com|apis\.map\.qq\.com|webapi\.amap\.com)"
        r"[^\s\"'<]{0,120}?(?:key|ak|access_token)=[A-Za-z0-9_-]{10,}")),
    ("leak:webhook", re.compile(
        r"https?://[^\s\"'`]*(?:webhook|hooks\.slack\.com|oapi\.dingtalk\.com|"
        r"qyapi\.weixin\.qq\.com|open\.feishu\.cn|webhook\.office\.com|"
        r"discord\.com/api/webhooks)[^\s\"'`]*", re.I)),
]

# SQL error signatures across engines (absorbed & kept multi-DB)
SQL_ERROR_RE = re.compile(
    r"(?i)(?:执行当前 Web 请求期间，出现未经处理的异常|Unclosed quotation mark|"
    r"ODBC Driver|System\.Data\.SqlClient|SqlException|"
    r"You have an error in your SQL syntax|MySQL server version|"
    r"Unknown column|Unknown table|Warning: mysql|mysqli_query|"
    r"MySQL server error|ORA-\d{1,5}|PLS-\d+|Oracle error|"
    r"ERROR:\s*syntax error at or near|PostgreSQL query|Jet SQL|\.mdb|\.accdb|"
    r"OLE DB|Syntax error.*SQL|Invalid column name|Table.*doesn.t exist|"
    r"Database error|SQLSTATE\[|MariaDB server version|SQL syntax.*near|"
    r"PDOException|SQL error|Driver.*SQL|Microsoft SQL Server|JDBC SQL|"
    r"SQLite error|no such table|"
    r"Check the manual that corresponds to your MySQL|MySQL syntax error|"
    r"PostgreSQL ERROR|SQLServer error|DB2 SQL|Sybase|Informix|"
    r"Column count doesn.t match|MySQL Error|SQL error code|Unknown database|"
    r"Access denied for user|Incorrect syntax near)")

# form-level vuln-point signatures on page bodies
LOGIN_FORM_RE = re.compile(
    r"(?is)<form[^>]*>(?:(?!</form>).)*?type=[\"']?text[\"'\s>][^>]*>.*?"
    r"type=[\"']?password[\"'\s>][^>]*>.*?</form")
UPLOAD_FORM_RE = re.compile(
    r"(?is)<form[^>]*enctype=[\"']?multipart/form-data[^>]*>"
    r"(?:(?!</form>).)*?type=[\"']?file[\"'\s>][^>]*>.*?</form")
PHONE_INPUT_RE = re.compile(
    r"<input[^>]*(?:=[^\"']*手机号[\"']|maxlength=[\"']11[\"'])[^>]*>", re.I)
ADMIN_TITLE_RE = re.compile(
    r"(?i)<title>.*?(后台|管理|admin|manage|console|dashboard).*?</title>")

# js sourcemap probe
SOURCEMAP_RE = re.compile(r'"sources"\s*:\s*\[')


def _classify_params(query: str) -> str | None:
    """First matching vuln-point class for a URL query string."""
    if not query:
        return None
    for hint, rx in PARAM_POINTS:
        if rx.search(query):
            return hint
    return None


def _mask(s: str, keep: int = 6) -> str:
    """Mask a leaked credential for display."""
    s = s.strip()
    if len(s) <= keep * 2:
        return s[:2] + "****"
    return s[:keep] + "****" + s[-4:]


def _scan_sensitive(body: str, url: str, source: str, out: list):
    """Append leak/vuln findings discovered in a response body."""
    for hint, rx in SECRET_RES:
        m = rx.search(body)
        if m:
            frag = m.group(0)
            out.append({
                "kind": "leak",
                "url": url,
                "source": source,
                "status_code": None,
                "title": _mask(frag[:120]),
                "length": None,
                "hint": hint,
            })
    m = SQL_ERROR_RE.search(body)
    if m:
        out.append({
            "kind": "vuln",
            "url": url,
            "source": source,
            "status_code": None,
            "title": "SQL报错: " + re.sub(r"\s+", " ", m.group(0))[:100],
            "length": None,
            "hint": "vuln:sqli",
        })


async def _page_signature(client, base_url: str) -> tuple:
    """(final_url, title, length, body_hash) of the site's homepage — used to
    tell a genuinely new page (attack surface) from a catch-all that just
    echoes the homepage."""
    try:
        r = await client.get(base_url)
    except httpx.HTTPError:
        return ("", "", 0, "")
    body = r.text[:300_000]
    title = ""
    if "html" in r.headers.get("content-type", ""):
        m = TITLE_RE.search(body)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    body_hash = hashlib.sha1(
        re.sub(r"\s+", "", body[:8000]).encode("utf-8", "ignore")
    ).hexdigest()
    return (str(r.url), title, len(r.content), body_hash)


def _same_as_home(sig: tuple, final_url: str, title: str, body_len: int,
                  body_hash: str) -> bool:
    """True when the discovered page is effectively the homepage again —
    redirect back to /, identical leading content, or same title with a
    near-identical length (catch-all templates)."""
    hfu, htitle, hlen, hhash = sig
    if not hfu:
        return False
    if final_url and final_url.rstrip("/") == hfu.rstrip("/"):
        return True
    if hhash and body_hash and body_hash == hhash:
        return True
    if htitle and title and title == htitle and \
            abs(body_len - hlen) <= max(120, hlen * 0.06):
        return True
    return False


def _detect_forms(body: str, url: str, source: str, out: list):
    """Login / upload / phone-login / admin-page form findings."""
    checks = [
        (UPLOAD_FORM_RE, "point:upload", "存在文件上传表单"),
        (LOGIN_FORM_RE, "point:login", "存在登录表单"),
        (PHONE_INPUT_RE, "point:login", "存在手机号登录输入框"),
        (ADMIN_TITLE_RE, "point:admin", "后台标题页"),
    ]
    for rx, hint, desc in checks:
        if rx.search(body):
            out.append({
                "kind": "point",
                "url": url,
                "source": source,
                "status_code": None,
                "title": desc,
                "length": None,
                "hint": hint,
            })


def _hint(path: str) -> str:
    p = path.lower()
    for name, kws in HINTS.items():
        if any(k in p for k in kws):
            return name
    return "other"


def _dict_words() -> list:
    if not hasattr(_dict_words, "_cache"):
        _dict_words._cache = list(dict.fromkeys(
            w.strip()
            for w in DICT_PATH.read_text(encoding="utf-8").splitlines()
            if w.strip() and not w.startswith("#")
        ))
    return _dict_words._cache


def _interesting_js_path(u: str) -> bool:
    p = urlsplit(u if "://" in u else f"http://x{u if u.startswith('/') else '/' + u}")
    path = p.path or ""
    segs = [s for s in path.split("/") if s]
    if not path or path == "/":
        return False
    if ASSET_EXT.search(path):
        return _hint(path) != "other"  # assets only if path hints admin/api
    # keep: >=2 segments, or 1 segment that hints, or has file extension (page)
    if len(segs) >= 2:
        return True
    return _hint(path) != "other" or "." in segs[-1]


async def js_scan(base_url: str, client: httpx.AsyncClient, dict_urls: list = None) -> list:
    """Extract endpoints embedded in the site's JS files. Also scans the
    homepage + JS bodies for secrets, SQL errors and form-level vuln points,
    and probes `<js>.map` sourcemaps."""
    try:
        resp = await client.get(base_url)
        html = resp.text[:500_000]
    except httpx.HTTPError:
        return []
    srcs = []
    for s in SCRIPT_SRC_RE.findall(html):
        u = urljoin(base_url, s)
        if urlsplit(u).hostname == urlsplit(base_url).hostname:
            srcs.append(u)
    for u in dict_urls or []:
        if urlsplit(u).hostname == urlsplit(base_url).hostname and u not in srcs:
            srcs.append(u)
    srcs = srcs[:MAX_JS_FILES]

    found = {}  # path-or-url -> source js
    extra = []  # leak/vuln/point findings
    base = urlsplit(base_url)

    # homepage itself: secrets, SQL errors, forms
    _scan_sensitive(html, base_url, base_url, extra)
    _detect_forms(html, base_url, base_url, extra)

    async def pull(js_url: str):
        try:
            r = await client.get(js_url)
            if r.status_code >= 400:
                return
            body = r.text[:MAX_JS_SIZE]
        except httpx.HTTPError:
            return
        _scan_sensitive(body, js_url, base_url, extra)
        for m in JS_URL_RE.findall(body):
            u = m.strip()
            if len(u) < 2 or u.startswith(("data:", "javascript:", "#")):
                continue
            if u.startswith("//"):
                u = base.scheme + ":" + u
            full = urljoin(base_url, u)
            if not _interesting_js_path(full):
                continue
            key = full.lower()
            found.setdefault(key, (full, js_url))

    async def probe_map(js_url: str):
        """<file>.js.map -> sourcemap often exposes original source paths."""
        try:
            r = await client.get(js_url + ".map")
            if r.status_code == 200 and SOURCEMAP_RE.search(r.text[:50_000]):
                extra.append({
                    "kind": "leak", "url": js_url + ".map", "source": js_url,
                    "status_code": 200, "title": "JS sourcemap 泄露(可还原源码)",
                    "length": len(r.content), "hint": "leak:sourcemap",
                })
        except httpx.HTTPError:
            pass

    await asyncio.gather(*(
        [pull(u) for u in srcs] + [probe_map(u) for u in srcs]
    ))

    out = []
    for u, src in found.values():
        same = urlsplit(u).hostname == base.hostname
        sp = urlsplit(u)
        hint = _classify_params(sp.query) or _hint(sp.path)
        out.append(
            {
                "kind": "js",
                "url": u,
                "source": src,
                "status_code": None,
                "title": None,
                "length": None,
                "hint": hint + ("" if same else ":external"),
                "surface": 0,   # js 提取的端点默认只是信息
            }
        )
    # dedupe leak findings on (hint, url)
    seen = set()
    for e in extra:
        k = (e["hint"], e["url"], e["title"])
        if k in seen or len(out) >= MAX_DIR_HITS * 2 + MAX_LEAK_HITS:
            continue
        seen.add(k)
        out.append(e)
    out.sort(key=lambda x: (
        0 if x["kind"] in ("leak", "vuln", "point") else 1,
        x["hint"].endswith("external"), x["hint"], x["url"],
    ))
    return out


async def _probe_path(client, url, baseline, home_sig):
    """One dict word. Returns a list of result dicts (empty on soft-404).

    Only 2xx/3xx/401/403 count as exposure — 429/406/5xx are rate-limit /
    WAF noise, not findings. `surface` marks whether the hit is a genuinely
    distinct page (attack surface) vs a catch-all echoing the homepage.
    Hit bodies are also scanned for SQL errors, secrets and form points."""
    try:
        r = await client.get(url)
    except httpx.HTTPError:
        return []
    status = r.status_code
    if not (200 <= status < 400 or status in (401, 403)):
        return []
    body = r.text[:300_000]
    body_len = len(r.content)
    title = ""
    if "html" in r.headers.get("content-type", ""):
        m = TITLE_RE.search(body)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    # soft-404 suppression: same status & similar length & same title as baseline
    for b_status, b_len, b_title in baseline:
        if status == b_status and title == b_title and \
                (b_len == 0 or abs(body_len - b_len) <= max(40, b_len * 0.1)):
            return []
    body_hash = hashlib.sha1(
        re.sub(r"\s+", "", body[:8000]).encode("utf-8", "ignore")
    ).hexdigest()
    surface = 0 if _same_as_home(home_sig, str(r.url), title, body_len, body_hash) else 1
    results = [{
        "kind": "dir",
        "url": url,
        "source": None,
        "status_code": status,
        "title": title or None,
        "length": body_len,
        "hint": _classify_params(urlsplit(url).query) or _hint(urlsplit(url).path),
        "surface": surface,
    }]
    _scan_sensitive(body, url, url, results)
    if status < 400 and "html" in r.headers.get("content-type", ""):
        _detect_forms(body, url, url, results)
    return results


async def dir_scan(base_url: str, client: httpx.AsyncClient, concurrency: int = 40) -> list:
    """dirsearch-style dictionary scan with soft-404 baseline."""
    p = urlsplit(base_url)
    base = f"{p.scheme}://{p.netloc}"

    # two random baselines to catch wildcard/soft-404 signatures
    baseline = []
    for i in range(2):
        rnd = f"{base}/scanx-{uuid.uuid4().hex[:12]}"
        try:
            r = await client.get(rnd)
            title = ""
            if "html" in r.headers.get("content-type", ""):
                m = TITLE_RE.search(r.text[:300_000])
                title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
            baseline.append((r.status_code, len(r.content), title))
        except httpx.HTTPError:
            baseline.append((0, 0, ""))

    home_sig = await _page_signature(client, base)
    sem = asyncio.Semaphore(concurrency)
    hits = []

    async def one(word):
        if len(hits) >= MAX_DIR_HITS + MAX_LEAK_HITS:
            return
        async with sem:
            rs = await _probe_path(client, f"{base}/{word.lstrip('/')}",
                                   baseline, home_sig)
            hits.extend(rs)

    await asyncio.gather(*(one(w) for w in _dict_words()))
    hits.sort(key=lambda x: (
        0 if x["kind"] in ("leak", "vuln", "point") else 1,
        -(x.get("surface") or 0), x.get("status_code") or 0, x["url"]))
    return hits


async def run_exposure(run_id: int):
    """Run js/dir exposure scan over a project's alive targets."""
    run = store.get_exposure_run(run_id)
    opts = json.loads(run["options"])
    project_id = run["project_id"]
    kinds = opts.get("kinds") or ["js", "dir"]
    cfg = store.get_settings()

    targets = store.alive_targets(project_id) if opts.get("scope", "alive") == "alive" \
        else store.list_targets(project_id)

    client = probe.make_client()
    dir_sem = asyncio.Semaphore(4)  # dir scans in parallel across targets
    target_sem = asyncio.Semaphore(max(1, min(6, cfg["browser_concurrency"])))

    async def per_target(t):
        url = t["url"] if "://" in t["url"] else "https://" + t["url"]
        results = []
        try:
            if "js" in kinds:
                results += await js_scan(url, client)
            if "dir" in kinds:
                async with dir_sem:
                    results += await dir_scan(
                        url, client, concurrency=max(10, cfg["concurrency"] // 2)
                    )
        finally:
            for r in results:
                store.save_exposure_result(run_id, t["id"], r)
            store.bump_exposure_done(run_id)

    try:
        await asyncio.gather(*(per_target(t) for t in targets))
        store.finish_exposure(run_id)
    except Exception:
        store.fail_exposure(run_id)
        raise
    finally:
        await client.aclose()
    # 自动深扫: 验证攻击面(与首页不同的真实页面)并截图+指纹
    if opts.get("auto_deep"):
        try:
            await run_deep_scan(run_id, int(opts.get("deep_limit") or 120))
        except Exception:
            pass


# ------------------------------------------------------------------
# Deep scan: fingerprint + screenshot every discovered in-scope URL
# ------------------------------------------------------------------

# selection priority for deep scan — attack points and leaks first
DEEP_PRIORITY = {"vuln": 0, "point": 1, "leak": 2, "dir": 3, "js": 4}


async def run_deep_scan(run_id: int, limit: int = 120):
    """Re-probe every discovered same-host URL: liveness + fingerprint +
    screenshot, exactly like the main fingerprint pipeline."""
    run = store.get_exposure_run(run_id)
    if not run:
        return
    project_id = run["project_id"]
    cfg = store.get_settings()
    targets = {t["id"]: t for t in store.list_targets(project_id)}
    rows = store.list_exposure_results(run_id)

    def host_of(t):
        u = t["url"] if "://" in t["url"] else "https://" + t["url"]
        return urlsplit(u).hostname

    # dedupe urls, keep best (lowest) priority kind; same-host scope only.
    # sort: known surfaces first, then vuln/point/leak/dir/js.
    urls = {}
    for r in rows:
        u = r.get("url") or ""
        t = targets.get(r.get("target_id"))
        if not u.startswith("http") or not t:
            continue
        if urlsplit(u).hostname != host_of(t):
            continue  # external hosts stay out of authorized scope
        pri = DEEP_PRIORITY.get(r.get("kind") or "js", 9)
        surf = 0 if r.get("surface") else 1   # surfaces sort first
        prev = urls.get(u)
        if prev is None or (surf, pri) < (prev[0], prev[1]):
            urls[u] = (surf, pri, r["target_id"])
    ordered = sorted(urls.items(), key=lambda kv: (kv[1][0], kv[1][1], kv[0]))[:limit]

    store.exposure_deep_start(run_id, len(ordered))

    client = probe.make_client()
    probe_sem = asyncio.Semaphore(max(5, cfg["concurrency"] // 3))
    shot_sem = asyncio.Semaphore(max(1, cfg["browser_concurrency"]))

    # homepage signature per target host — a surface must differ from it
    home_sigs = {}
    for t in targets.values():
        u = t["url"] if "://" in t["url"] else "https://" + t["url"]
        base = f"{urlsplit(u).scheme}://{urlsplit(u).netloc}"
        home_sigs[urlsplit(u).hostname] = await _page_signature(client, base)

    async def one(url, tid):
        try:
            async with probe_sem:
                resp = await probe.fetch(client, url)
            fields = {
                "status_code": resp["status_code"],
                "alive": 1 if resp["alive"] else 0,
                "surface": 0,
                "final_url": resp["final_url"],
                "server": resp["server"],
                "fingerprints": None,
                "screenshot": None,
                "protection": None,
            }
            if resp["alive"]:
                # attack surface = a page genuinely different from homepage
                host = urlsplit(url).hostname
                body = (resp.get("html") or "")[:300_000]
                body_hash = hashlib.sha1(
                    re.sub(r"\s+", "", body[:8000]).encode("utf-8", "ignore")
                ).hexdigest()
                same = _same_as_home(
                    home_sigs.get(host, ("", "", 0, "")),
                    resp["final_url"], resp["title"] or "",
                    len(resp.get("html") or ""), body_hash,
                )
                if not same:
                    fields["surface"] = 1
                    signals = None
                    shot_name = f"exp{run_id}_{uuid.uuid4().hex[:8]}.png"
                    if cfg["screenshot"]:
                        async with shot_sem:
                            cap = await traffic.capture(
                                resp["final_url"], traffic.SHOT_DIR / shot_name,
                                fp.js_globals(), fp.dom_selectors(),
                            )
                        if cap["ok"]:
                            fields["screenshot"] = shot_name
                            signals = fp.signals_from_capture(cap, resp)
                    if signals is None:
                        favicon_hash = await probe.fetch_favicon_hash(
                            client, resp["final_url"])
                        signals = fp.signals_from_response(resp, favicon_hash)
                    matched = fp.match(signals)
                    hits = list(matched["hits"])
                    if cfg["active_probe"]:
                        base = resp["final_url"]
                        for rule in matched["candidates"]:
                            for path in rule["probe"]:
                                try:
                                    r = await client.get(
                                        base.rstrip("/") + "/" + path.lstrip("/"))
                                    if r.status_code >= 400:
                                        continue
                                    h = fp.evaluate_probe(rule, r.text[:300_000])
                                except Exception:
                                    h = None
                                if h:
                                    hits.append(h)
                                    break
                    fps = fp.postprocess(hits)
                    fields["fingerprints"] = json.dumps(fps, ensure_ascii=False)
                    prot = [h["name"] for h in fps if h["category"] == "防护页"]
                    fields["protection"] = ",".join(prot) if prot else None
            store.update_exposure_deep_result(run_id, url, fields)
        except Exception:
            pass
        finally:
            store.bump_exposure_deep(run_id)

    try:
        await asyncio.gather(*(one(u, t) for u, (_s, _p, t) in ordered))
        store.finish_exposure_deep(run_id)
    except Exception:
        store.fail_exposure_deep(run_id)
        raise
    finally:
        await client.aclose()
