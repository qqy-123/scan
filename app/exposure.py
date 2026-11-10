"""Exposure scanning (资产测绘/暴露面): for alive targets,
  - js scan   : pull every same-host JS and extract embedded endpoints
                (hidden APIs, backend URLs, admin paths)
  - dirsearch : dictionary brute-force for admin/backup/api/config paths
                with soft-404 baseline to suppress noise.
"""

import asyncio
import base64
import hashlib
import json
import random
import re
import socket
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import bypass
from . import fingerprint as fp
from . import probe, store, traffic

DICT_PATH = Path(__file__).resolve().parent.parent / "rules" / "dirs.txt"
SUB_DICT_PATH = Path(__file__).resolve().parent.parent / "rules" / "subdomains.txt"
MAX_JS_FILES = 40
MAX_JS_SIZE = 400_000        # bodies scanned for secrets/errors (regex-heavy)
MAX_JS_ENDPOINT = 2_500_000  # bodies scanned for endpoint strings (cheap)
MAX_DIR_HITS = 300
MAX_LEAK_HITS = 120
MAX_SUB_CT = 1500       # CT names probed per root domain (crt.name can
                        # return tens of thousands — we random-sample)
MAX_SUB_DEAD = 300      # unresolved subdomains kept as info
MAX_NET_HITS = 300

# quoted URL-ish strings inside JS bundles
JS_URL_RE = re.compile(
    r"""["'`]((?:https?:)?//[a-zA-Z0-9_\-.]+(?::\d+)?(?:/[a-zA-Z0-9_\-./?&=%~#]*)?|/[a-zA-Z0-9_\-/?&=%~#.]+)['"`]"""
)
# relative endpoint paths: "user/info", 'index.php/login', `api/v2/x`
JS_REL_RE = re.compile(
    r"""["'`]([a-zA-Z0-9_\-]{2,40}(?:/[a-zA-Z0-9_\-.?=&%~]{1,60}){1,5})['"`]"""
)
# url-ish property values: url:"x", href:"x", action:"x", api:"x"
JS_PROP_RE = re.compile(
    r"(?:url|href|action|endpoint|target|ajax|api|src|path|uri)"
    r"\s*[:=]\s*[\"'`]([^\"'`]{2,200})[\"'`]",
    re.I,
)
# nested js references: 'user.min.js?t=1', "modules/x.js"
JS_FILE_RE = re.compile(r"""["'`]([\w\-./]{2,100}?\.js(?:\?[\w=&.\-]*)?)['"`]""")
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
INLINE_JS_RE = re.compile(r"<script[^>]*>([\s\S]*?)</script>", re.I)
TITLE_RE = probe.TITLE_RE
MIME_SKIP = ("text/", "image/", "audio/", "video/", "application/",
             "font/", "multipart/", "message/")
JUNK_HOSTS = ("w3.org", "schemas.", "purl.org", "example.", "localhost",
              "127.0.0.1", "0.0.0.0", "github.com", "gitee.com")

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
# a served page containing a password input / login wording = entry point
LOGIN_PAGE_RE = re.compile(
    r"type=[\"']?password[\"'\s>]|用户登录|登录|登陆|"
    r"sign[\s_-]?in|log[\s_-]?in", re.I)

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
    segs = {s for s in re.split(r"[/_.\-?=&%]+", p) if s}
    for name, kws in HINTS.items():
        for kw in kws:
            if len(kw) <= 3:
                if kw in segs:      # short hints need an exact segment
                    return name     #   ('v2.0' dir ≠ api/v2)
            elif kw in p:
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


# ------------------------------------------------------------------
# Domain expansion: subdomain enum/brute, host collision, net engines
# ------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# compound public suffixes — keep root-domain extraction sane for .com.cn etc.
COMPOUND_TLDS = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "com.hk", "com.tw", "com.mo", "co.jp", "or.jp", "ne.jp",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.kr", "or.kr",
    "co.in", "com.sg", "com.my", "com.br", "com.tr", "com.mx",
    "com.sa", "com.ph", "com.vn", "com.co", "com.ar", "com.pe",
}


def _is_ip(host: str) -> bool:
    return bool(host) and (bool(_IP_RE.match(host)) or ":" in host)


def _root_domain(host: str) -> str:
    """example.com / sub.example.com -> example.com; handles com.cn etc."""
    if not host or _is_ip(host):
        return host or ""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    last2 = ".".join(parts[-2:])
    if last2 in COMPOUND_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


async def _resolve(host: str) -> list:
    """All A/AAAA records for host, [] on failure. 4s cap."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.run_in_executor(
                None, socket.getaddrinfo, host, None, socket.AF_UNSPEC,
                socket.SOCK_STREAM),
            timeout=4,
        )
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


async def _probe_host(client, url: str, timeout: float = 8):
    """Light liveness probe: (status, title, final_url, len, body_hash)."""
    try:
        r = await client.get(url, timeout=timeout)
    except httpx.HTTPError:
        return None
    body = r.text[:200_000]
    title = ""
    if "html" in r.headers.get("content-type", ""):
        m = TITLE_RE.search(body)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    body_hash = hashlib.sha1(
        re.sub(r"\s+", "", body[:8000]).encode("utf-8", "ignore")
    ).hexdigest()
    return (r.status_code, title, str(r.url), len(r.content), body_hash)


def _extract_subs(text: str, root: str) -> set:
    """Hostnames under <root> embedded in a page/JS body."""
    if not root or not text:
        return set()
    rx = re.compile(
        r"((?:[a-zA-Z0-9_-]{1,63}\.)+" + re.escape(root) + r")\b")
    return {m.group(1).lower() for m in rx.finditer(text)}


async def subdomain_scan(base_url: str, client: httpx.AsyncClient,
                         concurrency: int = 40) -> list:
    """Subdomain discovery via crt.sh certificate-transparency logs, plus
    names embedded in the homepage body. Names that resolve get an HTTP
    probe -> surface; unresolved names are kept as info."""
    host = urlsplit(base_url).hostname
    root = _root_domain(host)
    if not root or _is_ip(root):
        return []
    names = {}          # name -> source label
    # crt.name — large CT index, free, one subdomain per line
    for attempt in range(2):
        try:
            r = await client.get("https://crt.name/v1/search",
                                 params={"apex": root}, timeout=30)
            if r.status_code == 200:
                for n in r.text.splitlines():
                    n = n.strip().lower().lstrip("*.")
                    if n != root and n.endswith("." + root):
                        names.setdefault(n, "crt.name")
                break
        except Exception:
            pass
        if attempt == 0:
            await asyncio.sleep(2)
    # crt.sh — second CT source (flaky, one retry)
    for attempt in range(2):
        try:
            r = await client.get(f"https://crt.sh/?q=%25.{root}&output=json",
                                 timeout=30)
            if r.status_code == 200:
                for ent in r.json():
                    for n in str(ent.get("name_value", "")).splitlines():
                        n = n.strip().lower().lstrip("*.")
                        if n != root and n.endswith("." + root):
                            names.setdefault(n, "crt.sh")
                break
        except Exception:
            pass
        if attempt == 0:
            await asyncio.sleep(2)
    # subdomains referenced by the page itself
    try:
        home = await client.get(base_url, timeout=10)
        for n in _extract_subs(home.text[:300_000], root):
            if n != root:
                names.setdefault(n, "page")
    except Exception:
        pass
    all_names = sorted(names)
    if len(all_names) > MAX_SUB_CT:
        # random sample — alphabetical slicing would bias toward 'a*' names
        all_names = sorted(random.sample(all_names, MAX_SUB_CT))
    if not all_names:
        return []

    # home signature — a live subdomain that just mirrors the homepage is
    # info, not a new attack surface
    sig = await _page_signature(client, base_url)
    sem = asyncio.Semaphore(concurrency)
    out = []
    dead = 0

    async def one(name: str):
        nonlocal dead
        src = names.get(name, "crt")
        async with sem:
            ips = await _resolve(name)
            if not ips:
                if dead < MAX_SUB_DEAD:
                    dead += 1
                    out.append({
                        "kind": "sub", "url": f"https://{name}", "source": src,
                        "status_code": None, "title": None, "length": None,
                        "hint": "sub:ct", "surface": 0,
                    })
                return
            for scheme in ("https", "http"):
                hit = await _probe_host(client, f"{scheme}://{name}")
                if hit:
                    status, title, fu, ln, bh = hit
                    same = _same_as_home(sig, fu, title, ln, bh)
                    fhost = urlsplit(fu).hostname if fu else ""
                    note = (f" → {fu}" if fhost and fhost != name
                            else "")   # redirect target kept as a note —
                                      # url stays the in-scope subdomain
                    out.append({
                        "kind": "sub", "url": f"{scheme}://{name}",
                        "source": src, "status_code": status,
                        "title": (title or f"解析 {ips[0]}") + note,
                        "length": ln,
                        "hint": "sub:echo" if same else "sub:alive",
                        "surface": 0 if same else 1, "server": None,
                    })
                    return
            out.append({
                "kind": "sub", "url": f"https://{name}", "source": src,
                "status_code": None, "title": f"解析 {ips[0]}", "length": None,
                "hint": "sub:dns", "surface": 0,
            })

    await asyncio.gather(*(one(n) for n in all_names))
    return out


async def subdomain_brute(base_url: str, client: httpx.AsyncClient,
                          concurrency: int = 60) -> list:
    """Dictionary DNS brute-force: <word>.<root> -> resolve -> HTTP probe."""
    host = urlsplit(base_url).hostname
    root = _root_domain(host)
    if not root or _is_ip(root) or not SUB_DICT_PATH.exists():
        return []
    words = [w.strip() for w in SUB_DICT_PATH.read_text(
        encoding="utf-8").splitlines() if w.strip() and not w.startswith("#")]
    sig = await _page_signature(client, base_url)
    sem = asyncio.Semaphore(concurrency)
    out = []

    async def one(word: str):
        fqdn = f"{word}.{root}"
        async with sem:
            ips = await _resolve(fqdn)
            if not ips:
                return
            for scheme in ("https", "http"):
                hit = await _probe_host(client, f"{scheme}://{fqdn}")
                if hit:
                    status, title, fu, ln, bh = hit
                    same = _same_as_home(sig, fu, title, ln, bh)
                    fhost = urlsplit(fu).hostname if fu else ""
                    note = f" → {fu}" if fhost and fhost != fqdn else ""
                    out.append({
                        "kind": "sub", "url": f"{scheme}://{fqdn}",
                        "source": "brute", "status_code": status,
                        "title": (title or f"解析 {ips[0]}") + note,
                        "length": ln,
                        "hint": "sub:echo" if same else "sub:alive",
                        "surface": 0 if same else 1, "server": None,
                    })
                    return
            out.append({
                "kind": "sub", "url": f"https://{fqdn}", "source": "brute",
                "status_code": None, "title": f"解析 {ips[0]}", "length": None,
                "hint": "sub:dns", "surface": 0,
            })

    await asyncio.gather(*(one(w) for w in words))
    return out


async def host_collision(target_url: str, client: httpx.AsyncClient,
                         candidates: list, concurrency: int = 30) -> list:
    """Host-header collision: connect to the target's IP with SNI+Host set
    to each candidate fqdn — a response differing from the bare-IP default
    vhost reveals a hidden virtual host. sni_fetch is required: httpx sends
    Host but keeps SNI=IP, which misses every SNI-routed vhost."""
    host = urlsplit(target_url).hostname
    if _is_ip(host):
        ip = host
    else:
        ips = await _resolve(host)
        ip = ips[0] if ips else None
    if not ip:
        return []
    scheme = urlsplit(target_url).scheme
    base_r = await probe.sni_fetch(ip, ip, scheme)
    if not base_r:  # IP's default vhost doesn't answer — nothing to compare
        return []
    sem = asyncio.Semaphore(concurrency)
    out = []

    async def one(fqdn: str):
        async with sem:
            r = await probe.sni_fetch(ip, fqdn, scheme)
            if not r or r["status"] >= 400:
                return
            same = _same_as_home(
                ("x", base_r["title"], base_r["length"], base_r["body_hash"]),
                "", r["title"], r["length"], r["body_hash"])
            if same:
                return
            out.append({
                "kind": "host", "url": f"{scheme}://{fqdn}",
                "source": f"host:{ip}", "status_code": r["status"],
                "title": r["title"], "length": r["length"],
                "hint": "host:vhost", "surface": 1,
            })

    await asyncio.gather(*(one(c) for c in candidates))
    return out


MAX_ORIGIN_CANDS = 320   # candidate IPs probed per domain (incl. /24 fill)


async def origin_scan(base_url: str, client: httpx.AsyncClient,
                      ip_pool: list, concurrency: int = 40) -> list:
    """fuckcdn-style origin discovery: probe every candidate IP with
    SNI+Host=<host> — a response matching the live homepage signature
    exposes the real origin hiding behind the CDN."""
    host = urlsplit(base_url).hostname
    if not host or _is_ip(host):
        return []
    sig = await _page_signature(client, base_url)  # homepage via CDN
    if not sig[0]:
        return []
    own = set(await _resolve(host))
    direct, seen = [], set()
    for ip in ip_pool:
        if _is_ip(ip) and ":" not in ip and ip not in own and ip not in seen:
            seen.add(ip)
            direct.append(ip)
    # classic fuckcdn move: sweep the /24 around each discovered infra IP
    cands = list(direct)
    seen24 = set()
    for ip in direct:
        prefix = ip.rsplit(".", 1)[0]
        if prefix in seen24:
            continue
        seen24.add(prefix)
        for i in range(1, 255):
            c = f"{prefix}.{i}"
            if c not in seen:
                seen.add(c)
                cands.append(c)
    cands = cands[:MAX_ORIGIN_CANDS]
    sem = asyncio.Semaphore(concurrency)
    out = []

    async def one(ip: str):
        async with sem:
            for scheme in ("https", "http"):
                r = await probe.sni_fetch(ip, host, scheme)
                if not r or r["status"] >= 400:
                    continue
                if not _same_as_home(sig, "", r["title"], r["length"],
                                     r["body_hash"]):
                    continue
                out.append({
                    "kind": "cdn", "url": f"{scheme}://{ip}",
                    "source": "fuckcdn", "status_code": r["status"],
                    "title": f"{host} 源站 · {r['title']}",
                    "length": r["length"], "hint": "origin", "surface": 1,
                })
                return

    await asyncio.gather(*(one(ip) for ip in cands))
    return out


# ---------------- wayback / takeover / port scan ----------------

async def wayback_scan(base_url: str, client: httpx.AsyncClient,
                       limit: int = 3000) -> list:
    """Historical URLs from web.archive.org CDX — dead-but-alive endpoints,
    legacy admin panels, old parameterized paths that JS extraction
    can't reach because they're no longer linked."""
    host = urlsplit(base_url).hostname
    root = _root_domain(host)
    if not root or _is_ip(root):
        return []
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params=[("url", root), ("matchType", "domain"),
                    ("output", "json"), ("fl", "original"),
                    ("collapse", "urlkey"), ("limit", str(limit)),
                    ("filter", "statuscode:200")],
            timeout=60)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    seen, out = set(), []
    for row in data[1:] if data and data[0] == ["original"] else data:
        u = row[0] if isinstance(row, list) else row
        if not isinstance(u, str) or not u.startswith("http"):
            continue
        h = urlsplit(u).hostname or ""
        if h != host and not h.endswith("." + root):
            continue
        if not _interesting_js_path(u) or u in seen:
            continue
        seen.add(u)
        sp = urlsplit(u)
        out.append({
            "kind": "url", "url": u, "source": "wayback",
            "status_code": None, "title": None, "length": None,
            "hint": _classify_params(sp.query) or _hint(sp.path),
            "surface": 0,
        })
    return out


TAKEOVER_HOSTS = (
    "github.io", "herokuapp.com", "herokussl.com", "s3.amazonaws.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "cloudapp.net",
    "azure-api.net", "trafficmanager.net", "blob.core.windows.net",
    "elasticbeanstalk.com", "wpengine.com", "zendesk.com", "freshdesk.com",
    "ghost.io", "myshopify.com", "pantheon.io", "webflow.io", "uservoice.com",
    "unbouncepages.com", "tilda.ws", "readme.io", "surge.sh", "bitbucket.io",
    "netlify.app", "fly.dev", "squarespace.com", "weebly.com",
    "strikingly.com", "helpscoutdocs.com", "intercom.io", "launchrock.com",
    "createsend.com", "getresponse.com", "acquia-sites.com",
    "hatenablog.com", "thinkific.com", "vercel.app", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "edgeapp.net",
    "azureedge.net", "ngrok.io", "kinsta.cloud",
)


async def _cname(name: str, client: httpx.AsyncClient) -> str:
    """CNAME target via DNS-over-HTTPS (works behind proxies, no dnspython)."""
    try:
        r = await client.get("https://dns.google/resolve",
                             params={"name": name, "type": "CNAME"},
                             timeout=8)
        for a in (r.json().get("Answer") or []):
            if a.get("type") == 5:
                return str(a["data"]).rstrip(".")
    except Exception:
        pass
    return ""


async def takeover_scan(names_status: dict, client: httpx.AsyncClient,
                        concurrency: int = 60) -> list:
    """Dangling-CNAME detection: a subdomain whose CNAME points at a
    claimable third-party service but doesn't serve a live site can be
    taken over by registering that service."""
    sem = asyncio.Semaphore(concurrency)
    out = []

    async def one(name: str, status):
        async with sem:
            c = await _cname(name, client)
            if not c:
                return
            if not any(c == p or c.endswith("." + p)
                       for p in TAKEOVER_HOSTS):
                return
            if status is not None and status < 400:
                return  # serves a live page — service is claimed
            out.append({
                "kind": "sub", "url": f"https://{name}",
                "source": "takeover", "status_code": status,
                "title": f"CNAME悬空→{c}（可接管）", "length": None,
                "hint": "takeover", "surface": 0,
            })

    await asyncio.gather(*(one(n, s) for n, s in names_status.items()))
    return out


TOP_PORTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 110: "pop3",
    143: "imap", 445: "smb", 465: "smtps", 587: "smtp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2375: "docker",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8000: "http", 8080: "http", 8443: "https",
    8888: "http", 9000: "http", 9200: "es", 11211: "memcached",
    27017: "mongo", 80: "http", 443: "https",
}
CRIT_PORTS = {6379, 9200, 27017, 2375, 11211}
MAX_PORT_HOSTS = 80


async def _port_probe(ip: str, host: str, port: int) -> dict | None:
    """Connect → grab banner; a few unauthenticated-service checks."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), 3)
    except Exception:
        return None
    try:
        if TOP_PORTS[port].startswith("http") or port in (9200,):
            writer.write(
                f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: {probe.UA}\r\nConnection: close\r\n\r\n"
                .encode())
        elif port == 6379:
            writer.write(b"INFO server\r\n")
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(4096), 4)
    except Exception:
        banner = b""
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return {"banner": banner.decode("utf-8", "ignore")}


async def port_scan(hosts: list, concurrency: int = 150) -> list:
    """TCP-connect TOP ports per discovered host; classify banners and
    flag unauthenticated services (Redis/ES/Mongo/Docker/Memcached)."""
    resolved = await asyncio.gather(*(_resolve(h) for h in hosts))
    todo = [(h, ips[0]) for h, ips in zip(hosts, resolved) if ips]
    sem = asyncio.Semaphore(concurrency)
    out = []

    async def one(h: str, ip: str, port: int):
        async with sem:
            r = await _port_probe(ip, h, port)
            if r is None:
                return
            svc = TOP_PORTS[port]
            text = r["banner"]
            hint, title, status = "port:open", f"{svc} open", None
            if port == 6379 and "redis_version" in text:
                hint, title = "port:critical", "Redis 未授权访问"
            elif port == 9200 and "cluster_name" in text:
                hint, title = "port:critical", "Elasticsearch 未授权"
            elif port == 2375 and '"Version"' in text:
                hint, title = "port:critical", "Docker API 未授权暴露"
            elif port == 27017 and ("ismaster" in text.lower()
                                    or "isWritablePrimary" in text):
                hint, title = "port:critical", "MongoDB 未授权"
            elif port == 11211 and "STAT " in text:
                hint, title = "port:critical", "Memcached 未授权"
            if text.startswith("HTTP/"):
                m = re.match(r"HTTP/\S+ (\d+)", text)
                status = int(m.group(1)) if m else None
                proto = "https" if port in (443, 8443) else "http"
                hint = "port:http"
                mt = TITLE_RE.search(text)
                title = re.sub(r"\s+", " ", mt.group(1)).strip() \
                    if mt else f"{proto}:{port}"
                url = f"{proto}://{h}:{port}/"
            else:
                first = text.strip().splitlines()
                if first:
                    title = f"{svc}: {first[0][:60]}"
                elif port in CRIT_PORTS:
                    title = f"{svc} open（TCP连通，应用层无响应）"
                url = f"{h}:{port}"
            out.append({
                "kind": "port", "url": url, "source": f"port:{ip}",
                "status_code": status, "title": title, "length": None,
                "hint": hint, "surface": 1 if status else 0,
            })

    await asyncio.gather(*(
        one(h, ip, p) for h, ip in todo for p in TOP_PORTS))
    return out


async def net_search(base_url: str, client: httpx.AsyncClient,
                     cfg: dict) -> list:
    """Optional cyberspace engines: FOFA / Hunter / Quake (need API keys
    from system settings). Returns asset rows as info — deep scan promotes
    live, distinct pages to surface."""
    host = urlsplit(base_url).hostname
    root = _root_domain(host)
    if not root or _is_ip(root):
        return []
    out = []

    # ---- FOFA ----
    if cfg.get("fofa_key") and cfg.get("fofa_email"):
        try:
            q = base64.b64encode(f'domain="{root}"'.encode()).decode()
            r = await client.get(
                "https://fofa.info/api/v1/search/all",
                params={
                    "email": cfg["fofa_email"], "key": cfg["fofa_key"],
                    "qbase64": q, "size": 100,
                    "fields": "host,title,ip,port,server,protocol",
                }, timeout=20)
            d = r.json()
            if not d.get("error"):
                for row in d.get("results", [])[:MAX_NET_HITS]:
                    h, t, ip, port, srv, proto = (list(row) + [""] * 6)[:6]
                    out.append({
                        "kind": "net", "url": h or f"{proto}://{ip}:{port}",
                        "source": f"fofa:{ip}:{port}", "status_code": None,
                        "title": t or srv, "length": None,
                        "hint": "net:fofa", "surface": 0,
                    })
        except Exception:
            pass

    # ---- Hunter (鹰图) ----
    if cfg.get("hunter_key"):
        try:
            q = base64.urlsafe_b64encode(f'domain="{root}"'.encode()).decode()
            r = await client.get(
                "https://hunter.qianxin.com/openApi/search",
                params={"api-key": cfg["hunter_key"], "search": q,
                        "page": 1, "page_size": 100, "is_web": 3},
                timeout=20)
            d = r.json()
            for it in (d.get("data") or {}).get("arr", [])[:MAX_NET_HITS]:
                url = it.get("url") or it.get("domain") or ""
                out.append({
                    "kind": "net",
                    "url": url if "://" in url else f"https://{url}",
                    "source": f"hunter:{it.get('ip','')}:{it.get('port','')}",
                    "status_code": it.get("status_code"),
                    "title": it.get("web_title") or it.get("component"),
                    "length": None, "hint": "net:hunter", "surface": 0,
                })
        except Exception:
            pass

    # ---- Quake (360) ----
    if cfg.get("quake_key"):
        try:
            r = await client.post(
                "https://quake.360.net/api/v3/search/quake",
                headers={"X-QuakeToken": cfg["quake_key"]},
                json={"query": f'domain:"{root}"', "start": 0, "size": 100,
                      "latest": True},
                timeout=20)
            for it in (r.json().get("data") or [])[:MAX_NET_HITS]:
                http = it.get("http") or {}
                h = http.get("host") or it.get("ip") or ""
                out.append({
                    "kind": "net",
                    "url": h if "://" in str(h) else f"https://{h}",
                    "source": f"quake:{it.get('ip','')}:{it.get('port','')}",
                    "status_code": http.get("status_code"),
                    "title": http.get("title"), "length": None,
                    "hint": "net:quake", "surface": 0,
                })
        except Exception:
            pass

    # dedupe by url
    seen, dedup = set(), []
    for r in out:
        if r["url"] not in seen:
            seen.add(r["url"])
            dedup.append(r)
    return dedup


STRONG_HINT = ("admin", "manage", "console", "backend", "backstage",
               "login", "signin", "api", "config", "upload", "download",
               "debug", "actuator", "env", "token", "secret")
WEB_FILE_EXT = {"php", "jsp", "asp", "aspx", "do", "action", "cgi",
                "json", "html", "htm", "xml", "jspx", "shtml", "fcgi"}
# strings that are formats/module-ids, not endpoints
NOT_ENDPOINT = re.compile(
    r"^(?:y+|m+|d+|h+|s+|[\w.]*(?:vue|react|jquery|angular|lodash|moment|"
    r"dayjs|axios|webpack|babel|core-js|es-module-shims|regenerator)[\w.]*|"
    r"modules?|vendor|chunk|runtime|manifest|polyfill|sw|worker)",
    re.I,
)
BAD_CHARS = re.compile(r"[^a-zA-Z0-9._~:/?&=%#\-@!$,*]")
STATIC_DIR = re.compile(
    r"^/?(?:static|assets?|public|dist|build|images?|img|css|fonts?|media|"
    r"node_modules|vendor|libs?|plugins?|styles?|pics?|uploads?/)(?:/|$)",
    re.I,
)


def _interesting_js_path(u: str) -> bool:
    p = urlsplit(u if "://" in u else f"http://x{u if u.startswith('/') else '/' + u}")
    path = p.path or ""
    segs = [s for s in path.split("/") if s]
    if not path or path == "/":
        return False
    pl = path.lower()
    if any(j in pl for j in JUNK_HOSTS):
        return False
    if STATIC_DIR.match(pl):
        # asset roots only yield endpoints when the leaf is a web file
        # or the path itself screams admin/api
        ext = segs[-1].rsplit(".", 1)[-1] if "." in segs[-1] else ""
        return ext in WEB_FILE_EXT or any(k in pl for k in STRONG_HINT)
    if ASSET_EXT.search(path):
        # static assets only when the path itself screams admin/api —
        # a 'v2' version dir on a .png is not an endpoint
        return any(k in pl for k in STRONG_HINT)
    if len(segs) >= 2:
        return True
    return _hint(path) != "other" or "." in segs[-1]


async def js_scan(base_url: str, client: httpx.AsyncClient, dict_urls: list = None) -> list:
    """Extract endpoints embedded in the site's JS files. Covers:
      - <script src> on same host or sibling subdomains of the root
      - inline <script> bodies (config blobs, JSON endpoints)
      - one level of nested .js references (module loaders: seajs map,
        webpack chunks — where the real API calls live)
    Also scans bodies for secrets, SQL errors, form points, sourcemaps."""
    try:
        resp = await client.get(base_url)
        html = resp.text[:500_000]
    except httpx.HTTPError:
        return []
    base = urlsplit(base_url)
    root = _root_domain(base.hostname)

    def allowed_host(h: str) -> bool:
        return bool(h) and (h == base.hostname or
                            (root and h.endswith("." + root)))

    srcs = []
    for s in SCRIPT_SRC_RE.findall(html):
        u = urljoin(base_url, s)
        if allowed_host(urlsplit(u).hostname) and u not in srcs:
            srcs.append(u)
    for u in dict_urls or []:
        if allowed_host(urlsplit(u).hostname) and u not in srcs:
            srcs.append(u)
    srcs = srcs[:MAX_JS_FILES]

    found = {}  # path-or-url -> source js
    extra = []  # leak/vuln/point findings

    # homepage itself: secrets, SQL errors, forms
    _scan_sensitive(html, base_url, base_url, extra)
    _detect_forms(html, base_url, base_url, extra)

    def harvest(body: str, js_url: str) -> list:
        """Collect endpoint strings + nested .js refs from a JS body."""
        _scan_sensitive(body[:MAX_JS_SIZE], js_url, base_url, extra)
        for rx in (JS_URL_RE, JS_REL_RE, JS_PROP_RE):
            for m in rx.findall(body):
                u = m.strip()
                if len(u) < 3 or u.startswith(
                        ("data:", "javascript:", "#")):
                    continue
                if u.lower().startswith(MIME_SKIP):
                    continue      # text/javascript, image/png — not endpoints
                if BAD_CHARS.search(u):      # '+' concat, parens, CJK…
                    continue
                if any(j in u for j in JUNK_HOSTS):
                    continue
                seg0 = u.split("/")[0].split("?")[0].lower()
                if NOT_ENDPOINT.search(seg0):
                    continue                  # module ids, date formats
                if u.startswith("//"):
                    u = base.scheme + ":" + u
                full = urljoin(base_url, u)
                p = urlsplit(full).path
                if "/" not in u.split("://")[-1] and \
                        "." in p and \
                        p.rsplit(".", 1)[-1].lower() not in WEB_FILE_EXT:
                    continue      # 'user.figureurl_2' — property, not file
                if not _interesting_js_path(full):
                    continue
                found.setdefault(full.lower(), (full, js_url))
        nested = []
        for m in JS_FILE_RE.findall(body):
            u = urljoin(js_url, m.strip())
            if allowed_host(urlsplit(u).hostname) and u not in srcs:
                nested.append(u)
        return nested

    async def pull(js_url: str, retry_modules: bool = True) -> list:
        try:
            r = await client.get(js_url)
            if r.status_code == 404 and retry_modules:
                # seajs-style: real file often lives under <dir>/modules/
                p = urlsplit(js_url)
                alt = p._replace(
                    path=p.path.rsplit("/", 1)[0] + "/modules/" +
                    p.path.rsplit("/", 1)[-1])
                return await pull(alt.geturl(), False)
            if r.status_code >= 400:
                return []
            return harvest(r.text[:MAX_JS_ENDPOINT], js_url)
        except httpx.HTTPError:
            return []

    # inline <script> bodies count as zero-cost js files
    for body in INLINE_JS_RE.findall(html)[:10]:
        harvest(body[:MAX_JS_SIZE], base_url)

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

    nested_lists = await asyncio.gather(*(
        [pull(u) for u in srcs] + [probe_map(u) for u in srcs]
    ))
    # second-level: module-loader bundles (seajs map, webpack chunks)
    level2 = []
    for nested in nested_lists:
        if isinstance(nested, list):
            for u in nested:
                if u not in level2:
                    level2.append(u)
    level2 = level2[:MAX_JS_FILES]
    if level2:
        srcs += level2
        await asyncio.gather(*(pull(u) for u in level2))

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
    hint = _classify_params(urlsplit(url).query) or _hint(urlsplit(url).path)
    if hint == "other" and LOGIN_PAGE_RE.search(body):
        hint = "entry"
    results = [{
        "kind": "dir",
        "url": url,
        "source": None,
        "status_code": status,
        "title": title or None,
        "length": body_len,
        "hint": hint,
        "surface": surface,
    }]
    _scan_sensitive(body, url, url, results)
    if status < 400 and "html" in r.headers.get("content-type", ""):
        _detect_forms(body, url, url, results)
    return results


def _dirish(url: str, status: int) -> bool:
    """A directory (route prefix), not a file: extensionless last path
    segment with a served response — eligible for deeper dict recursion."""
    seg = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
    return bool(seg) and "." not in seg and \
        status in (200, 301, 302, 307, 401, 403)


# extended coverage caps: sub-domain roots and entry-prefix dir scans
DIR_SUB_MAX = 8       # alive subdomains dir-scanned per root
DIR_ENTRY_MAX = 5     # entry-point prefixes dir-scanned per target
SUB_DICT_TOP = 400    # truncated dict for sub/entry scans


async def dir_scan(base_url: str, client: httpx.AsyncClient,
                   concurrency: int = 40, depth: int = 0,
                   max_bases: int = 1, words: list | None = None) -> list:
    """dirsearch-style dictionary scan with soft-404 baseline.

    Multi-level: hits that look like directories (extensionless served
    path) are re-scanned with the same dictionary, `depth` levels deep,
    `max_bases` extra bases in total."""
    p = urlsplit(base_url)
    netloc = f"{p.scheme}://{p.netloc}"
    words = words or _dict_words()
    home_sig = await _page_signature(client, netloc)
    sem = asyncio.Semaphore(concurrency)
    hits = []
    first = (base_url.rstrip("/") + "/") if p.path not in ("", "/") \
        else netloc + "/"
    queue = [(first, 0)]
    seen_bases = set()

    while queue and len(hits) < MAX_DIR_HITS + MAX_LEAK_HITS:
        base, lvl = queue.pop(0)
        if base in seen_bases or (lvl and len(seen_bases) > max_bases):
            continue
        seen_bases.add(base)
        baseline = []
        for _ in range(2):
            rnd = f"{base}scanx-{uuid.uuid4().hex[:12]}"
            try:
                r = await client.get(rnd)
                title = ""
                if "html" in r.headers.get("content-type", ""):
                    m = TITLE_RE.search(r.text[:300_000])
                    title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
                baseline.append((r.status_code, len(r.content), title))
            except httpx.HTTPError:
                baseline.append((0, 0, ""))
        lvl_hits = []

        async def one(word):
            if len(hits) >= MAX_DIR_HITS + MAX_LEAK_HITS:
                return
            async with sem:
                rs = await _probe_path(client, base + word.lstrip("/"),
                                       baseline, home_sig)
                lvl_hits.extend(rs)
                hits.extend(rs)

        await asyncio.gather(*(
            one(w) for w in (words if lvl == 0 else words[:SUB_DICT_TOP])))
        if lvl:
            for h in lvl_hits:
                if h.get("source") is None:
                    h["source"] = "dir:多级"
        if lvl < depth:
            for h in lvl_hits:
                if h["kind"] == "dir" and _dirish(h["url"],
                                                h.get("status_code") or 0):
                    nb = h["url"].rstrip("/") + "/"
                    if nb not in seen_bases:
                        queue.append((nb, lvl + 1))
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
    domain_sem = asyncio.Semaphore(2)  # subdomain/net scans per root domain
    domain_cache = {}   # root domain -> shared scan task
    seen_urls = set()   # (kind,url,hint) already saved — no dup rows

    async def _domain_scan(url, host, root):
        out = []
        async with domain_sem:
            if "sub" in kinds:
                out += await subdomain_scan(
                    url, client, max(20, cfg["concurrency"] // 2))
            if "brute" in kinds:
                out += await subdomain_brute(
                    url, client, max(30, cfg["concurrency"]))
            if "net" in kinds:
                out += await net_search(url, client, cfg)
            if "host" in kinds:
                # host collision: probe this IP with discovered FQDNs
                fqdns = sorted({
                    urlsplit(r["url"]).hostname
                    for r in out if r["kind"] == "sub"
                } - {host, root})
                if not fqdns and SUB_DICT_PATH.exists():
                    fqdns = [
                        f"{w.strip()}.{root}" for w in
                        SUB_DICT_PATH.read_text(
                            encoding="utf-8").splitlines()[:120]
                        if w.strip() and not w.startswith("#")
                    ]
                if fqdns:
                    out += await host_collision(url, client, fqdns)
            if "origin" in kinds:
                # fuckcdn: candidate IPs = net-engine IPs + resolved subs
                ip_pool = set()
                for r in out:
                    for m in re.finditer(
                            r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                            r.get("source") or ""):
                        ip_pool.add(m.group(0))
                sub_hosts = {
                    urlsplit(r["url"]).hostname
                    for r in out
                    if r.get("kind") == "sub" and r.get("status_code")
                } - {host}
                for lst in await asyncio.gather(
                        *(_resolve(h) for h in list(sub_hosts)[:80])):
                    ip_pool.update(lst)
                out += await origin_scan(url, client, sorted(ip_pool))
            if "wayback" in kinds:
                out += await wayback_scan(url, client)
            if "takeover" in kinds:
                ns = {
                    urlsplit(r["url"]).hostname: r.get("status_code")
                    for r in out if r.get("kind") == "sub"
                }
                if not ns and SUB_DICT_PATH.exists():
                    ns = {
                        f"{w.strip()}.{root}": None for w in
                        SUB_DICT_PATH.read_text(
                            encoding="utf-8").splitlines()[:120]
                        if w.strip() and not w.startswith("#")
                    }
                if ns:
                    out += await takeover_scan(ns, client)
            if "port" in kinds:
                hosts = {host}
                for r in out:
                    if r.get("kind") == "sub" and r.get("status_code"):
                        hh = urlsplit(r["url"]).hostname
                        if hh:
                            hosts.add(hh)
                    elif r.get("kind") == "net":
                        for m in re.finditer(
                                r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                                r.get("source") or ""):
                            hosts.add(m.group(0))
                out += await port_scan(sorted(hosts)[:MAX_PORT_HOSTS])
            if "dir" in kinds:
                # extended directory coverage: alive subdomain roots and
                # entry-point prefixes discovered by js/url/dir collectors
                sub_roots, entry_dirs = [], []
                for r in out:
                    u = r.get("url") or ""
                    if not u.startswith("http") or not r.get("status_code"):
                        continue
                    sp = urlsplit(u)
                    if r.get("kind") == "sub" and sp.hostname != host:
                        sub_roots.append(f"{sp.scheme}://{sp.netloc}/")
                    elif r.get("kind") in ("js", "dir") and \
                            sp.hostname == host:
                        seg = sp.path.strip("/").split("/")[0]
                        if len(seg) > 2 and "." not in seg:
                            entry_dirs.append(
                                f"{sp.scheme}://{sp.netloc}/{seg}/")
                words = _dict_words()[:SUB_DICT_TOP]
                conc = max(10, cfg["concurrency"] // 2)
                for b in list(dict.fromkeys(sub_roots))[:DIR_SUB_MAX]:
                    out += await dir_scan(b, client, conc,
                                          depth=1, max_bases=2, words=words)
                for b in list(dict.fromkeys(entry_dirs))[:DIR_ENTRY_MAX]:
                    out += await dir_scan(b, client, conc,
                                          depth=1, max_bases=2, words=words)
        return out

    async def per_target(t):
        url = t["url"] if "://" in t["url"] else "https://" + t["url"]
        results = []
        host = urlsplit(url).hostname
        root = _root_domain(host)
        try:
            if "js" in kinds:
                results += await js_scan(url, client)
            if "dir" in kinds:
                async with dir_sem:
                    results += await dir_scan(
                        url, client, concurrency=max(10, cfg["concurrency"] // 2),
                        depth=2, max_bases=4)
            # domain-level scans run once per root domain (shared task)
            if root and not _is_ip(root):
                task = domain_cache.get(root)
                if task is None:
                    task = asyncio.create_task(_domain_scan(url, host, root))
                    domain_cache[root] = task
                results += await task
            # subdomains of this root that JS/目录 findings pointed at —
            # recorded as unvalidated intel ("sub:js"), deep scan promotes
            if root and not _is_ip(root):
                seen_hosts = set()
                for r in list(results):
                    h = urlsplit(r.get("url") or "").hostname or ""
                    if h.endswith("." + root) and h != host \
                            and h not in seen_hosts:
                        seen_hosts.add(h)
                        results.append({
                            "kind": "sub", "url": f"https://{h}",
                            "source": "js", "status_code": None,
                            "title": None, "length": None,
                            "hint": "sub:js", "surface": 0,
                        })
        finally:
            for r in results:
                k = (r.get("kind"), r.get("url"), r.get("hint"))
                if k in seen_urls:
                    continue
                seen_urls.add(k)
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

# selection priority for deep scan — confirmed surfaces and vuln points first
DEEP_PRIORITY = {"cdn": 0, "host": 0, "vuln": 0, "sub": 1, "port": 1,
                 "point": 2, "leak": 2, "url": 2, "dir": 3, "js": 4, "net": 5}


def _dom_sig(html: str) -> str:
    """Interface signature of a rendered page: only the sequence of tag
    names is hashed — text/attributes are ignored, so the same interface
    with different tokens/timestamps still gets the same signature."""
    tags = re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9]*)", (html or "")[:200_000])
    return hashlib.sha1(" ".join(tags).encode()).hexdigest()[:16]


async def _bypassed_result(client, url, fields, run_id, shot_sem, cfg):
    """A protection page was fingerprinted — try to reach the real backend
    behind it and re-fingerprint/screenshot that response instead."""
    bp = await bypass.find_bypass(client, url)
    if not bp:
        return {}
    r = bp["resp"]
    resp = bypass.resp_to_dict(r, bp["url"])
    out = {
        "protection": (fields["protection"] or "") + f"→bypass:{bp['mode']}",
        "status_code": r.status_code,
        "server": resp["server"],
    }
    signals = None
    if cfg["screenshot"]:
        shot_name = f"exp{run_id}_{uuid.uuid4().hex[:8]}.png"
        async with shot_sem:
            cap = await traffic.capture(
                bp["url"], traffic.SHOT_DIR / shot_name,
                fp.js_globals(), fp.dom_selectors(), headers=bp["headers"],
                proxy=cfg.get("proxy") or None)
        if cap["ok"]:
            out["screenshot"] = shot_name
            out["shot_sig"] = f"{r.status_code}|{_dom_sig(cap['html'])}"
            signals = fp.signals_from_capture(cap, resp)
    fps = await bypass.refingerprint(client, resp, signals)
    out["fingerprints"] = json.dumps(fps, ensure_ascii=False)
    return out


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
        h = urlsplit(u).hostname or ""
        th = host_of(t)
        # scope: exact target host, or a same-root host for domain-expansion
        # kinds (sub/host/net — they live under the target's own domain);
        # anything else stays out of authorized scope
        in_scope = h == th or r.get("kind") == "cdn" or (
            r.get("kind") in ("sub", "host", "net", "url", "port")
            and _root_domain(h) and _root_domain(h) == _root_domain(th))
        if not in_scope:
            continue
        pri = DEEP_PRIORITY.get(r.get("kind") or "js", 9)
        hint = r.get("hint") or ""
        if hint in ("entry", "point:login", "point:admin"):
            pri = 0                         # entries always probe first
        surf = 0 if r.get("surface") else 1   # surfaces sort first
        prev = urls.get(u)
        if prev is None or (surf, pri) < (prev[0], prev[1]):
            urls[u] = (surf, pri, r["target_id"], hint)
    # HTTP probing is cheap — cover far more URLs than the capture budget;
    # `limit` then means "distinct pages to screenshot", not "rows scanned"
    ordered = sorted(
        urls.items(), key=lambda kv: (kv[1][0], kv[1][1], kv[0])
    )[:max(limit * 4, 400)]

    store.exposure_deep_start(run_id, len(ordered))

    client = probe.make_client()
    proxy = cfg.get("proxy") or None
    probe_sem = asyncio.Semaphore(max(5, cfg["concurrency"] // 3))
    shot_sem = asyncio.Semaphore(max(1, cfg["browser_concurrency"]))

    # ---- phase 1: probe every URL (cheap) ----
    probed = []

    async def phase1(url, _tid, hint=""):
        try:
            async with probe_sem:
                resp = await probe.fetch(client, url)
            body = ""
            bh = ""
            if resp["alive"]:
                body = (resp.get("html") or "")[:300_000]
                bh = hashlib.sha1(
                    re.sub(r"\s+", "", body[:8000]).encode("utf-8", "ignore")
                ).hexdigest()
            fields = {
                "status_code": resp["status_code"],
                "alive": 1 if resp["alive"] else 0,
                "surface": 0,
                "final_url": resp["final_url"],
                "server": resp["server"],
                "fingerprints": None,
                "screenshot": None,
                "protection": None,
                "shot_sig": None,
                "hint": "entry" if body and LOGIN_PAGE_RE.search(body)
                        else None,
            }
            probed.append({"url": url, "resp": resp, "fields": fields,
                           "bh": bh, "hint": hint})
            if not fields["alive"]:
                store.update_exposure_deep_result(run_id, url, fields)
                store.bump_exposure_deep(run_id)
        except Exception:
            store.bump_exposure_deep(run_id)

    await asyncio.gather(*(phase1(u, t, h)
                           for u, (_s, _p, t, h) in ordered))

    # ---- phase 2: a "surface" is a page not seen before — one per
    # distinct body. identical bodies share ONE capture + fingerprint ----
    groups = {}
    for p in probed:
        if p["fields"]["alive"]:
            groups.setdefault(p["bh"], []).append(p)
    ordered_groups = list(groups.values())  # keeps priority order

    extra_entry_shots = {"n": 0}    # entries beyond limit still captured
    MAX_ENTRY_SHOTS = 50

    async def run_group(idx, members):
        p0 = members[0]               # rep = the first-seen distinct page
        resp0 = p0["resp"]
        shared = {"screenshot": None, "shot_sig": None}
        signals = None
        is_entry = p0.get("hint") in ("entry", "point:login", "point:admin")
        take_shot = idx < limit or (is_entry
                                    and extra_entry_shots["n"] < MAX_ENTRY_SHOTS)
        if take_shot and idx >= limit:
            extra_entry_shots["n"] += 1
        if take_shot and cfg["screenshot"]:
            shot_name = f"exp{run_id}_{uuid.uuid4().hex[:8]}.png"
            try:
                async with shot_sem:
                    cap = await traffic.capture(
                        resp0["final_url"], traffic.SHOT_DIR / shot_name,
                        fp.js_globals(), fp.dom_selectors(), proxy=proxy)
                if cap["ok"]:
                    shared["screenshot"] = shot_name
                    shared["shot_sig"] = (
                        f"{resp0['status_code']}|{_dom_sig(cap['html'])}")
                    signals = fp.signals_from_capture(cap, resp0)
                else:
                    print(f"[deep] capture failed {resp0['final_url']}: "
                          f"{cap.get('error')}")
            except Exception as e:
                print(f"[deep] capture error {resp0['final_url']}: {e}")
        if signals is None:
            fav = await probe.fetch_favicon_hash(client, resp0["final_url"])
            signals = fp.signals_from_response(resp0, fav)
        matched = fp.match(signals)
        hits = list(matched["hits"])
        if cfg["active_probe"]:
            base = resp0["final_url"]
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
        fps_json = json.dumps(fps, ensure_ascii=False)
        prot = [h["name"] for h in fps if h["category"] == "防护页"]
        prot_str = ",".join(prot) if prot else None

        async def fin(p):
            fields = dict(p["fields"])
            fields.update({
                "surface": 1 if p is p0 else 0,
                "screenshot": shared["screenshot"],
                "shot_sig": shared["shot_sig"],
                "fingerprints": fps_json,
                "protection": prot_str,
            })
            if prot:
                fields.update(await _bypassed_result(
                    client, p["url"], fields, run_id, shot_sem, cfg))
            store.update_exposure_deep_result(run_id, p["url"], fields)
            store.bump_exposure_deep(run_id)

        await asyncio.gather(*(fin(p) for p in members))

    try:
        await asyncio.gather(*(
            run_group(i, ms) for i, ms in enumerate(ordered_groups)))
        store.finish_exposure_deep(run_id)
    except Exception:
        store.fail_exposure_deep(run_id)
        raise
    finally:
        await client.aclose()
