"""Exposure scanning (资产测绘/暴露面): for alive targets,
  - js scan   : pull every same-host JS and extract embedded endpoints
                (hidden APIs, backend URLs, admin paths)
  - dirsearch : dictionary brute-force for admin/backup/api/config paths
                with soft-404 baseline to suppress noise.
"""

import asyncio
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import probe, store

DICT_PATH = Path(__file__).resolve().parent.parent / "rules" / "dirs.txt"
MAX_JS_FILES = 25
MAX_JS_SIZE = 400_000
MAX_DIR_HITS = 300

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
    """Extract endpoints embedded in the site's JS files."""
    try:
        html = (await client.get(base_url)).text[:500_000]
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
    base = urlsplit(base_url)

    async def pull(js_url: str):
        try:
            r = await client.get(js_url)
            if r.status_code >= 400:
                return
            body = r.text[:MAX_JS_SIZE]
        except httpx.HTTPError:
            return
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

    await asyncio.gather(*(pull(u) for u in srcs))

    out = []
    for u, src in found.values():
        same = urlsplit(u).hostname == base.hostname
        out.append(
            {
                "kind": "js",
                "url": u,
                "source": src,
                "status_code": None,
                "title": None,
                "length": None,
                "hint": _hint(urlsplit(u).path) + ("" if same else ":external"),
            }
        )
    out.sort(key=lambda x: (x["hint"].endswith("external"), x["hint"], x["url"]))
    return out


async def _probe_path(client, url, baseline):
    """One dict word. Returns result dict or None if it looks like a soft-404.

    Only 2xx/3xx/401/403 count as exposure — 429/406/5xx are rate-limit /
    WAF noise, not findings."""
    try:
        r = await client.get(url)
    except httpx.HTTPError:
        return None
    status = r.status_code
    if not (200 <= status < 400 or status in (401, 403)):
        return None
    body_len = len(r.content)
    title = ""
    if "html" in r.headers.get("content-type", ""):
        m = TITLE_RE.search(r.text[:300_000])
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    # soft-404 suppression: same status & similar length & same title as baseline
    for b_status, b_len, b_title in baseline:
        if status == b_status and title == b_title and \
                (b_len == 0 or abs(body_len - b_len) <= max(40, b_len * 0.1)):
            return None
    return {
        "kind": "dir",
        "url": url,
        "source": None,
        "status_code": status,
        "title": title or None,
        "length": body_len,
        "hint": _hint(urlsplit(url).path),
    }


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

    sem = asyncio.Semaphore(concurrency)
    hits = []

    async def one(word):
        if len(hits) >= MAX_DIR_HITS:
            return
        async with sem:
            r = await _probe_path(client, f"{base}/{word.lstrip('/')}", baseline)
            if r:
                hits.append(r)

    await asyncio.gather(*(one(w) for w in _dict_words()))
    hits.sort(key=lambda x: (x["status_code"], x["url"]))
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
