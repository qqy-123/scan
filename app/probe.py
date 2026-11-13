import asyncio
import hashlib
import re
import ssl
import time

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


def _title(html: str) -> str:
    m = TITLE_RE.search(html)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


async def fetch(client: httpx.AsyncClient, url: str) -> dict:
    """Fetch a URL; returns response details + raw materials for fingerprinting.

    URL without scheme tries https first, then http.
    """
    candidates = (
        [f"https://{url}", f"http://{url}"]
        if "://" not in url
        else [url]
    )
    last_err = None
    # connect-level failures deserve one retry: under browser-capture load a
    # wave of connects can starve past the timeout and mass-mark live targets
    # dead. Read/write errors stay single-shot.
    for attempt in range(2):
        for cand in candidates:
            start = time.monotonic()
            try:
                resp = await client.get(cand)
                elapsed = int((time.monotonic() - start) * 1000)
                body = resp.text[:500_000]
                return {
                    "alive": True,
                    "status_code": resp.status_code,
                    "final_url": str(resp.url),
                    "title": _title(body),
                    "server": resp.headers.get("server", ""),
                    "elapsed_ms": elapsed,
                    "headers": dict(resp.headers),
                    "cookies": dict(resp.cookies),
                    "html": body,
                    "error": None,
                }
            except httpx.HTTPError as e:
                last_err = f"{type(e).__name__}: {e}"
        if attempt or not last_err or not last_err.startswith(
            ("ConnectTimeout", "ConnectError", "PoolTimeout")
        ):
            break
        await asyncio.sleep(0.5)
    return {
        "alive": False,
        "status_code": None,
        "final_url": candidates[-1],
        "title": "",
        "server": "",
        "elapsed_ms": None,
        "headers": {},
        "cookies": {},
        "html": "",
        "error": last_err,
    }


STATIC_PROBE_EXT = {
    "svg", "png", "jpg", "jpeg", "gif", "ico", "css", "js", "map", "json",
    "xml", "txt", "webp", "woff", "woff2", "ttf", "eot", "pdf", "zip",
}


def probe_is_fallback(path: str, resp: httpx.Response) -> bool:
    """SPA/static hosts answer EVERY path with 200 + index.html — a probe
    for a static-extension file answered as HTML is the fallback page,
    not the real file (existence probes would hit on every such host)."""
    name = path.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in STATIC_PROBE_EXT and "html" in (
        resp.headers.get("content-type") or ""
    )


_NORM_WS = re.compile(r"\s+")
_NORM_URL = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
_NORM_TOKEN = re.compile(r"[a-zA-Z0-9]{16,}")
_NORM_DIGITS = re.compile(r"\d+")


def _norm_probe_body(body: str, path: str) -> str:
    """Normalize a probe response for catch-all comparison: strip the
    requested path (echoed paths are the #1 probe false-positive), full
    URLs, whitespace, machine tokens (session ids, timestamps, hashes)
    and digits — leaving the stable semantic skeleton of the page."""
    text = body.replace(path, " ")
    text = _NORM_URL.sub(" ", text)
    text = _NORM_TOKEN.sub(" ", text)
    text = _NORM_DIGITS.sub(" ", text)
    return _NORM_WS.sub(" ", text)


async def probe_baseline(client: httpx.AsyncClient, base_url: str,
                         semaphore=None) -> str | None:
    """Catch-all calibration (ffuf/opendoor soft-404 technique): fetch a
    random nonexistent path once per host. If it returns <400, the host
    wildcard-serves content — return the normalized body so probe hits
    can be compared against it (same skeleton = fallback, not a hit)."""
    import secrets

    path = f"/{secrets.token_hex(8)}"
    url = base_url.rstrip("/") + path
    try:
        if semaphore:
            async with semaphore:
                r = await client.get(url)
        else:
            r = await client.get(url)
    except httpx.HTTPError:
        return None
    if r.status_code >= 400:
        return None
    return _norm_probe_body(r.text[:300_000], path)


def probe_matches_baseline(body: str, path: str, baseline: str) -> bool:
    """Probe response is the same catch-all page as the baseline when the
    normalized skeletons are identical or near-identical (>=0.97 covers
    shells embedding tokens the normalizer can't strip)."""
    import difflib

    norm = _norm_probe_body(body, path)
    if norm == baseline:
        return True
    if not norm or not baseline:
        return False
    return difflib.SequenceMatcher(
        None, norm, baseline).quick_ratio() >= 0.97


async def fetch_favicon_hash(client: httpx.AsyncClient, final_url: str) -> int | None:
    import base64

    import mmh3

    try:
        from urllib.parse import urlsplit

        p = urlsplit(final_url)
        resp = await client.get(f"{p.scheme}://{p.netloc}/favicon.ico")
        if resp.status_code == 200 and resp.content:
            return mmh3.hash(base64.encodebytes(resp.content))
    except httpx.HTTPError:
        pass
    return None


async def sni_fetch(ip: str, host: str, scheme: str = "https",
                    path: str = "/", timeout: int = 8) -> dict | None:
    """Direct connection to `ip` speaking SNI/Host of `host` — the
    primitive for vhost collision and CDN-origin discovery. Always
    direct (never via proxy): the point is the IP itself."""
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = asyncio.open_connection(
                ip, 443, ssl=ctx, server_hostname=host)
        else:
            conn = asyncio.open_connection(ip, 80)
        reader, writer = await asyncio.wait_for(conn, timeout)
    except Exception:
        return None
    try:
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
            f"Accept: text/html,*/*;q=0.8\r\nConnection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(400_000), timeout)
    except Exception:
        return None
    finally:
        try:
            writer.close()
        except Exception:
            pass
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except Exception:
        return None
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        if k.strip():
            headers[k.strip().lower()] = v.strip()
    if "chunked" in headers.get("transfer-encoding", ""):
        body = _dechunk(body)
    text = body.decode("utf-8", "ignore")
    m = TITLE_RE.search(text)
    return {
        "status": status,
        "title": re.sub(r"\s+", " ", m.group(1)).strip() if m else "",
        "length": len(body),
        "body_hash": hashlib.sha1(
            re.sub(r"\s+", "", text[:8000]).encode("utf-8", "ignore")
        ).hexdigest(),
        "server": headers.get("server", ""),
        "headers": headers,
        "html": text[:300_000],
    }


def _dechunk(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        nl = data.find(b"\r\n", pos)
        if nl < 0:
            break
        try:
            size = int(data[pos:nl].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        pos = nl + 2
        out += data[pos:pos + size]
        pos += size + 2
    return bytes(out)


def make_client() -> httpx.AsyncClient:
    from . import store

    cfg = store.get_settings()
    timeout = httpx.Timeout(
        connect=cfg["connect_timeout"],
        read=cfg["read_timeout"],
        write=8,
        pool=30,
    )
    return httpx.AsyncClient(
        verify=False,
        proxy=cfg.get("proxy") or None,
        follow_redirects=True,
        timeout=timeout,
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        },
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )
