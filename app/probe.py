import re
import time

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
TIMEOUT = httpx.Timeout(connect=8, read=15, write=8, pool=30)
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


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=TIMEOUT,
        headers={"User-Agent": UA},
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )
