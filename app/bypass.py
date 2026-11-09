"""Front-protection bypass: when a scan lands on a WAF/CDN interstitial
page, try alternate routes to reach the real backend service.

Two strategies:
  1. forwarding-header spoof (X-Forwarded-For/X-Real-IP/...) — some WAF
     rules trust internal-looking addresses or mis-parse client IPs
  2. origin-IP bypass — resolve the host, request each IP with the real
     Host header; CDN-fronted sites often answer the raw vhost directly
"""

import asyncio
import socket
from urllib.parse import urlsplit

import httpx

from . import fingerprint as fp

HEADER_ATTEMPTS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
     "X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "{host}"},
    {"Referer": "https://{host}/"},
]


def _prot_rules():
    return [r for r in fp.load_rules() if r.get("category") == "防护页"]


def _signals(r: httpx.Response):
    return fp.signals_from_response(
        {
            "final_url": str(r.url),
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "cookies": dict(r.cookies),
            "html": r.text[:300_000],
            "title": "",
        },
        None,
    )


def is_protected_response(r: httpx.Response) -> bool:
    """True when the response still carries a protection-page signature."""
    try:
        return any(fp.evaluate(rule, _signals(r)) for rule in _prot_rules())
    except Exception:
        return False


async def _resolve(host: str) -> list:
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, None, socket.AF_UNSPEC, socket.SOCK_STREAM),
            timeout=4,
        )
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def _unprotected(r: httpx.Response) -> bool:
    return 200 <= r.status_code < 400 and not is_protected_response(r)


async def find_bypass(client: httpx.AsyncClient, url: str) -> dict | None:
    """Probe alternate routes to a protected page.
    Returns {"mode", "url", "headers", "resp"} — `url`/`headers` can be fed
    straight into probe.fetch-style requests or playwright capture."""
    host = urlsplit(url).hostname or ""
    path = urlsplit(url).path or "/"

    # 1. forwarding-header spoof on the same URL
    for hdrs in HEADER_ATTEMPTS:
        h = {k: v.format(host=host) for k, v in hdrs.items()}
        try:
            r = await client.get(url, headers=h, timeout=10)
        except httpx.HTTPError:
            continue
        if _unprotected(r):
            return {"mode": "header:" + ",".join(h),
                    "url": url, "headers": h, "resp": r}

    # 2. origin-IP bypass: each resolved IP + real Host header
    for ip in await _resolve(host):
        for scheme in ("https", "http"):
            ip_url = f"{scheme}://{ip}{path}"
            try:
                r = await client.get(ip_url, headers={"Host": host},
                                     timeout=8)
            except httpx.HTTPError:
                continue
            if _unprotected(r):
                return {"mode": f"origin:{ip}",
                        "url": ip_url, "headers": {"Host": host}, "resp": r}
    return None


def resp_to_dict(r: httpx.Response, url: str) -> dict:
    """httpx.Response -> the resp-dict shape fingerprint helpers expect."""
    return {
        "alive": True,
        "status_code": r.status_code,
        "final_url": str(r.url) or url,
        "title": "",
        "server": r.headers.get("server", ""),
        "headers": dict(r.headers),
        "cookies": dict(r.cookies),
        "html": r.text[:300_000],
    }


async def refingerprint(client: httpx.AsyncClient, resp: dict,
                        signals=None) -> list:
    """Passive fingerprinting of a bypassed (real-service) response."""
    from . import probe

    if signals is None:
        favicon = await probe.fetch_favicon_hash(client, resp["final_url"])
        signals = fp.signals_from_response(resp, favicon)
    matched = fp.match(signals)
    return fp.postprocess(list(matched["hits"]))
