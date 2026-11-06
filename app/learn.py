"""Fingerprint learning: extract distinctive source-code features from a
sample site and turn them into a reusable rule saved in rules/custom.json."""

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import fingerprint as fp
from . import probe, traffic

CUSTOM_RULES = Path(__file__).resolve().parent.parent / "rules" / "custom.json"

ATTR_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', re.I)

# path segments too common to identify a source system
GENERIC = {
    "static", "assets", "asset", "js", "css", "img", "images", "image", "upload",
    "uploads", "api", "lib", "libs", "fonts", "font", "media", "public",
    "common", "vendor", "plugins", "node_modules", "unpkg", "cdn", "dist",
    "build", "res", "resource", "resources", "skin", "style", "styles",
    "script", "scripts", "temp", "tmp", "file", "files", "pic", "pics",
    "html", "themes", "theme", "template", "templates", "include", "includes",
    "inc", "core", "app", "www", "home", "index", "user", "admin", "system",
}


def _prefix_counts(urls: list, base_host: str) -> Counter:
    counts = Counter()
    for u in urls:
        p = urlsplit(u)
        if p.hostname and base_host and p.hostname != base_host \
                and not p.hostname.endswith(base_host):
            continue
        segs = [s for s in p.path.split("/") if s]
        if not segs or segs[0].lower() in GENERIC:
            continue
        if len(segs) == 1 and re.search(
            r"\.(ico|png|jpe?g|gif|svg|css|js|woff2?|map|txt|xml|json)$",
            segs[0],
            re.I,
        ):
            continue  # single-segment assets are not distinctive
        counts["/" + "/".join(segs[:2]) if len(segs) >= 2 else "/" + segs[0]] += 1
    return counts


def _path_prefixes(html: str, base_url: str, packet_urls: list = None) -> list:
    """Rank candidate path prefixes from src/href attrs + all request URLs."""
    base = urlsplit(base_url)
    urls = []
    for m in ATTR_RE.findall(html):
        u = m.strip()
        if u.startswith(("data:", "javascript:", "#", "mailto:")):
            continue
        urls.append(urljoin(base_url, u))
    counts = _prefix_counts(urls, base.hostname or "")
    if packet_urls:
        counts.update(_prefix_counts(packet_urls, base.hostname or ""))
    return [p for p, _ in counts.most_common(15)]


def _distinctive_text(html: str) -> list:
    """Candidate keywords: HTML comments and uncommon meta/powered-by hints."""
    out = []
    for m in re.findall(r"<!--(.*?)-->", html, re.S)[:50]:
        s = re.sub(r"\s+", " ", m).strip()
        if 4 <= len(s) <= 60 and not re.fullmatch(r"[\W_]+", s):
            out.append(s)
    for m in re.findall(
        r'(?:content|value)\s*=\s*["\']([^"\']*(?:Powered|CMS|System|系统|平台)[^"\']*)["\']',
        html,
        re.I,
    )[:10]:
        out.append(m.strip())
    return list(dict.fromkeys(out))[:15]


# response headers that carry no product identity
BORING_HEADERS = {
    "date", "content-type", "content-length", "content-encoding",
    "transfer-encoding", "connection", "keep-alive", "cache-control",
    "pragma", "expires", "etag", "vary", "accept-ranges", "age",
    "alt-svc", "report-to", "nel", "server-timing", "set-cookie",
    "strict-transport-security", "content-security-policy",
    "content-security-policy-report-only", "x-content-type-options",
    "x-frame-options", "x-xss-protection", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy",
    "origin-agent-cluster", "x-dns-prefetch-control", "expect-ct",
    "last-modified", "if-modified-since", "location", "refresh",
    "content-disposition", "content-language", "content-range",
    "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-allow-credentials",
    "timing-allow-origin", "x-request-id", "x-correlation-id",
}


def _interesting_headers(packets: list, base_host: str) -> list:
    """Distinctive response headers from same-host packets -> 'k=v' strings."""
    out = []
    for p in packets:
        host = urlsplit(p["url"]).hostname or ""
        if base_host and host and host != base_host and not host.endswith(base_host):
            continue
        if p.get("type") not in ("document", "xhr", "fetch"):
            continue
        for k, v in (p.get("headers") or {}).items():
            k = k.lower()
            if k in BORING_HEADERS:
                continue
            if not (k.startswith("x-") or k in ("server", "via", "powered-by")):
                continue
            v = (v or "").strip()
            if len(v) > 80:
                continue
            out.append(f"{k}={v}" if v else k)
    return list(dict.fromkeys(out))[:20]


def _xhr_paths(packets: list, base_host: str) -> list:
    """XHR/fetch request paths -> 'xhr' rule candidates."""
    out = []
    for p in packets:
        if p.get("type") not in ("xhr", "fetch"):
            continue
        u = urlsplit(p["url"])
        host = u.hostname or ""
        if base_host and host and host != base_host and not host.endswith(base_host):
            continue
        path = u.path or "/"
        if len(path) < 2 or path.lower().split("/")[1] in GENERIC:
            continue
        out.append(path)
    return list(dict.fromkeys(out))[:15]


def _packet_list(packets: list) -> list:
    """Deduped packet summary for UI display / row selection."""
    seen, out = set(), []
    for p in packets:
        u = p["url"]
        if u in seen:
            continue
        seen.add(u)
        out.append({"url": u, "type": p.get("type"), "status": p.get("status")})
        if len(out) >= 150:
            break
    return out


async def extract(url: str, client=None) -> dict:
    own = client is None
    client = client or probe.make_client()
    try:
        resp = await probe.fetch(client, url)
        if not resp["alive"]:
            return {"ok": False, "error": resp["error"], "url": url}

        # browser pass for richer candidates (all triggered packet URLs)
        cap = await traffic.capture(resp["final_url"], None, [], [])
        if cap["ok"]:
            signals = fp.signals_from_capture(cap, resp)
            html = signals["html"]
            packet_urls = signals["urls"]
        else:
            favicon = await probe.fetch_favicon_hash(client, resp["final_url"])
            cap["favicon_hash"] = favicon
            signals = fp.signals_from_response(resp, favicon)
            html = resp["html"]
            packet_urls = []

        detected = fp.postprocess(fp.match(signals)["hits"])
        packets = cap.get("packets") or []
        base_host = urlsplit(signals["url"] or resp["final_url"]).hostname or ""
        return {
            "ok": True,
            "url": url,
            "final_url": signals["url"] or resp["final_url"],
            "title": signals["title"] or resp["title"],
            "server": resp["server"],
            "favicon": cap.get("favicon_hash"),
            "meta": {k: v for k, v in signals["meta"].items() if v},
            "cookies": sorted(signals["cookies"].keys()),
            "paths": _path_prefixes(html, resp["final_url"], packet_urls),
            "keywords": _distinctive_text(html),
            # packet-derived candidates for url/xhr/headers/js rule fields
            "packets": _packet_list(packets),
            "url_suggest": [
                p for p, _ in _prefix_counts(packet_urls, base_host).most_common(12)
            ],
            "xhr_suggest": _xhr_paths(packets, base_host),
            "headers": _interesting_headers(packets, base_host),
            "js": [
                f"{k}={v}" for k, v in (cap.get("js") or {}).items()
            ],
            "detected": [
                {"name": h["name"], "category": h["category"], "confidence": h["confidence"]}
                for h in detected
            ],
        }
    finally:
        if own:
            await client.aclose()


_VERSION_RE = re.compile(r"^\d+(?:\.\d+)+$")


def _kv(v: str) -> tuple:
    """Split a 'key=value' suggestion; value ''/None -> '.*'."""
    i = v.index("=") if "=" in v else -1
    return (v[:i], v[i + 1:]) if i >= 0 else (v, ".*")


def build_rule(name: str, selected: dict, category: str = "自定义") -> dict:
    """Compose a rule dict from user-selected candidate features."""
    rule = {"name": name, "category": category}
    if selected.get("html"):
        rule["html"] = selected["html"]
    if selected.get("meta"):
        rule["meta"] = {k: [v or ".*"] for k, v in selected["meta"].items()}
    if selected.get("cookies"):
        rule["cookies"] = {c: ".*" for c in selected["cookies"]}
    if selected.get("favicon"):
        rule["favicon"] = [str(selected["favicon"])]
    if selected.get("scriptSrc"):
        rule["scriptSrc"] = selected["scriptSrc"]
    if selected.get("probe"):
        rule["probe"] = {p: [".*"] for p in selected["probe"]}
    # packet-derived fields
    if selected.get("url"):
        rule["url"] = selected["url"]
    if selected.get("xhr"):
        rule["xhr"] = selected["xhr"]
    if selected.get("headers"):
        rule["headers"] = {k: [v or ".*"] for k, v in selected["headers"].items()}
    if selected.get("js"):
        js = {}
        for item in selected["js"]:
            k, v = _kv(item) if isinstance(item, str) else item
            if _VERSION_RE.match(v or ""):
                js[k] = ["([0-9]+(?:\\.[0-9]+)*)\\;version:\\1"]
            else:
                js[k] = [v or ".*"]
        rule["js"] = js
    return rule


def load_custom() -> list:
    if not CUSTOM_RULES.exists():
        return []
    return json.loads(CUSTOM_RULES.read_text(encoding="utf-8"))


def save_custom(rule: dict):
    rules = load_custom()
    rules = [r for r in rules if r.get("name") != rule["name"]]
    rules.append(rule)
    CUSTOM_RULES.write_text(
        json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    fp.reload()


def delete_custom(name: str) -> bool:
    rules = load_custom()
    kept = [r for r in rules if r.get("name") != name]
    if len(kept) == len(rules):
        return False
    CUSTOM_RULES.write_text(
        json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    fp.reload()
    return True


def set_disabled(name: str, disabled: bool):
    """Disable a rule via a custom.json override, or re-enable it.

    For custom rules the flag toggles on the existing entry; for built-ins a
    {"name": ..., "_disabled": true} override entry is appended.
    """
    rules = load_custom()
    entry = next((r for r in rules if r.get("name") == name), None)
    if disabled:
        if entry is None:
            rules.append({"name": name, "_disabled": True})
        else:
            entry["_disabled"] = True
    else:
        if entry is None:
            return  # nothing to enable
        entry.pop("_disabled", None)
        if not any(k for k in entry if k not in ("name", "category", "_file")):
            rules = [r for r in rules if r is not entry]  # pure stub -> drop
    CUSTOM_RULES.write_text(
        json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    fp.reload()


def is_disabled(name: str) -> bool:
    entry = next((r for r in load_custom() if r.get("name") == name), None)
    return bool(entry and entry.get("_disabled"))


def disabled_names() -> set:
    return {r["name"] for r in load_custom() if r.get("_disabled")}


def builtin_raw(name: str):
    """Raw JSON of a built-in rule (non-custom files) + its source file."""
    for f in sorted(fp.RULES_DIR.glob("*.json"), key=lambda x: x.name):
        if f.name == "custom.json":
            continue
        for raw in json.loads(f.read_text(encoding="utf-8")):
            if raw.get("name") == name:
                return raw, f.name
    return None, None
