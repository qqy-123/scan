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
            "detected": [
                {"name": h["name"], "category": h["category"], "confidence": h["confidence"]}
                for h in detected
            ],
        }
    finally:
        if own:
            await client.aclose()


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
