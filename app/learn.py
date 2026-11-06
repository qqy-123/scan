"""Fingerprint learning: extract distinctive source-code features from a
sample site and turn them into a reusable rule saved in rules/custom.json."""

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import fingerprint as fp
from . import probe

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


def _path_prefixes(html: str, base_url: str) -> list:
    """Extract ranked candidate path prefixes from src/href attributes."""
    base = urlsplit(base_url)
    counts = Counter()
    for m in ATTR_RE.findall(html):
        u = m.strip()
        if u.startswith(("data:", "javascript:", "#", "mailto:")):
            continue
        p = urlsplit(urljoin(base_url, u))
        if p.hostname and base.hostname and p.hostname != base.hostname \
                and not p.hostname.endswith(base.hostname):
            continue
        segs = [s for s in p.path.split("/") if s]
        if not segs or segs[0].lower() in GENERIC:
            continue
        if len(segs) == 1 and re.search(r"\.(ico|png|jpe?g|gif|svg|css|js|woff2?|map|txt|xml|json)$", segs[0], re.I):
            continue  # single-segment assets are not distinctive
        prefix = "/" + "/".join(segs[:2]) if len(segs) >= 2 else "/" + segs[0]
        counts[prefix] += 1
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
        favicon = await probe.fetch_favicon_hash(client, resp["final_url"])
        signals = fp.signals_from_response(resp, favicon)
        detected = fp.postprocess(fp.match(signals)["hits"])
        return {
            "ok": True,
            "url": url,
            "final_url": resp["final_url"],
            "title": resp["title"],
            "server": resp["server"],
            "favicon": favicon,
            "meta": {k: v for k, v in signals["meta"].items() if v},
            "cookies": sorted(signals["cookies"].keys()),
            "paths": _path_prefixes(resp["html"], resp["final_url"]),
            "keywords": _distinctive_text(resp["html"]),
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
