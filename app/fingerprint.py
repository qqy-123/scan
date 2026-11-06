"""Wappalyzer-style fingerprint engine.

Signal sources: headers, cookies, meta, html, scriptSrc, scripts, url,
favicon (mmh3), js globals & dom (rendered via playwright), probe (active).

Pattern syntax: "regex\\;confidence:60\\;version:\\1"
A technology is confirmed when summed confidence of matched patterns >= 100,
40-99 => possible.
"""

import json
import re
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
CONFIRMED = 100
POSSIBLE = 40

META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
META_ATTR = {
    "name": re.compile(r'(?:name|property)\s*=\s*["\']([^"\']+)["\']', re.I),
    "content": re.compile(r'content\s*=\s*["\']([^"\']*)["\']', re.I),
}
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>", re.I | re.S)


class Pattern:
    __slots__ = ("raw", "regex", "confidence", "version")

    def __init__(self, raw: str):
        parts = raw.split("\\;")
        self.raw = raw
        self.regex = re.compile(parts[0] or ".*", re.I | re.S)
        self.confidence = 100
        self.version = None
        for t in parts[1:]:
            if t.startswith("confidence:"):
                self.confidence = int(t[11:])
            elif t.startswith("version:"):
                self.version = t[8:]

    def search(self, text: str):
        m = self.regex.search(text)
        if not m:
            return None
        ver = None
        if self.version is not None:
            ver = self.version
            for i, g in enumerate(m.groups(), 1):
                ver = ver.replace(f"\\{i}", g or "")
            ver = ver.replace("\\0", m.group(0)).strip() or None
        return {"version": ver, "confidence": self.confidence, "pattern": self.raw}


def _plist(v) -> list:
    if isinstance(v, str):
        v = [v]
    return [Pattern(x) for x in (v or [])]


def _pmap(d) -> dict:
    return {k: _plist(v) for k, v in (d or {}).items()}


def compile_rule(raw: dict) -> dict:
    rule = dict(raw)
    for f in ("headers", "cookies", "meta", "js", "probe"):
        rule[f] = _pmap(rule.get(f))
    for f in ("html", "scriptSrc", "scripts", "url", "xhr", "css", "robots"):
        rule[f] = _plist(rule.get(f))
    rule["favicon"] = [str(x) for x in rule.get("favicon") or []]
    rule["dom"] = rule.get("dom") or {}
    rule["implies"] = rule.get("implies") or []
    rule["excludes"] = rule.get("excludes") or []
    return rule


_cache = None


def load_rules() -> list:
    global _cache
    if _cache is None:
        rules = []
        for f in sorted(RULES_DIR.glob("*.json")):
            for raw in json.loads(f.read_text(encoding="utf-8")):
                raw["_file"] = f.name
                rules.append(compile_rule(raw))
        _cache = rules
    return _cache


def reload():
    """Drop the compiled-rule cache so new/edited rule files take effect."""
    global _cache
    _cache = None


def rule_names() -> set:
    return {r["name"] for r in load_rules()}


def js_globals() -> list:
    out = set()
    for r in load_rules():
        out.update(r["js"].keys())
    return sorted(out)


def dom_selectors() -> list:
    out = set()
    for r in load_rules():
        out.update(r["dom"].keys())
    return sorted(out)


# ---------------- signal collection ----------------

def signals_from_response(resp: dict, favicon_hash=None) -> dict:
    """Build signals dict from a probe.fetch() result."""
    html = resp.get("html") or ""
    meta = {}
    for tag in META_TAG_RE.findall(html):
        name = META_ATTR["name"].search(tag)
        content = META_ATTR["content"].search(tag)
        if name:
            meta[name.group(1).lower()] = content.group(1) if content else ""
    return {
        "url": resp.get("final_url") or "",
        "status": resp.get("status_code"),
        "headers": {k.lower(): v for k, v in (resp.get("headers") or {}).items()},
        "cookies": resp.get("cookies") or {},
        "html": html,
        "title": resp.get("title") or "",
        "meta": meta,
        "script_src": SCRIPT_SRC_RE.findall(html),
        "scripts": "\n".join(INLINE_SCRIPT_RE.findall(html))[:300_000],
        "favicon": str(favicon_hash) if favicon_hash is not None else "",
        "js": {},
        "dom": {},
        "urls": [],
        "xhr_urls": [],
    }


def signals_from_capture(cap: dict, fallback_resp: dict | None = None) -> dict:
    """Build signals from a traffic.capture() result (all browser packets)."""
    packets = cap.get("packets") or []
    docs = [p for p in packets if p.get("type") == "document"]
    main = docs[-1] if docs else {}

    cookies = {}
    for p in packets:
        sc = p.get("headers", {}).get("set-cookie", "")
        for part in sc.split("\n") if "\n" in sc else [sc]:
            nv = part.split(";", 1)[0]
            if "=" in nv:
                k, v = nv.split("=", 1)
                cookies.setdefault(k.strip(), v.strip())

    html = cap.get("html") or (main.get("body") if main else "")
    resp = fallback_resp or {}
    base = signals_from_response(
        {
            "final_url": cap.get("final_url") or resp.get("final_url"),
            "status_code": main.get("status") or resp.get("status_code"),
            "headers": main.get("headers") or resp.get("headers") or {},
            "cookies": cookies or resp.get("cookies") or {},
            "html": html or resp.get("html") or "",
            "title": cap.get("title") or resp.get("title") or "",
        },
        cap.get("favicon_hash"),
    )
    base["script_src"] = sorted(
        set(base["script_src"]) | set(cap.get("script_src") or [])
    )
    base["js"] = cap.get("js") or {}
    base["dom"] = cap.get("dom") or {}
    base["urls"] = [p["url"] for p in packets]
    base["xhr_urls"] = [
        p["url"] for p in packets if p.get("type") in ("xhr", "fetch")
    ]
    base["title"] = cap.get("title") or base["title"]
    return base


# ---------------- matching ----------------

def _match_map(pmap: dict, data: dict, field: str, evidence: list):
    """For {key: [patterns]} fields; key is a regex matched against data keys."""
    score, version = 0, None
    for key_pat, patterns in pmap.items():
        key_re = re.compile(key_pat, re.I)
        matched_key = next((k for k in data if key_re.search(k)), None)
        if matched_key is None:
            continue
        value = data.get(matched_key)
        value = "" if value is None else str(value)
        for p in patterns:
            hit = p.search(value)
            if hit:
                score += hit["confidence"]
                version = version or hit["version"]
                evidence.append(
                    {"field": field, "key": matched_key, "pattern": p.raw}
                )
                break
    return score, version


def _match_list(patterns: list, text, field: str, evidence: list):
    score, version = 0, None
    if isinstance(text, list):
        text = "\n".join(text)
    if not text:
        return 0, None
    for p in patterns:
        hit = p.search(text)
        if hit:
            score += hit["confidence"]
            version = version or hit["version"]
            evidence.append({"field": field, "pattern": p.raw})
    return score, version


def evaluate(rule: dict, signals: dict) -> dict | None:
    """Passive evaluation of one rule. Returns hit dict or None."""
    evidence, score, version = [], 0, None

    for field, pmap in (
        ("headers", rule["headers"]),
        ("cookies", rule["cookies"]),
        ("meta", rule["meta"]),
        ("js", rule["js"]),
    ):
        s, v = _match_map(pmap, signals.get(field) or {}, field, evidence)
        score += s
        version = version or v

    for field, key in (
        ("html", "html"),
        ("scriptSrc", "script_src"),
        ("scripts", "scripts"),
    ):
        s, v = _match_list(rule[field], signals.get(key), field, evidence)
        score += s
        version = version or v

    # url patterns match final URL and every request URL the page triggered;
    # xhr patterns match only XHR/fetch request URLs
    url_blob = "\n".join([signals.get("url") or ""] + (signals.get("urls") or []))
    s, v = _match_list(rule["url"], url_blob, "url", evidence)
    score += s
    version = version or v
    s, v = _match_list(
        rule["xhr"], "\n".join(signals.get("xhr_urls") or []), "xhr", evidence
    )
    score += s
    version = version or v

    for sel, cond in rule["dom"].items():
        d = signals["dom"].get(sel)
        if not d or not d.get("exists"):
            continue
        ok = True
        for sub, pats in _pmap(cond.get("attributes", {})).items() if isinstance(cond, dict) else []:
            if not any(p.search(str(d.get("attrs", {}).get(sub, ""))) for p in pats):
                ok = False
        if isinstance(cond, dict) and cond.get("text"):
            ok = ok and any(
                p.search(d.get("text") or "") for p in _plist(cond["text"])
            )
        if ok:
            score += 100
            evidence.append({"field": "dom", "key": sel, "pattern": str(cond)})

    if rule["favicon"] and signals.get("favicon") in rule["favicon"]:
        score += 100
        evidence.append(
            {"field": "favicon", "key": "mmh3", "pattern": signals["favicon"]}
        )

    if not evidence:
        return None
    return {
        "name": rule["name"],
        "category": rule.get("category", "other"),
        "website": rule.get("website"),
        "version": version,
        "score": score,
        "confidence": "confirmed" if score >= CONFIRMED else "possible",
        "evidence": evidence,
    }


def match(signals: dict, rules: list | None = None) -> dict:
    """Returns {hits: [hit], candidates: [rule]} — candidates are every rule
    that defines a probe path (active probing is the caller's choice)."""
    rules = rules if rules is not None else load_rules()
    hits = [h for rule in rules if (h := evaluate(rule, signals))]
    candidates = [r for r in rules if r["probe"]]
    return {"hits": hits, "candidates": candidates}


def evaluate_probe(rule: dict, body: str) -> dict | None:
    """Active-probe evaluation: patterns matched against probed path body."""
    for path, patterns in rule["probe"].items():
        for p in patterns:
            hit = p.search(body or "")
            if hit:
                return {
                    "name": rule["name"],
                    "category": rule.get("category", "other"),
                    "website": rule.get("website"),
                    "version": hit["version"],
                    "score": 100,
                    "confidence": "confirmed",
                    "evidence": [
                        {"field": "probe", "key": path, "pattern": p.raw}
                    ],
                }
    return None


def postprocess(hits: list) -> list:
    """Apply implies / excludes / dedupe; sort confirmed first."""
    by_name = {}
    for h in hits:
        cur = by_name.get(h["name"])
        if not cur or h["score"] > cur["score"]:
            by_name[h["name"]] = h
    detected = set(by_name)

    rules = {r["name"]: r for r in load_rules()}
    for name in list(detected):
        for imp in rules.get(name, {}).get("implies", []):
            imp = imp.split("\\;")[0]
            if imp not in detected:
                by_name[imp] = {
                    "name": imp,
                    "category": rules.get(imp, {}).get("category", "implied"),
                    "version": None,
                    "score": 0,
                    "confidence": "implied",
                    "evidence": [{"field": "implies", "key": name, "pattern": ""}],
                }
                detected.add(imp)

    for name in list(detected):
        for exc in rules.get(name, {}).get("excludes", []):
            exc = exc.split("\\;")[0]
            detected.discard(exc)
            by_name.pop(exc, None)

    out = sorted(by_name.values(), key=lambda h: -h["score"])
    return out
