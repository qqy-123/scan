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
# opaque payloads never carry fingerprint markers but DO produce random
# substrings that short patterns false-match (e.g. "TdOA" inside base64)
_DATA_URI_RE = re.compile(
    r"data:[a-z0-9.+-]+/[a-z0-9.+-]*;base64,[a-z0-9+/=\s]+", re.I)
_LONG_TOKEN_RE = re.compile(r"[a-z0-9+/=_]{80,}", re.I)


def _scrub(text: str) -> str:
    """Drop opaque blobs (data URIs, long base64/hex runs) so pattern
    matching only sees human-meaningful markup/code."""
    if not text:
        return ""
    return _LONG_TOKEN_RE.sub(
        " ", _DATA_URI_RE.sub("data:", text))


class Pattern:
    __slots__ = ("raw", "regex", "confidence", "version")

    def __init__(self, raw: str):
        parts = raw.split("\\;")
        self.raw = raw
        pat = parts[0] or ".*"
        # bare short alpha tokens auto-wrap in word boundaries — otherwise
        # they substring-match inside identifiers/base64 blobs ("TdOA"
        # inside "1TdOA2LV") and false-positive constantly
        if re.fullmatch(r"[a-zA-Z]{2,6}", pat):
            pat = r"\b" + pat + r"\b"
        self.regex = re.compile(pat, re.I | re.S)
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


_TOKEN_RUN = re.compile(r"[a-zA-Z0-9_./-]{4,}")


def _pattern_tokens(raw: str) -> set:
    """Literal runs inside a pattern — a pattern can only match text that
    contains at least one of them."""
    return {m.group(0).lower() for m in _TOKEN_RUN.finditer(raw.split("\\;")[0])}


def _rule_tokens(raw: dict) -> set | None:
    """All candidate literal tokens for a rule, or None when any single
    pattern has no extractable literal (that rule must always evaluate)."""
    toks = set()

    def feed(p):
        raw = getattr(p, "raw", p)
        t = _pattern_tokens(raw)
        if not t:
            raise _TokenlessPattern
        toks.update(t)

    try:
        for f in ("headers", "cookies", "meta", "js", "probe"):
            for k, pats in (raw.get(f) or {}).items():
                feed(k)
                for p in (pats if isinstance(pats, list) else [pats]):
                    feed(p)
        for f in ("html", "scriptSrc", "scripts", "url", "xhr", "css",
                  "robots"):
            v = raw.get(f) or []
            for p in (v if isinstance(v, list) else [v]):
                feed(p)
        for sel, cond in (raw.get("dom") or {}).items():
            feed(sel)
            if isinstance(cond, dict):
                txt = cond.get("text") or []
                for pat in (txt if isinstance(txt, list) else [txt]):
                    feed(pat)
                for pats in (cond.get("attributes") or {}).values():
                    for pat in (pats if isinstance(pats, list) else [pats]):
                        feed(pat)
                for pats in (cond.get("properties") or {}).values():
                    for pat in (pats if isinstance(pats, list) else [pats]):
                        feed(pat)
    except _TokenlessPattern:
        return None
    return toks


class _TokenlessPattern(Exception):
    pass


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
    rule["_keys"] = {
        f: [(re.compile(k, re.I), pats) for k, pats in rule[f].items()]
        for f in ("headers", "cookies", "meta", "js", "probe")
    }
    rule["_tokens"] = _rule_tokens(rule)
    return rule


_cache = None


def _merge_rules(base: dict, new: dict):
    """Union-merge `new` into `base` — same-name rules across built-in
    files contribute their evidence together (wappalyzer breadth +
    curated probes/specifics), never silently replace each other."""
    for f in ("headers", "cookies", "meta", "js", "probe"):
        for k, pats in new[f].items():
            cur = base[f].setdefault(k, [])
            have = {p.raw for p in cur}
            cur += [p for p in pats if p.raw not in have]
    for f in ("html", "scriptSrc", "scripts", "url", "xhr", "css", "robots"):
        have = {p.raw for p in base[f]}
        base[f] += [p for p in new[f] if p.raw not in have]
    for sel, cond in new["dom"].items():
        base["dom"].setdefault(sel, cond)
    for f in ("favicon", "implies", "excludes"):
        base[f] = sorted(set(base[f]) | set(new[f]))
    base["cpe"] = base.get("cpe") or new.get("cpe")
    base["_keys"] = {
        f: [(re.compile(k, re.I), pats) for k, pats in base[f].items()]
        for f in ("headers", "cookies", "meta", "js", "probe")
    }
    base["_tokens"] = _rule_tokens(base)


def load_rules() -> list:
    """Load all rules. custom.json is applied LAST so user-saved rules
    override built-ins by name; entries with _disabled are skipped.
    Same-name rules across built-in files are UNION-merged."""
    global _cache
    if _cache is None:
        files = sorted(
            RULES_DIR.glob("*.json"), key=lambda f: f.name == "custom.json"
        )
        by_name = {}
        order = []
        for f in files:
            for raw in json.loads(f.read_text(encoding="utf-8")):
                name = raw.get("name")
                if not name:
                    continue
                if raw.get("_disabled"):
                    by_name.pop(name, None)
                    continue
                raw["_file"] = f.name
                if name not in by_name:
                    order.append(name)
                    by_name[name] = compile_rule(raw)
                elif f.name == "custom.json":
                    by_name[name] = compile_rule(raw)
                else:
                    _merge_rules(by_name[name], compile_rule(raw))
        _cache = [by_name[n] for n in order if n in by_name]
    return _cache


def reload():
    """Drop the compiled-rule cache so new/edited rule files take effect."""
    global _cache
    _cache = None


def raw_of(rule: dict) -> dict:
    """Reconstruct editable raw JSON from a compiled rule."""
    raw = {"name": rule["name"], "category": rule.get("category", "other")}
    if rule.get("website"):
        raw["website"] = rule["website"]
    for f in ("headers", "cookies", "meta", "js", "probe"):
        if rule.get(f):
            raw[f] = {k: [p.raw for p in pats] for k, pats in rule[f].items()}
    for f in ("html", "scriptSrc", "scripts", "url", "xhr"):
        if rule.get(f):
            raw[f] = [p.raw for p in rule[f]]
    if rule.get("favicon"):
        raw["favicon"] = rule["favicon"]
    if rule.get("dom"):
        raw["dom"] = rule["dom"]
    if rule.get("implies"):
        raw["implies"] = rule["implies"]
    if rule.get("excludes"):
        raw["excludes"] = rule["excludes"]
    raw["_file"] = rule.get("_file")
    return raw


def rule_names() -> set:
    return {r["name"] for r in load_rules()}


def js_globals() -> list:
    out = set()
    for r in load_rules():
        out.update(r["js"].keys())
    return sorted(out)


def dom_selectors() -> dict:
    """selector -> {attrs: [names], props: [names]} — what the capture
    pass must collect per selector for dom-condition evaluation."""
    out = {}
    for r in load_rules():
        for sel, cond in r["dom"].items():
            need = out.setdefault(sel, {"attrs": set(), "props": set()})
            if isinstance(cond, dict):
                need["attrs"].update((cond.get("attributes") or {}).keys())
                need["props"].update((cond.get("properties") or {}).keys())
    return {
        s: {"attrs": sorted(n["attrs"]), "props": sorted(n["props"])}
        for s, n in out.items()
    }


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
        "html": _scrub(html),
        "title": resp.get("title") or "",
        "meta": meta,
        "script_src": SCRIPT_SRC_RE.findall(html),
        "scripts": _scrub(
            "\n".join(INLINE_SCRIPT_RE.findall(html))[:300_000]),
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

def _match_map(pairs: list, data: dict, field: str, evidence: list):
    """For {key: [patterns]} fields; key is a regex matched against data keys."""
    score, version = 0, None
    for key_re, patterns in pairs:
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

    for field in ("headers", "cookies", "meta", "js"):
        s, v = _match_map(
            rule["_keys"][field], signals.get(field) or {}, field, evidence)
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
    url_blob = _scrub(
        "\n".join([signals.get("url") or ""] + (signals.get("urls") or [])))
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
        if isinstance(cond, str):
            # bare string cond = element text pattern
            ok = any(p.search(d.get("text") or "") for p in _plist(cond))
        elif isinstance(cond, dict):
            # attribute/property conditions must see the REAL value —
            # a missing attr/prop fails the condition (never vacuous pass)
            for sub, pats in _pmap(cond.get("attributes", {})).items():
                val = (d.get("attrs") or {}).get(sub)
                if val is None or not any(p.search(str(val)) for p in pats):
                    ok = False
            for sub, pats in _pmap(cond.get("properties", {})).items():
                val = (d.get("props") or {}).get(sub)
                if val is None or not any(p.search(str(val)) for p in pats):
                    ok = False
            if cond.get("text"):
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
        "cpe": rule.get("cpe"),
        "score": score,
        "confidence": "confirmed" if score >= CONFIRMED else "possible",
        "evidence": evidence,
    }


def _haystack(signals: dict) -> str:
    """Every string a pattern could conceivably hit, joined once — the
    token prefilter checks rule literals against this."""
    parts = [signals.get("html") or "", signals.get("scripts") or "",
             signals.get("url") or "", signals.get("title") or ""]
    parts += signals.get("script_src") or []
    parts += signals.get("urls") or []
    parts += signals.get("xhr_urls") or []
    for k, v in (signals.get("headers") or {}).items():
        parts += [k, str(v)]
    parts += list(signals.get("cookies") or {})
    for k, v in (signals.get("meta") or {}).items():
        parts += [k, str(v)]
    parts += list(signals.get("js") or {})
    parts += list(signals.get("dom") or {})
    return "\n".join(parts).lower()


def match(signals: dict, rules: list | None = None) -> dict:
    """Returns {hits: [hit], candidates: [rule]} — candidates are every rule
    that defines a probe path (active probing is the caller's choice)."""
    rules = rules if rules is not None else load_rules()
    hay = _haystack(signals)
    # literal-token prefilter: a rule can't match a page containing none
    # of its literals — with 7k+ rules this is the difference between
    # minutes and milliseconds per page
    pool = [r for r in rules
            if not r["_tokens"] or any(t in hay for t in r["_tokens"])]
    hits = [h for rule in pool if (h := evaluate(rule, signals))]
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


def hit_level(h: dict) -> str:
    """Trust tier for one fingerprint hit:
      confirmed — deterministic evidence (active probe path hit, favicon
                    mmh3 match, DOM selector match)
      high      — score >= 100 from corroborating passive signals
      low       — weak/partial match or implied-by-another-hit
    """
    if h.get("confidence") == "implied":
        return "low"
    fields = {e.get("field") for e in h.get("evidence") or []}
    if fields & {"probe", "favicon", "dom"}:
        return "confirmed"
    return "high" if (h.get("score") or 0) >= CONFIRMED else "low"


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
    for h in out:
        h["level"] = hit_level(h)
    return out
