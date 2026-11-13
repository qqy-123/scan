"""Convert the enthec/webappanalyzer technology DB into our rules format.

Usage:
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/enthec/webappanalyzer.git /tmp/wappalyzer
    cd /tmp/wappalyzer && git sparse-checkout set src/technologies
    python tools/convert_wappalyzer.py /tmp/wappalyzer/src > rules/0_wappalyzer.json

Field mapping:
  headers/cookies/meta/js     -> same shape {key: [patterns]}
  html/scriptSrc/scripts/url/xhr -> same (list)
  text                        -> appended to html (visible-text patterns)
  dom (list or dict)          -> dict {selector: cond}; css selectors merged in
  probe                       -> same {path: [patterns]}
  implies/excludes/requires   -> kept verbatim (postprocess parses them)
  requiresCategory            -> category ids -> names via categories.json
  cats[0]                     -> category name via categories.json
  cpe/website                 -> kept
  dropped: icon/description/saas/oss/pricing/dns/certIssuer

PATTERN_PATCHES: hand-curated fixes for upstream patterns that false-
positive in the wild. Each entry: (tech name, field, map key or None,
pattern substring, action, value). Applied during conversion so they
survive regeneration; keep the list short and evidence-driven.
"""

import json
import sys
from pathlib import Path


def _lst(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# (name, field, key|None, pattern-substring, "drop"|"confidence", value)
PATTERN_PATCHES = [
    # generic cookie/header names that substring-hit on unrelated sites
    # (anchored fullmatch in the engine covers most; keep belt+braces for
    # names that are plain words in every app)
    ("Phoenix Cart", "cookies", "ceid", "", "confidence", 30),
    # any page loading a .php URL (third-party widgets included) is not a
    # PHP stack — needs PHPSESSID/X-Powered-By/.php-in-body corroboration
    ("PHP", "url", None, "\\.php(?:$|\\?)", "confidence", 50),
]


def _patch_patterns(name, field, values):
    """Rewrite/drop patterns in a list field per PATTERN_PATCHES."""
    out = []
    for p in values:
        raw = p if isinstance(p, str) else str(p)
        for (n, f, key, sub, act, val) in PATTERN_PATCHES:
            if n != name or f != field or key is not None:
                continue
            if sub and sub not in raw:
                continue
            if act == "drop":
                raw = None
            elif act == "confidence":
                raw = raw.split("\\;")[0] + f"\\;confidence:{val}"
            break
        if raw is not None:
            out.append(raw)
    return out


def _patch_map(name, field, d):
    out = {}
    for k, v in d.items():
        keep = True
        for (n, f, key, sub, act, val) in PATTERN_PATCHES:
            if n != name or f != field or key != k:
                continue
            if act == "drop":
                keep = False
            elif act == "confidence":
                v = [x.split("\\;")[0] + f"\\;confidence:{val}"
                     for x in _lst(v)]
            break
        if keep:
            out[k] = v
    return out


def main(src_dir: str):
    src = Path(src_dir)
    cats = {}
    cat_file = src / "categories.json"
    if cat_file.exists():
        cats = {int(k): v["name"]
                for k, v in json.loads(cat_file.read_text(encoding="utf-8")).items()}

    out = []
    for f in sorted((src / "technologies").glob("*.json")):
        for name, t in json.loads(f.read_text(encoding="utf-8")).items():
            r = {"name": name,
                 "category": cats.get((t.get("cats") or [0])[0], "other")}
            if t.get("website"):
                r["website"] = t["website"]
            if t.get("cpe"):
                r["cpe"] = t["cpe"]

            for field in ("headers", "cookies", "meta", "js", "probe"):
                if t.get(field):
                    r[field] = _patch_map(
                        name, field,
                        {k: _lst(v) for k, v in t[field].items()})

            for field in ("html", "scriptSrc", "scripts", "url", "xhr",
                          "robots"):
                if t.get(field):
                    r[field] = _patch_patterns(name, field, _lst(t[field]))

            if t.get("text"):
                r.setdefault("html", []).extend(_lst(t["text"]))

            dom = {}
            for item in _lst(t.get("dom")):
                if isinstance(item, str):
                    dom[item] = {}
                elif isinstance(item, dict):
                    dom.update(item)
            if isinstance(t.get("dom"), dict):
                dom.update(t["dom"])
            for sel in _lst(t.get("css")):
                if isinstance(sel, str):
                    dom.setdefault(sel, {})
            if dom:
                r["dom"] = dom

            for field in ("implies", "excludes", "requires"):
                if t.get(field):
                    r[field] = _lst(t[field])
            if t.get("requiresCategory"):
                r["requiresCategory"] = [
                    cats.get(c if isinstance(c, int) else -1, str(c))
                    for c in _lst(t["requiresCategory"])
                ]

            # skip empty rules (only carried requires/dns we can't use)
            if any(r.get(f) for f in ("headers", "cookies", "meta", "js",
                                      "html", "scriptSrc", "scripts", "url",
                                      "xhr", "dom", "probe")):
                out.append(r)

    dest = sys.argv[2] if len(sys.argv) > 2 else "-"
    if dest == "-":
        sys.stdout.reconfigure(encoding="utf-8")
        json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    else:
        Path(dest).write_text(
            json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"# converted {len(out)} rules", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
