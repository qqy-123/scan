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
  implies/excludes            -> kept verbatim (postprocess parses them)
  cats[0]                     -> category name via categories.json
  cpe/website                 -> kept
  dropped: icon/description/saas/oss/pricing/dns/certIssuer/requires*/
"""

import json
import sys
from pathlib import Path


def _lst(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


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
                    r[field] = {k: _lst(v) for k, v in t[field].items()}

            for field in ("html", "scriptSrc", "scripts", "url", "xhr",
                          "robots"):
                if t.get(field):
                    r[field] = _lst(t[field])

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

            for field in ("implies", "excludes"):
                if t.get(field):
                    r[field] = _lst(t[field])

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
