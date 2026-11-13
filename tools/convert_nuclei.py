"""Convert nuclei-templates tech-detection YAML into our rules format.

Usage:
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/projectdiscovery/nuclei-templates.git /tmp/nuclei
    cd /tmp/nuclei && git sparse-checkout set http/technologies http/miscellaneous
    python tools/convert_nuclei.py /tmp/nuclei > rules/nuclei_tech.json

Convertible subset — single GET request, word/regex/status matchers only:
  path {{BaseURL}}[/]  -> probe "/" (evaluated against the already-fetched
                          homepage response, zero extra requests); when the
                          whole template is body-words under OR, emitted as
                          passive `html` patterns instead — free detection
                          even with active_probe disabled
  deep paths           -> probe path entries (probe_root: paths are
                          site-root-relative in nuclei semantics)
  matchers-condition: and  -> {"all"|"groups"|"headers"|"status"} clauses
                          that must all pass (AND-of-ORs keeps each word
                          matcher as its own `groups` entry)
  or (default)         -> merged "any" body patterns; header/status OR
                          members are dropped — keeping them would match
                          nearly every 200 page
  word matcher         -> regex-escaped literals (engine compiles re.I)
  part: header         -> headers["_raw"]  (raw header block)
  part: server/content_type/x_cache/<hdr> -> headers[Name]

Skipped: dsl matchers, multi-request/flow, non-GET, raw requests,
variables/constants, interactsh/rand/md5 payloads, negative matchers,
status-only templates, OR templates with no body matcher.
"""

import json
import re
import sys
from pathlib import Path

import yaml

TECH_DIRS = ("http/technologies", "http/miscellaneous")

CATEGORIES = [
    (("oa", "seeyon", "weaver", "tongda", "yonyou", "landray", "kingdee",
      "泛微", "致远", "用友", "金蝶", "蓝凌"), "OA"),
    (("vpn", "sslvpn", "firewall", "gateway", "堡垒机", "bastion"), "VPN"),
    (("iot", "camera", "router", "dvr", "nvr", "printer", "hikvision",
      "dahua", "webcam", "modem", "plc", "scada", "摄像头"), "IoT设备"),
    (("waf", "fortinet", "fortiweb", "安全设备", "security-appliance"),
     "安全设备"),
    (("ci", "jenkins", "gitlab", "harbor", "nexus", "sonar", "gitea",
      "devops", "jira", "confluence"), "DevOps"),
    (("monitor", "zabbix", "grafana", "prometheus", "nagios", "skywalking"),
     "监控"),
    (("database", "phpmyadmin", "adminer", "redis", "mongo", "elastic",
      "kibana", "db"), "数据库"),
    (("panel", "admin", "console", "login", "dashboard", "webui", "管理"),
     "管理面板"),
    (("cms", "blog", "wordpress", "joomla", "drupal", "forum", "discuz",
      "shop", "ecommerce", "商城"), "CMS"),
    (("framework", "laravel", "thinkphp", "django", "spring", "rails"),
     "Web框架"),
    (("server", "nginx", "apache", "iis", "tomcat", "weblogic", "jboss",
      "jetty", "resin"), "Web服务器"),
    (("mail", "webmail", "exchange", "邮箱"), "邮箱"),
    (("storage", "minio", "oss", "nas", "backup", "网盘", "cloud-disk"),
     "存储/网盘"),
    (("cdn", "cloudflare", "waf-detect"), "CDN"),
]

_NAME_CLEAN = re.compile(
    r"\s*[-–—]?\s*(Detection|Detect|detect|Fingerprint|指纹|识别)\s*$")

# page-feature detectors, not products — pure noise in a fingerprint column
SKIP_NAMES = {
    "form", "add dom eventlistener", "sitemap", "robots.txt file",
    "robots.txt endpoint prober",
}

# parts that map to a specific response header
PART_HEADERS = {
    "server": "Server", "content_type": "Content-Type",
    "x_cache": "X-Cache", "all_headers": "_raw", "header": "_raw",
    "headers": "_raw", "raw": "_raw", "set-cookie": "Set-Cookie",
}


def _category(info: dict) -> str:
    tags = info.get("tags") or ""
    hay = f"{info.get('name', '')},{tags}".lower()
    for keys, cat in CATEGORIES:
        if any(k in hay for k in keys):
            return cat
    return "Other"


def _name(info: dict, tid: str) -> str:
    n = _NAME_CLEAN.sub("", (info.get("name") or tid).strip())
    return n.strip(" -–—") or tid


def _clean_regex(p: str) -> str:
    """Normalize upstream regexes for our engine:
    - (x|X) charwise case alternations -> single char (engine compiles
      re.I; the alternation form is the classic ReDoS shape)
    - edge .*/.*? wrappers are pure noise under unanchored search
    """
    prev = None
    while prev != p:
        prev = p
        p = re.sub(
            r"\((\w)\|(\w)\)",
            lambda m: m.group(1)
            if m.group(1).lower() == m.group(2).lower() else m.group(0),
            p)
    p = re.sub(r"^(\.\*\??)+", "", p)
    p = re.sub(r"(\.\*\??)+$", "", p)
    return p


def _pats(matcher: dict) -> list:
    """matcher -> body regexes list (word -> escaped, regex -> verbatim)."""
    out = []
    if matcher.get("type") == "word":
        for w in matcher.get("words") or []:
            if "{{" not in str(w):
                out.append(re.escape(str(w)))
    elif matcher.get("type") == "regex":
        for w in matcher.get("regex") or []:
            if "{{" not in str(w):
                cleaned = _clean_regex(str(w))
                if cleaned.strip("^$.*?"):
                    out.append(cleaned)
    return out


def _convert_matcher(m: dict, cond: dict):
    """Fold one matcher into the cond group under AND semantics."""
    part = m.get("part", "body")
    status = m.get("status") or ([m["status_code"]] if m.get("status_code") else [])
    if m.get("type") == "status" or status:
        cond.setdefault("status", [])
        cond["status"] = sorted(set(cond["status"]) | {int(s) for s in status})
        return
    pats = _pats(m)
    if not pats:
        return
    if part in PART_HEADERS:
        key = PART_HEADERS[part]
        hdr = cond.setdefault("headers", {})
        hdr.setdefault(key, [])
        hdr[key] += pats
        return
    if part != "body":
        # unknown part (e.g. a specific named header) — treat as raw headers
        hdr = cond.setdefault("headers", {})
        hdr.setdefault("_raw", [])
        hdr["_raw"] += pats
        return
    if m.get("condition") == "and":
        cond.setdefault("all", [])
        cond["all"] += pats
    elif len(pats) == 1:
        cond.setdefault("all", [])
        cond["all"] += pats
    else:
        cond.setdefault("groups", [])
        cond["groups"].append(pats)


def _ok_passive(p: str) -> bool:
    """Quality gate for patterns emitted as passive `html` (they run on
    every homepage): drop bare numbers and generic short words — e.g.
    the literal word '35' would substring-hit every page."""
    plain = re.sub(r"\\(.)", r"\1", p)
    if re.search(r"[一-鿿]", plain):
        return True
    if re.fullmatch(r"[\d.]+", plain):
        return len(plain) >= 8
    if re.fullmatch(r"[A-Za-z0-9 ]+", plain):
        return len(plain) >= 5
    return len(plain) >= 3


def convert_file(path: Path) -> list:
    try:
        d = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(d, dict):
        return []
    reqs = d.get("http")
    if not isinstance(reqs, list) or len(reqs) != 1:
        return []
    if d.get("variables") or d.get("constants") or d.get("flow"):
        return []
    r = reqs[0]
    if not isinstance(r, dict):
        return []
    if r.get("method", "GET").upper() != "GET" or r.get("raw"):
        return []
    matchers = r.get("matchers") or []
    if not matchers or any(
            m.get("type") == "dsl" or m.get("negative") or m.get("internal")
            for m in matchers):
        return []
    text = path.read_text(encoding="utf-8")
    if "interactsh" in text or "{{rand" in text or "md5(" in text:
        return []

    paths = r.get("path") or ["{{BaseURL}}"]
    paths = [re.sub(r"^\{\{BaseURL\}\}", "", str(p)) or "/" for p in paths]
    paths = [p if p.startswith("/") else "/" + p for p in paths]
    if any("{{" in p for p in paths):
        return []

    info = d.get("info") or {}
    tid = d.get("id") or path.stem
    ref = info.get("reference")
    website = ref[0] if isinstance(ref, list) and ref else None

    def _mk(name: str, html=None, probe=None) -> dict:
        rule = {"name": name, "category": _category(
            {"name": name, "tags": info.get("tags") or ""}),
            "_src": f"nuclei:{tid}"}
        if website:
            rule["website"] = website
        if html:
            rule["html"] = html
        if probe:
            rule["probe"] = probe
            rule["probe_root"] = True
        return rule

    cond_and = r.get("matchers-condition") == "and"
    if cond_and:
        cond = {}
        for m in matchers:
            _convert_matcher(m, cond)
        if not any(cond.get(k) for k in ("all", "any", "groups", "headers")):
            return []  # status-only
        name = _name(info, tid)
        if name.lower() in SKIP_NAMES:
            return []
        return [_mk(name, probe={p: cond for p in paths})]

    # OR semantics. Named matchers (FingerprintHub mega-template: each
    # `name:` is a distinct product) split into per-product rules; the
    # rest fold into one rule. Only body matchers kept — a status/header
    # OR member trivially fires on nearly every live page.
    by_matcher_name = {}
    anon, rules = [], []
    for m in matchers:
        if m.get("type") == "status":
            continue
        part = m.get("part", "body")
        if part in PART_HEADERS or part != "body":
            continue
        pats = _pats(m)
        if not pats:
            continue
        name = str(m["name"]) if m.get("name") else None
        if m.get("condition") == "and" and len(pats) > 1:
            # "all words must appear" is one OR-alternative — a distinct
            # rule carrying an all-clause, not part of any/anon pools
            rn = name or _name(info, tid)
            if rn.lower() not in SKIP_NAMES:
                rules_and = _mk(rn, probe={p: {"all": pats} for p in paths})
                rules.append(rules_and)
        elif name:
            by_matcher_name.setdefault(name, []).extend(pats)
        else:
            anon.extend(pats)

    root_only = paths == ["/"]
    # passive text signatures are weak evidence — a vendor page merely
    # *mentioning* a product (integrations/partners) must not produce a
    # confirmed hit; demote html-emitted patterns to confidence 55 so a
    # single text match lands in "possible" (低可信) tier
    demote = lambda ps: [p + "\\;confidence:55" for p in ps]
    for name, pats in by_matcher_name.items():
        pats = sorted(set(pats))
        if name.lower() in SKIP_NAMES:
            continue
        if root_only:
            keep = [p for p in pats if _ok_passive(p)]
            if keep:
                rules.append(_mk(name, html=demote(keep)))
        else:
            rules.append(_mk(name, probe={p: pats for p in paths}))
    if anon:
        name = _name(info, tid)
        if root_only:
            keep = [p for p in sorted(set(anon)) if _ok_passive(p)]
            if keep and name.lower() not in SKIP_NAMES:
                rules.append(_mk(name, html=demote(keep)))
        else:
            rules.append(
                _mk(name, probe={p: sorted(set(anon)) for p in paths}))
    return rules


def main(src: str):
    root = Path(src)
    by_name = {}
    stats = {"files": 0, "skipped": 0, "rules": 0, "paths": 0}
    for td in TECH_DIRS:
        for f in sorted(root.glob(f"{td}/**/*.yaml")):
            stats["files"] += 1
            rs = convert_file(f)
            if not rs:
                stats["skipped"] += 1
            for r in rs:
                name = r["name"]
                if name in by_name:
                    cur = by_name[name]
                    if r.get("html"):
                        cur["html"] = sorted(set(
                            (cur.get("html") or []) + r["html"]))
                    for p, c in (r.get("probe") or {}).items():
                        cur.setdefault("probe", {}).setdefault(p, c)
                    cur["probe_root"] = (cur.get("probe_root")
                                         or r.get("probe_root"))
                else:
                    by_name[name] = r
                    stats["rules"] += 1
                    stats["paths"] += len(r.get("probe") or {})

    out = list(by_name.values())
    dest = sys.argv[2] if len(sys.argv) > 2 else "-"
    if dest == "-":
        sys.stdout.reconfigure(encoding="utf-8")
        json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    else:
        Path(dest).write_text(
            json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"# {stats}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
