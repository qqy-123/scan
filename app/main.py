import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import fingerprint as fp
from . import ingest, learn, pipeline, store, traffic

BASE = Path(__file__).resolve().parent.parent
DIST = BASE / "frontend" / "dist"

app = FastAPI(title="scan")


@app.on_event("startup")
def _startup():
    store.init()
    traffic.SHOT_DIR.mkdir(exist_ok=True)


# ---------------- projects ----------------

class ProjectIn(BaseModel):
    name: str
    description: str = ""


@app.post("/api/projects")
def create_project(body: ProjectIn):
    if not body.name.strip():
        raise HTTPException(400, "name required")
    pid = store.create_project(body.name.strip(), body.description)
    return {"id": pid}


@app.get("/api/projects")
def list_projects():
    return store.list_projects()


@app.get("/api/projects/{pid}")
def get_project(pid: int):
    p = store.get_project(pid)
    if not p:
        raise HTTPException(404)
    p["targets"] = store.list_targets(pid)
    p["latest"] = {str(k): v for k, v in store.latest_results_by_target(pid).items()}
    p["scans"] = store.list_scans(pid)
    p["running"] = store.running_scan(pid)
    return p


# ---------------- targets ----------------

class TargetsIn(BaseModel):
    urls: str


@app.post("/api/projects/{pid}/targets")
def add_targets_text(pid: int, body: TargetsIn):
    if not store.get_project(pid):
        raise HTTPException(404)
    urls = ingest.from_text(body.urls)
    res = store.add_targets(pid, urls)
    res["parsed"] = len(urls)
    return res


@app.post("/api/projects/{pid}/targets/upload")
async def add_targets_file(pid: int, file: UploadFile):
    if not store.get_project(pid):
        raise HTTPException(404)
    data = await file.read()
    if file.filename.lower().endswith((".xlsx", ".xlsm")):
        urls = ingest.from_xlsx(data)
    else:
        urls = ingest.from_text(data.decode("utf-8", "ignore"))
    res = store.add_targets(pid, urls)
    res["parsed"] = len(urls)
    return res


@app.delete("/api/targets/{tid}")
def delete_target(tid: int):
    store.delete_target(tid)
    return {"ok": True}


# ---------------- scans ----------------

class ScanIn(BaseModel):
    scope: str = "all"            # all | alive (二次扫描: 仅对存活目标重扫)
    active_probe: bool = True     # 主动探测开关
    screenshot: bool = True
    concurrency: int = 50


@app.post("/api/projects/{pid}/scans")
async def create_scan(pid: int, body: ScanIn):
    if not store.get_project(pid):
        raise HTTPException(404)
    if store.running_scan(pid):
        raise HTTPException(409, "a scan is already running for this project")
    if body.scope == "alive":
        total = len(store.alive_targets(pid))
    else:
        total = len(store.list_targets(pid))
    if total == 0:
        raise HTTPException(400, "no targets to scan")
    sid = store.create_scan(
        pid,
        kind="rescan" if body.scope == "alive" else "full",
        options=body.model_dump(),
        total=total,
    )
    asyncio.create_task(pipeline.run_scan(sid))
    return {"id": sid, "total": total}


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    s = store.get_scan(sid)
    if not s:
        raise HTTPException(404)
    s["options"] = json.loads(s["options"] or "{}")
    s["results"] = store.list_results(sid)
    return s


@app.get("/api/scans/{sid}/stats")
def scan_stats(sid: int):
    results = store.list_results(sid)
    cat_count, fp_count = {}, {}
    for r in results:
        for f in json.loads(r["fingerprints"] or "[]"):
            cat_count[f["category"]] = cat_count.get(f["category"], 0) + 1
            fp_count[f["name"]] = fp_count.get(f["name"], 0) + 1
    return {
        "total": len(results),
        "alive": sum(1 for r in results if r["alive"]),
        "by_category": cat_count,
        "top_fingerprints": sorted(fp_count.items(), key=lambda x: -x[1])[:20],
    }


# ---------------- results ----------------

@app.get("/api/results/{rid}")
def get_result(rid: int):
    r = store.get_result(rid)
    if not r:
        raise HTTPException(404)
    r["fingerprints"] = json.loads(r["fingerprints"] or "[]")
    return r


@app.get("/api/rules")
def rules_summary():
    rules = fp.load_rules()
    return {"count": len(rules), "names": sorted({r["name"] for r in rules})}


# ---------------- overview / dashboard ----------------

@app.get("/api/overview")
def overview():
    d = store.overview()
    fp_names, fp_cats = {}, {}
    for row in d.pop("fp_rows"):
        try:
            for f in json.loads(row):
                fp_names[f["name"]] = fp_names.get(f["name"], 0) + 1
                fp_cats[f["name"]] = f["category"]
        except Exception:
            pass
    top = sorted(fp_names.items(), key=lambda x: -x[1])[:15]
    d["top_fingerprints"] = [
        {"name": n, "count": c, "category": fp_cats.get(n, "")} for n, c in top
    ]
    d["rules_count"] = len(fp.load_rules())
    return d


# ---------------- fingerprint learning ----------------

class LearnIn(BaseModel):
    url: str


@app.post("/api/learn/preview")
async def learn_preview(body: LearnIn):
    """Fetch a site and extract candidate fingerprint features."""
    return await learn.extract(body.url.strip())


SIGNAL_FIELDS = ("headers", "cookies", "meta", "js", "html", "scriptSrc",
                 "scripts", "url", "xhr", "css", "robots", "favicon",
                 "dom", "probe")


@app.get("/api/rules/detail")
def rules_detail():
    out = []
    for r in fp.load_rules():
        signals = {f: (list(r[f].keys()) if isinstance(r[f], dict) else len(r[f]))
                   for f in SIGNAL_FIELDS if r.get(f)}
        out.append({
            "name": r["name"],
            "category": r.get("category", "other"),
            "file": r.get("_file"),
            "signals": signals,
            "implies": r.get("implies", []),
            "disabled": False,
        })
    # disabled rules don't reach the engine; list them so they can be re-enabled
    present = {r["name"] for r in out}
    for name in learn.disabled_names() - present:
        out.append({
            "name": name,
            "category": "-",
            "file": "custom.json",
            "signals": {},
            "implies": [],
            "disabled": True,
        })
    return out


class CustomRuleIn(BaseModel):
    name: str
    category: str = "自定义"
    selected: dict


@app.post("/api/rules/custom")
def save_custom_rule(body: CustomRuleIn):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name required")
    rule = learn.build_rule(name, body.selected, body.category.strip() or "自定义")
    if not any(k in rule for k in SIGNAL_FIELDS):
        raise HTTPException(400, "select at least one signal")
    learn.save_custom(rule)
    return {"ok": True, "rule": rule}


@app.get("/api/rules/raw/{name}")
def rule_raw(name: str):
    """Raw editable JSON of a rule + where it comes from.

    Disabled rules are still returned for editing: prefer the custom.json
    entry when it carries signal fields; otherwise fall back to the built-in
    definition so its content can be edited (and re-enabled)."""
    custom = next(
        (r for r in learn.load_custom() if r.get("name") == name), None
    )
    disabled = bool(custom and custom.get("_disabled"))
    if custom and any(k in custom for k in SIGNAL_FIELDS):
        return {
            "name": name,
            "disabled": disabled,
            "file": "custom.json",
            "rule": custom,
        }
    for r in fp.load_rules():
        if r["name"] == name:
            return {
                "name": name,
                "disabled": False,
                "file": r.get("_file"),
                "rule": fp.raw_of(r),
            }
    raw, fname = learn.builtin_raw(name)
    if raw:
        raw = dict(raw)
        return {"name": name, "disabled": disabled, "file": fname, "rule": raw}
    if custom:
        return {"name": name, "disabled": disabled, "file": "custom.json", "rule": custom}
    raise HTTPException(404)


class RawRuleIn(BaseModel):
    rule: dict


@app.put("/api/rules/custom")
def update_custom_rule(body: RawRuleIn):
    """Save an edited rule into custom.json — overrides same-name built-in."""
    rule = body.rule
    name = (rule.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "rule.name required")
    if not any(k in rule for k in SIGNAL_FIELDS) and not rule.get("_disabled"):
        raise HTTPException(400, "rule must define at least one signal")
    rule.pop("_file", None)
    learn.save_custom(rule)
    return {"ok": True}


@app.post("/api/rules/{name}/disable")
def disable_rule(name: str):
    learn.set_disabled(name, True)
    return {"ok": True}


@app.post("/api/rules/{name}/enable")
def enable_rule(name: str):
    learn.set_disabled(name, False)
    return {"ok": True}


@app.delete("/api/rules/custom/{name}")
def delete_custom_rule(name: str):
    if not learn.delete_custom(name):
        raise HTTPException(404)
    return {"ok": True}


# ---------------- static ----------------

@app.get("/screenshots/{name}")
def shot(name: str):
    p = (traffic.SHOT_DIR / name).resolve()
    if p.parent != traffic.SHOT_DIR.resolve() or not p.exists():
        raise HTTPException(404)
    return FileResponse(p)


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}")
    def spa(path: str):
        f = DIST / path
        if path and f.is_file():
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
