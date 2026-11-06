import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import fingerprint as fp
from . import ingest, learn, pipeline, screenshot, store

BASE = Path(__file__).resolve().parent.parent
DIST = BASE / "frontend" / "dist"

app = FastAPI(title="scan")


@app.on_event("startup")
def _startup():
    store.init()
    screenshot.SHOT_DIR.mkdir(exist_ok=True)


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


# ---------------- fingerprint learning ----------------

class LearnIn(BaseModel):
    url: str


@app.post("/api/learn/preview")
async def learn_preview(body: LearnIn):
    """Fetch a site and extract candidate fingerprint features."""
    return await learn.extract(body.url.strip())


SIGNAL_FIELDS = ("headers", "cookies", "meta", "js", "html", "scriptSrc",
                 "scripts", "url", "favicon", "dom", "probe")


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


@app.delete("/api/rules/custom/{name}")
def delete_custom_rule(name: str):
    if not learn.delete_custom(name):
        raise HTTPException(404)
    return {"ok": True}


# ---------------- static ----------------

@app.get("/screenshots/{name}")
def shot(name: str):
    p = (screenshot.SHOT_DIR / name).resolve()
    if p.parent != screenshot.SHOT_DIR.resolve() or not p.exists():
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
