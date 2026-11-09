import asyncio
import hashlib
import hmac
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from pydantic import BaseModel

from . import fingerprint as fp
from . import exposure, ingest, learn, pipeline, store, traffic

BASE = Path(__file__).resolve().parent.parent
DIST = BASE / "frontend" / "dist"

app = FastAPI(title="scan")


# ---------------- auth ----------------

def _expected_token() -> str:
    """Session token bound to the current password hash: changing the
    password invalidates every issued token."""
    return hmac.new(
        store.auth_secret().encode(), store.password_hash().encode(),
        hashlib.sha256,
    ).hexdigest()


@app.middleware("http")
async def auth_gate(request: Request, call_next):
    p = request.url.path
    if p.startswith("/api/") and p != "/api/login":
        tok = request.headers.get("authorization", "")
        tok = tok[7:] if tok.lower().startswith("bearer ") else tok
        if not hmac.compare_digest(tok, _expected_token()):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


class LoginIn(BaseModel):
    password: str


@app.post("/api/login")
def login(body: LoginIn):
    if not store.verify_password(body.password):
        raise HTTPException(401, "密码错误")
    return {"token": _expected_token()}


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


class ProjectUpdate(BaseModel):
    name: str
    description: str = ""


@app.put("/api/projects/{pid}")
def update_project(pid: int, body: ProjectUpdate):
    if not store.get_project(pid):
        raise HTTPException(404)
    if not body.name.strip():
        raise HTTPException(400, "name required")
    store.update_project(pid, body.name.strip(), body.description)
    return {"ok": True}


@app.delete("/api/projects/{pid}")
def delete_project(pid: int):
    if not store.get_project(pid):
        raise HTTPException(404)
    store.delete_project(pid)
    return {"ok": True}


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


class TargetUpdate(BaseModel):
    url: str


@app.put("/api/targets/{tid}")
def update_target(tid: int, body: TargetUpdate):
    url = ingest.normalize(body.url)
    if not url:
        raise HTTPException(400, "invalid url")
    res = store.update_target(tid, url)
    if not res["ok"]:
        raise HTTPException(409 if res["error"] == "duplicate" else 404,
                            "URL 已存在于该项目" if res["error"] == "duplicate" else "not found")
    return {"ok": True}


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


# ---------------- exposure (暴露面测绘) ----------------

class ExposureIn(BaseModel):
    scope: str = "alive"                 # alive | all
    kinds: list = ["js", "dir"]          # js: JS接口提取  dir: 目录爆破
    auto_deep: bool = True               # 完成后自动深扫(截图+指纹)
    deep_limit: int = 200                # 自动深扫的URL上限


@app.post("/api/projects/{pid}/exposure")
async def create_exposure(pid: int, body: ExposureIn):
    if not store.get_project(pid):
        raise HTTPException(404)
    total = len(
        store.alive_targets(pid)
        if body.scope == "alive"
        else store.list_targets(pid)
    )
    if total == 0:
        raise HTTPException(400, "no targets to scan")
    running = [r for r in store.list_exposure_runs(pid) if r["status"] == "running"]
    if running:
        raise HTTPException(409, "an exposure scan is already running")
    rid = store.create_exposure_run(pid, body.model_dump(), total)
    asyncio.create_task(exposure.run_exposure(rid))
    return {"id": rid, "total": total}


@app.get("/api/exposure")
def list_exposure_all():
    return store.list_exposure_runs()


# NOTE: must precede /api/exposure/{rid} or "stats" is parsed as an int rid
@app.get("/api/exposure/stats")
def exposure_stats():
    return store.exposure_stats()


@app.get("/api/projects/{pid}/exposure")
def list_exposure(pid: int):
    return store.list_exposure_runs(pid)


@app.get("/api/exposure/{rid}")
def get_exposure(rid: int):
    run = store.get_exposure_run(rid)
    if not run:
        raise HTTPException(404)
    run["options"] = json.loads(run["options"] or "{}")
    run["results"] = store.list_exposure_results(rid)
    return run


class DeepScanIn(BaseModel):
    limit: int = 120                    # max discovered urls to deep-scan


@app.post("/api/exposure/{rid}/deepscan")
async def deep_scan_exposure(rid: int, body: DeepScanIn = None):
    run = store.get_exposure_run(rid)
    if not run:
        raise HTTPException(404)
    if run["status"] != "done":
        raise HTTPException(409, "exposure scan is still running")
    if run.get("deep_status") == "running":
        raise HTTPException(409, "deep scan is already running")
    limit = min(max(1, (body.limit if body else 120)), 1000)
    asyncio.create_task(exposure.run_deep_scan(rid, limit))
    return {"ok": True}


@app.delete("/api/exposure/{rid}")
def delete_exposure(rid: int):
    if not store.get_exposure_run(rid):
        raise HTTPException(404)
    store.delete_exposure_run(rid)
    return {"ok": True}


# ---------------- settings / system ----------------

def _mask_keys(cfg: dict) -> dict:
    """Mask *_key values for display — real keys never leave the server."""
    out = dict(cfg)
    for k in out:
        if k.endswith("_key") and out[k]:
            s = str(out[k])
            out[k] = "****" + s[-4:] if len(s) > 4 else "****"
    return out


@app.get("/api/settings")
def get_settings():
    return _mask_keys(store.get_settings())


@app.put("/api/settings")
def update_settings(body: dict):
    body = dict(body)
    new_pw = body.pop("new_password", None)
    if new_pw is not None:
        new_pw = str(new_pw).strip()
        if len(new_pw) < 6:
            raise HTTPException(400, "密码至少 6 位")
        store.set_password(new_pw)  # invalidates all issued tokens
    # masked or blank key display values are not written back — only real
    # new keys (an empty *_key can never be a deliberate clear here)
    body = {k: v for k, v in body.items()
            if not (k.endswith("_key")
                    and ("****" in str(v) or not str(v).strip()))}
    store.set_settings(body)
    return _mask_keys(store.get_settings())


@app.get("/api/system")
def system_info():
    import platform
    import sys

    rules = fp.load_rules()
    shots = list(traffic.SHOT_DIR.glob("*.png")) if traffic.SHOT_DIR.exists() else []
    shot_mb = sum(f.stat().st_size for f in shots) / 1048576
    if store.PG:
        cfg = store._PG_CFG
        db_label = f"postgresql://{cfg['host']}:{cfg['port']}/{cfg['dbname']}"
        db_mb = store.pg_size_mb()
    else:
        db_label = "sqlite"
        db_mb = (
            store.DB_PATH.stat().st_size / 1048576
            if store.DB_PATH.exists() else 0
        )
    browser = traffic._browser
    return {
        "version": "0.5.0",
        "python": sys.version.split()[0],
        "platform": platform.system(),
        "db_engine": db_label,
        "db_size_mb": round(db_mb, 1),
        "screenshots": len(shots),
        "screenshots_mb": round(shot_mb, 1),
        "rules_total": len(rules),
        "rules_custom": len(learn.load_custom()),
        "rules_disabled": len(learn.disabled_names()),
        "browser": "running" if browser and browser.is_connected() else "idle",
    }


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

    @app.api_route("/assets/{path:path}", methods=["GET", "HEAD"])
    def assets_cached(path: str):
        # hash-named build assets: safe to cache forever
        f = (DIST / "assets" / path).resolve()
        if not f.is_file() or (DIST / "assets").resolve() not in f.parents:
            raise HTTPException(404)
        return FileResponse(
            f,
            headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )

    @app.api_route("/{path:path}", methods=["GET", "HEAD"])
    def spa(path: str):
        f = (DIST / path).resolve()
        if path and f.is_file() and DIST.resolve() in f.parents:
            return FileResponse(f)
        # index.html must never be cached — it pins the asset filenames
        return FileResponse(
            DIST / "index.html",
            headers={"Cache-Control": "no-cache"},
        )
