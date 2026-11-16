import asyncio
import json
import os
import sys
sys.path.insert(0, '.')
os.environ['SCAN_DB_URL'] = (
    'postgres://scan:' + open('/root/.scan_dbpw').read().strip()
    + '@127.0.0.1:5432/scan')
from app import store, pipeline

scan = store.get_scan(1)
targets = store.list_targets(scan["project_id"])
tmap = {t["id"]: t for t in targets}
dead = store.dead_results(1)
inmap = sum(1 for d in dead if d["target_id"] in tmap)
print(f"dead={len(dead)} in-tmap={inmap}", flush=True)

# instrument: what does confirm() see? patch probe.fetch to log verdicts
import app.probe as probe
orig = probe.fetch
seen = {"alive": 0, "dead": 0, "errs": {}}


async def spy(client, url, retry=True):
    r = await orig(client, url, retry)
    if r["alive"]:
        seen["alive"] += 1
    else:
        seen["dead"] += 1
        k = (r["error"] or "?").split(":")[0]
        seen["errs"][k] = seen["errs"].get(k, 0) + 1
    return r


probe.fetch = spy
n = asyncio.run(pipeline._reverify_dead(
    scan, json.loads(scan["options"]), store.get_settings(), tmap))
print("revived:", n)
print("probe verdicts:", seen)
