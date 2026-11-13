"""Run on server: generate valid token, then playwright smoke test."""
import os, sys, hmac, hashlib, asyncio
sys.path.insert(0, "/opt/scan")
os.environ.setdefault("SCAN_DB_URL",
    "postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan")
import app.store as store

tok = hmac.new(store.auth_secret().encode(),
               store.password_hash().encode(),
               hashlib.sha256).hexdigest()
sys.argv = ["_smoke.py", tok]
exec(open("/tmp/_smoke.py").read())
