#!/bin/bash
echo "=== ip6 route ==="; ip -6 route 2>/dev/null | head -5
echo "=== ip4 route ==="; ip -4 route | head -5
for u in "https://cg51.com" "http://souqappfree.top" "https://armed.czeemiefc.cc" "https://76.azureedge.net" "https://www.gstatic.com/generate_204"; do
  v4=$(curl -4 -s -o /dev/null -w "%{http_code}/%{time_total}s" --max-time 10 "$u" 2>&1)
  v6=$(curl -6 -s -o /dev/null -w "%{http_code}/%{time_total}s" --max-time 10 "$u" 2>&1)
  echo "v4[$v4] v6[$v6]  $u"
done
echo "=== python httpx v4-only test ==="
cd /opt/scan && .venv/bin/python - <<'PYEOF'
import httpx, asyncio
async def t():
    tr = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
    c = httpx.AsyncClient(transport=tr, verify=False, timeout=8,
                          follow_redirects=True)
    for u in ("https://cg51.com", "http://souqappfree.top",
              "https://armed.czeemiefc.cc"):
        try:
            r = await c.get(u)
            print("v4only", r.status_code, u)
        except Exception as e:
            print("v4only", type(e).__name__, u)
    await c.aclose()
asyncio.run(t())
PYEOF
