import os, sys, json
os.environ["SCAN_DB_URL"] = "postgres://scan:Sc4n197932c3f59a7850@127.0.0.1:5432/scan"
sys.path.insert(0, "/opt/scan")
from app import store

conn = store._conn()
# suspicious rows from scan 12
sus = {
    608: ["Jenkins", "Ubuntu", "Java"],
    614: ["Phoenix Cart", "Nuxt.js", "Pinia", "Tencent Waterproof Wall"],
    619: ["Magento", "MySQL", "PHP", "Angular", "Zone.js", "Node.js"],
    599: ["Spring", "Java", "OWL Carousel", "Alibaba Cloud CDN"],
    606: ["Vue.js", "Vite", "Swiper", "Animate.css", "Baidu Analytics (\u767e\u5ea6\u7edf\u8ba1)"],
    591: ["Vue.js", "PHP", "Cloudflare Browser Insights", "HTTP/3"],
    609: ["Ant Design", "React", "Microsoft HTTPAPI", "Azure", "jQuery"],
}
for rid, want in sus.items():
    r = conn.execute(
        "SELECT url, status_code, fingerprints FROM results WHERE id=?", (rid,)
    ).fetchone()
    print(f"\n######## #{rid} {r['url']}")
    for f in json.loads(r["fingerprints"] or "[]"):
        if f["name"] not in want:
            continue
        print(f"  [{f['name']}] score={f.get('score')} conf={f.get('confidence')}")
        for e in (f.get("evidence") or [])[:4]:
            print(f"     {e.get('field')}:{e.get('key') or ''} <- {e.get('pattern')}")
conn.close()
