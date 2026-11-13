"use client";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { Chip, Modal, Spin, Tag } from "@/components/ui";
import { DataTable, type Col } from "@/components/data-table";
import { FpTags, fpLevel, parseFps, type Fp } from "@/components/fp-tags";

/* ---------- severity / tags (ported from ExposureResults.vue) ---------- */

const TAG_LABEL: Record<string, string> = {
  entry: "入口", entryq: "疑似入口", api: "API", upload: "上传", auth: "认证",
  config: "配置", debug: "调试", leak: "泄露", vuln: "漏洞", point: "攻击点",
  takeover: "接管", origin: "源站", host: "Host碰撞", port: "端口",
  sub: "子域", url: "历史URL", net: "测绘", surface: "攻击面", shot: "已截图",
};

const ENTRY_RE = /\/(admin|manage|console|backend|backstage|login|signin|portal|sso|dashboard|phpmyadmin|wp-admin)(\/|\.|\?|$)/i;
const API_RE = /\/api[\/_.-]|\.api\.|^api\.|\/v\d+(\/|$)/i;

function tagsOf(r: any): string[] {
  const t: string[] = [];
  const h = r.hint || "";
  const u = (r.url || "").toLowerCase();
  const h0 = h.split(":")[0];
  const path = u.replace(/^[a-z]+:\/\/[^/]+/i, "");
  const isPage = r.status_code != null && r.status_code < 400 &&
    r.status_code !== 204 && (r.title || r.screenshot || r.surface);
  const blockedByProt = r.protection && !r.protection.includes("bypass");
  if (isPage && !blockedByProt &&
      (h === "entry" || h === "point:admin" || h === "point:login"
       || h0 === "admin" || h0 === "auth" || ENTRY_RE.test(path)))
    t.push("entry");
  if (isPage) t.push("entryq");
  if (h0 === "api" || h === "point:api" || API_RE.test(u)) t.push("api");
  if (h0 === "upload") t.push("upload");
  if (h0 === "auth") t.push("auth");
  if (h0 === "config") t.push("config");
  if (h0 === "debug") t.push("debug");
  if (h.startsWith("leak:")) t.push("leak");
  if (h.startsWith("vuln:")) t.push("vuln");
  if (h.startsWith("point:")) t.push("point");
  if (h === "takeover") t.push("takeover");
  if (h === "origin" || r.kind === "cdn") t.push("origin");
  if (r.kind === "host") t.push("host");
  if (r.kind === "port") t.push("port");
  if (r.kind === "sub") t.push("sub");
  if (r.kind === "url") t.push("url");
  if (r.kind === "net") t.push("net");
  if (r.surface) t.push("surface");
  if (r.screenshot) t.push("shot");
  return t;
}

const HIGH_LEAK = /rsa|private|aws|github|gitlab|token|jwt|secret|password|passwd|jdbc|oss|s3|shiro|cloud|aliyun|tencent|apikey|aksk|webhook/i;
const ADMIN_URL = /(^|[\/_\-.])(admin|manager|manage|console|backend|backstage|druid|phpmyadmin|nacos|actuator|jolokia|jenkins|sonar|weblogic|grafana|kibana|harbor|rancher|zabbix|sentinel|xxl|apisix|portainer|minio|elasticsearch|swagger|dubbo|nexus|gitlab|gitea|jumpserver|waf)([\/_\-.?]|$)/i;

// 0 高危 1 中危 2 信息 3 噪声
function sevOf(r: any): number {
  const h = r.hint || "";
  const u = (r.url || "").toLowerCase();
  if (h.startsWith("vuln:")) return 0;
  if (h === "point:admin") return 0;
  if (h.startsWith("leak:") && HIGH_LEAK.test(h)) return 0;
  if (r.surface && ADMIN_URL.test(u)) return 0;
  if (h === "takeover") return 0;
  if (h === "port:critical") return 0;
  if (h === "host:vhost") return 1;
  if (h === "origin") return 1;
  if (h.startsWith("port:")) return 1;
  if (h.startsWith("point:")) return 1;
  if (h.startsWith("leak:")) return 1;
  if (r.surface) return 1;
  if (r.status_code != null || r.alive === 0) return 3;
  return 2;
}

const SEV = [
  { label: "高危", color: "red", hex: "#f87171" },
  { label: "中危", color: "orange", hex: "#fbbf24" },
  { label: "信息", color: "blue", hex: "#60a5fa" },
  { label: "噪声", color: "gray", hex: "#9aa4b8" },
];

const kindColor = (k: string) =>
  (({ js: "cyan", dir: "blue", leak: "magenta", vuln: "red", point: "volcano",
     sub: "purple", host: "volcano", cdn: "red", net: "green",
     url: "geekblue", port: "orange" }) as Record<string, string>)[k] || "default";
const kindLabel = (k: string) =>
  (({ js: "JS", dir: "DIR", leak: "泄露", vuln: "漏洞", point: "攻击点",
     sub: "子域", host: "Host碰撞", cdn: "源站", net: "测绘",
     url: "历史URL", port: "端口" }) as Record<string, string>)[k] || k;
export const statusColor = (s: number) =>
  s < 300 ? "green" : s < 400 ? "geekblue" : s === 401 || s === 403 ? "orange" : "red";
const hintColor = (h: string) =>
  (({ admin: "red", api: "geekblue", upload: "orange", auth: "purple",
     config: "gold", debug: "cyan", vuln: "red", leak: "magenta",
     point: "volcano", origin: "red", host: "volcano", entry: "purple",
     takeover: "red", critical: "red", port: "orange" }) as Record<string, string>)[String(h).split(":")[0]] || "default";

function parseCodeRange(v: string): [number, number] | null {
  v = (v || "").trim().toLowerCase();
  if (!v) return null;
  let m = v.match(/^(\d)xx$/);
  if (m) return [+m[1] * 100, +m[1] * 100 + 99];
  m = v.match(/^(\d{3})\s*-\s*(\d{3})$/);
  if (m) return [+m[1], +m[2]];
  if (/^\d{3}$/.test(v)) return [+v, +v];
  return null;
}

const sigOf = (r: any) =>
  r.status_code != null
    ? `${r.status_code}|${(r.title || "").trim().toLowerCase()}|${Math.round((r.length || 0) / 300)}`
    : null;

const INTEL_HINT_RANK: Record<string, number> = {
  "sub:alive": 0, "sub:dns": 1, "sub:ct": 2, "sub:echo": 3, "sub:js": 4,
};

/* ---------- packet viewer with fp evidence highlights ---------- */

const LV_HEX: Record<string, string> = {
  confirmed: "#4ade80", high: "#fbbf24", low: "#9aa4b8",
};
const SKIP_HL = new Set(["dom", "favicon", "implies", "js", "xhr"]);
const escHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const escRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const shortPat = (p: string) => String(p || "").split("\\;")[0].slice(0, 80);

function buildPktHtml(url: string, response: string, fps: Fp[], activeFp: string | null) {
  const reqEnd = `GET ${url} HTTP/1.1\n`.length;
  const text = `GET ${url} HTTP/1.1\n` + (response || "");
  const idx = text.indexOf("\n\n");
  const bodyStart = idx >= 0 ? idx + 2 : text.length;
  const spans: { s: number; e: number; color: string }[] = [];
  const addPat = (pat: string, region: [number, number], color: string) => {
    try {
      const rx = new RegExp(pat, "gi");
      const slice = text.slice(region[0], region[1]);
      let m: RegExpExecArray | null, n = 0;
      while ((m = rx.exec(slice)) && n++ < 60) {
        if (!m[0]) { rx.lastIndex++; continue; }
        spans.push({ s: region[0] + m.index, e: region[0] + m.index + m[0].length, color });
      }
    } catch { /* python-only regex */ }
  };
  for (const f of fps) {
    if (activeFp && f.name !== activeFp) continue;
    const color = LV_HEX[fpLevel(f)] || LV_HEX.low;
    for (const e of f.evidence || []) {
      if (!e.pattern || SKIP_HL.has(e.field)) continue;
      const pat = String(e.pattern).split("\\;")[0];
      if ((e.field === "headers" || e.field === "cookies") && e.key) {
        const km = new RegExp(`^${escRe(e.key)}\\s*:.*$`, "gim").exec(text);
        if (km) addPat(pat, [km.index, km.index + km[0].length], color);
      } else if (e.field === "meta" && e.key) {
        const km = new RegExp(`<meta[^>]*(?:name|property)=["']?${escRe(e.key)}["']?[^>]*>`, "gi").exec(text);
        if (km) addPat(pat, [km.index, km.index + km[0].length], color);
      } else if (e.field === "url" || e.field === "probe") {
        addPat(e.field === "probe" && e.key ? escRe(e.key) : pat, [0, reqEnd + 4], color);
      } else if (bodyStart < text.length) {
        addPat(pat, [bodyStart, text.length], color);
      }
    }
  }
  spans.sort((a, b) => a.s - b.s || b.e - a.e);
  let html = "", pos = 0;
  for (const sp of spans) {
    if (sp.s < pos) continue;
    html += escHtml(text.slice(pos, sp.s))
      + `<mark style="background:${sp.color}2e;outline:1px solid ${sp.color}">`
      + escHtml(text.slice(sp.s, sp.e)) + "</mark>";
    pos = sp.e;
  }
  return html + escHtml(text.slice(pos));
}

/* ---------- main component ---------- */

export function ExposureResults({
  runId,
  filter = "",
  embedded,
}: {
  runId?: number;
  filter?: string;
  /** rows supplied directly (target-level view) instead of fetching by run */
  embedded?: any[];
}) {
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [kw, setKw] = useState("");
  const [codeFilter, setCodeFilter] = useState("");
  const [sevSel, setSevSel] = useState<number[]>([]);
  const [tagSel, setTagSel] = useState<string[]>([]);

  useEffect(() => {
    if (embedded) { setResults(embedded); return; }
    if (!runId) return;
    setLoading(true);
    api.getExposure(runId)
      .then((d) => setResults(d.results || []))
      .finally(() => setLoading(false));
  }, [runId, embedded]);

  const tagOpts = useMemo(() => {
    const present = new Set<string>();
    for (const r of results) for (const t of tagsOf(r)) present.add(t);
    return Object.entries(TAG_LABEL)
      .filter(([k]) => present.has(k))
      .map(([value, label]) => ({ value, label }));
  }, [results]);

  interface Row extends Record<string, any> {
    key: string; num: number | string; sev: number;
    isAlike?: boolean; _alike?: any[]; children?: Row[];
  }

  const flat = useMemo<Row[]>(() => {
    const search = (kw || filter || "").trim().toLowerCase();
    const codeRange = parseCodeRange(codeFilter);
    const match = (r: any) => {
      if (sevSel.length && !sevSel.includes(sevOf(r))) return false;
      if (tagSel.length && !tagsOf(r).some((t) => tagSel.includes(t))) return false;
      if (codeRange && (r.status_code == null || r.status_code < codeRange[0] || r.status_code > codeRange[1]))
        return false;
      if (!search) return true;
      const hay = [r.url, r.title, r.hint, r.source, r.fingerprints, r.target_url,
        ...tagsOf(r).map((t) => TAG_LABEL[t])].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(search);
    };
    const rows = results.filter(match);

    const probed: any[] = [];
    const intelGroups = new Map<string, any[]>();
    for (const r of rows) {
      if (sigOf(r)) { probed.push(r); continue; }
      const k = `intel|${r.url}`;
      if (!intelGroups.has(k)) intelGroups.set(k, []);
      intelGroups.get(k)!.push(r);
    }
    const intelReps: any[] = [];
    for (const [, rs] of intelGroups) {
      rs.sort((a, b) => (INTEL_HINT_RANK[a.hint] ?? 9) - (INTEL_HINT_RANK[b.hint] ?? 9));
      const [rep, ...rest] = rs;
      rep._alike = rest;
      intelReps.push(rep);
    }
    const bySig = new Map<string, any[]>();
    for (const r of probed) {
      const k = sigOf(r)!;
      if (!bySig.has(k)) bySig.set(k, []);
      bySig.get(k)!.push(r);
    }
    const reps: any[] = [];
    for (const [, rs] of bySig) {
      rs.sort((a, b) =>
        sevOf(a) - sevOf(b) || (b.surface || 0) - (a.surface || 0)
        || (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0) || a.url.length - b.url.length);
      const [rep, ...rest] = rs;
      rep._alike = rest;
      reps.push(rep);
    }
    reps.sort((a, b) => sevOf(a) - sevOf(b)
      || (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0));
    const byShot = new Map<string, any>();
    const merged: any[] = [];
    for (const r of reps) {
      const s = r.shot_sig;
      if (!s) { merged.push(r); continue; }
      const keep = byShot.get(s);
      if (!keep) { byShot.set(s, r); merged.push(r); continue; }
      keep._alike = [...(keep._alike || []), r, ...(r._alike || [])];
    }
    const all = [...merged, ...intelReps];
    all.sort((a, b) => sevOf(a) - sevOf(b)
      || (b.screenshot ? 1 : 0) - (a.screenshot ? 1 : 0)
      || (b.surface || 0) - (a.surface || 0) || a.url.localeCompare(b.url));
    const out: Row[] = [];
    all.forEach((r, i) => {
      out.push({ ...r, key: `r-${r.id}`, sev: sevOf(r), num: i + 1 });
      (r._alike || []).forEach((a: any, j: number) =>
        out.push({ ...a, key: `a-${r.id}-${j}`, isAlike: true, sev: sevOf(a), num: `${i + 1}.${j + 1}` }));
    });
    return out;
  }, [results, kw, filter, codeFilter, sevSel, tagSel]);

  const dupTotal = useMemo(
    () => flat.reduce((s, r) => s + (r.isAlike ? 1 : 0), 0), [flat]);

  /* ---- packet modal ---- */
  const [pkt, setPkt] = useState({ open: false, loading: false, url: "", response: "", fingerprints: "" });
  const [activeFp, setActiveFp] = useState<string | null>(null);
  const openPkt = async (r: any) => {
    setPkt({ open: true, loading: true, url: r.url, response: "", fingerprints: r.fingerprints || "" });
    setActiveFp(null);
    try {
      const d = await api.exposureRowResponse(r.id);
      setPkt((p) => ({ ...p, loading: false, response: d.response || "", fingerprints: d.fingerprints || p.fingerprints }));
    } catch {
      setPkt((p) => ({ ...p, loading: false }));
    }
  };
  const pktFps = useMemo(() => parseFps(pkt.fingerprints), [pkt.fingerprints]);
  const pktHtml = useMemo(
    () => buildPktHtml(pkt.url, pkt.response, pktFps, activeFp),
    [pkt.url, pkt.response, pktFps, activeFp]);

  const cols = useMemo<Col<Row>[]>(() => [
    {
      key: "num", title: "#", width: 76, fixed: true,
      render: (r) => (
        <span className={r.isAlike ? "muted" : "font-medium"} style={{ fontSize: r.isAlike ? 11 : 13 }}>
          {r.num}
        </span>
      ),
    },
    {
      key: "url", title: "URL / 标题", fixed: true,
      render: (r) => r.isAlike ? (
        <>
          <span className="mono text-[12px] text-[var(--fg-3)]" style={{ wordBreak: "break-all" }}>└ {r.url}</span>
          {r.title && <div className="sub-line">{r.title}</div>}
        </>
      ) : (
        <>
          <a href={r.url} target="_blank" rel="noopener" className="mono text-[12.5px] text-[var(--accent)]"
             style={{ wordBreak: "break-all" }}>{r.url}</a>
          {!!r._alike?.length && <Tag className="ml-1.5">×{r._alike.length + 1} 相同</Tag>}
          <div className="sub-line">
            {r.title}
            {r.title && r.target_url ? " · " : ""}
            {r.target_url}
          </div>
        </>
      ),
    },
    {
      key: "sev", title: "危害", width: 66,
      render: (r) => !r.isAlike && <Tag color={SEV[r.sev].color}>{SEV[r.sev].label}</Tag>,
    },
    {
      key: "level", title: "级别", width: 70,
      render: (r) => <Tag color={r.surface ? "red" : "default"}>{r.surface ? "攻击面" : "信息"}</Tag>,
    },
    {
      key: "kind", title: "方式", width: 76,
      render: (r) => <Tag color={kindColor(r.kind)}>{kindLabel(r.kind)}</Tag>,
    },
    {
      key: "status", title: "状态", width: 74,
      render: (r) => r.status_code
        ? <Tag color={statusColor(r.status_code)}>{r.status_code}</Tag>
        : r.alive === 0 ? <Tag>失活</Tag> : <span className="muted">-</span>,
    },
    {
      key: "hint", title: "分类", width: 104,
      render: (r) => r.hint && r.hint !== "other"
        ? <Tag color={hintColor(r.hint)}>{r.hint}</Tag>
        : <span className="muted">-</span>,
    },
    {
      key: "fingerprints", title: "指纹", width: 240,
      render: (r) => !r.isAlike && (
        <>
          {r.status_code || r.alive
            ? <FpTags raw={r.fingerprints} />
            : <span className="muted" title="未深扫">-</span>}
          {r.protection && <span className="text-[11px] text-[var(--orange)] ml-1">🛡 {r.protection}</span>}
        </>
      ),
    },
    {
      key: "screenshot", title: "截图", width: 92,
      render: (r) => !r.isAlike && (
        r.screenshot ? (
          <a href={`/screenshots/${r.screenshot}`} target="_blank" rel="noopener">
            <img src={`/screenshots/${r.screenshot}`} loading="lazy" alt=""
              style={{ width: 72, border: "1px solid var(--border)", borderRadius: 4, display: "block" }} />
          </a>
        ) : <span className="muted" title="未进深扫 / 与首页相同(非攻击面) / 截图失败">-</span>
      ),
    },
    {
      key: "pkt", title: "详情", width: 56, fixed: true,
      render: (r) => !r.isAlike && (
        r.has_response
          ? <a className="text-[var(--accent)] cursor-pointer text-[12.5px]"
               onClick={(e) => { e.stopPropagation(); openPkt(r); }}>查看</a>
          : <span className="muted">-</span>
      ),
    },
    {
      key: "source", title: "来源", width: 140,
      render: (r) => (
        <span className="mono text-[11px] text-[var(--fg-3)]" style={{ wordBreak: "break-all" }}>
          {r.source || "-"}
        </span>
      ),
    },
  ], []);

  const toggle = (arr: number[] | string[], v: any, set: (x: any) => void) => {
    const i = (arr as any[]).indexOf(v);
    set(i < 0 ? [...arr, v] : (arr as any[]).filter((x) => x !== v));
  };

  return (
    <div>
      <div className="flex items-center gap-1.5 flex-wrap mb-3">
        {SEV.map((o, i) => (
          <Chip key={i} checked={sevSel.includes(i)} activeColor={o.hex}
            onChange={() => toggle(sevSel, i, setSevSel)}>{o.label}</Chip>
        ))}
        <span className="w-px h-4 bg-[var(--border)] mx-1" />
        {tagOpts.map((o) => (
          <Chip key={o.value} checked={tagSel.includes(o.value)}
            onChange={() => toggle(tagSel, o.value, setTagSel)}>{o.label}</Chip>
        ))}
        <input className="ipt !py-1 text-[12px] ml-auto w-40"
          placeholder="码：200 / 200-399 / 4xx"
          value={codeFilter} onChange={(e) => setCodeFilter(e.target.value)} />
        <input className="ipt !py-1 text-[12px] w-52"
          placeholder="搜索 URL / 标题 / 指纹 / 标签"
          value={kw} onChange={(e) => setKw(e.target.value)} />
        <span className="muted text-[12px] whitespace-nowrap">
          {flat.filter((r) => !r.isAlike).length} 条结果
          {dupTotal ? `（合并 ${dupTotal} 条相同）` : ""}
        </span>
      </div>

      <DataTable cols={cols} rows={flat} rowKey="key" loading={loading}
        scrollY={560} pageSizeOptions={[10, 20, 30, 50]} />

      <Modal open={pkt.open} onClose={() => setPkt((p) => ({ ...p, open: false }))}
        title="回显数据包" width={880}>
        <div className="mono text-[12px] text-[var(--fg-3)] mb-2" style={{ wordBreak: "break-all" }}>
          {pkt.url}
        </div>
        {pkt.loading ? <Spin /> : (
          <>
            {pktFps.length > 0 && (
              <div className="mb-2 space-y-1">
                {pktFps.map((f) => {
                  const lv = fpLevel(f);
                  const LV = { confirmed: ["确认", "green"], high: ["高可信", "orange"], low: ["低可信", "gray"] } as any;
                  const [txt, col] = LV[lv] || LV.low;
                  return (
                    <div key={f.name} className="text-[12px]">
                      <Tag color={col} className="cursor-pointer mr-1.5"
                        style={activeFp === f.name ? { outline: "2px solid var(--accent)" } : undefined}
                        onClick={() => setActiveFp(activeFp === f.name ? null : f.name)}>
                        {txt}·{f.name}{f.version ? ` ${f.version}` : ""}
                      </Tag>
                      {(f.evidence || []).map((e, i) => (
                        <span key={i} className="text-[11px] text-[var(--fg-3)] mr-2">
                          {e.field}{e.key ? "." + e.key : ""} ~ {shortPat(e.pattern || "")}
                        </span>
                      ))}
                    </div>
                  );
                })}
                <div className="text-[11px] text-[var(--fg-3)]">点击指纹可只看它的命中高亮</div>
              </div>
            )}
            <pre
              className="max-h-[60vh] overflow-auto rounded-md p-3 text-[12px] leading-5"
              style={{ background: "#0a0c12", color: "#c9d1e0", whiteSpace: "pre-wrap", wordBreak: "break-all" }}
              dangerouslySetInnerHTML={{ __html: pktHtml }}
            />
          </>
        )}
      </Modal>
    </div>
  );
}
