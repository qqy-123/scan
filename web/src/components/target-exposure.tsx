"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { fmtTime, setIfChanged } from "@/lib/fmt";
import { Modal, Spin, Tag } from "@/components/ui";
import { ColSettings, DataTable, useColPrefs, type Col } from "@/components/data-table";
import { FpTags } from "@/components/fp-tags";
import { statusColor } from "@/components/exposure-results";

const kindColor = (k: string) =>
  (({ js: "cyan", dir: "blue", leak: "magenta", vuln: "red", point: "volcano",
     sub: "purple", host: "volcano", cdn: "red", net: "green",
     url: "geekblue", port: "orange" }) as Record<string, string>)[k] || "default";
const kindLabel = (k: string) =>
  (({ js: "JS", dir: "DIR", leak: "泄露", vuln: "漏洞", point: "攻击点",
     sub: "子域", host: "Host碰撞", cdn: "源站", net: "测绘",
     url: "历史URL", port: "端口" }) as Record<string, string>)[k] || k;
const hintColor = (h: string) =>
  (({ admin: "red", api: "geekblue", upload: "orange", auth: "purple",
     config: "gold", debug: "cyan", vuln: "red", leak: "magenta",
     point: "volcano", origin: "red", host: "volcano", entry: "purple",
     takeover: "red", critical: "red", port: "orange" }) as Record<string, string>)[String(h).split(":")[0]] || "default";

export function TargetExposure({
  target,
  running,
  onScan,
}: {
  target: any;
  running: boolean;
  onScan: (t: any) => void;
}) {
  const [rows, setRows] = useState<any[]>([]);
  const [runs, setRuns] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const loaded = useRef(false);

  const runningNow = running || runs.some((r) => r.status === "running");
  const surfaceCount = rows.filter((r) => r.surface).length;
  const lastRun = useMemo(() => {
    const ts = [...runs.map((r) => r.started_at), ...rows.map((r) => r.run_started)]
      .filter(Boolean).sort();
    return ts.length ? ts[ts.length - 1] : null;
  }, [runs, rows]);

  const load = async () => {
    if (!loaded.current) setLoading(true);
    try {
      const d = await api.targetExposure(target.id);
      setIfChanged(setRows, d.results || []);
      setIfChanged(setRuns, d.runs || []);
    } finally {
      loaded.current = true;
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [target.id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (timer.current) clearInterval(timer.current);
    if (runningNow) timer.current = setInterval(load, 5000);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [runningNow]); // eslint-disable-line react-hooks/exhaustive-deps

  /* packet modal */
  const [pkt, setPkt] = useState({ open: false, loading: false, url: "", response: "" });
  const openPkt = async (r: any) => {
    setPkt({ open: true, loading: true, url: r.url, response: "" });
    try {
      const d = await api.exposureRowResponse(r.id);
      setPkt((p) => ({ ...p, loading: false, response: d.response || "" }));
    } catch {
      setPkt((p) => ({ ...p, loading: false }));
    }
  };

  const cols = useMemo<Col<any>[]>(() => [
    { key: "kind", title: "方式", width: 78,
      render: (r) => <Tag color={kindColor(r.kind)}>{kindLabel(r.kind)}</Tag> },
    { key: "url", title: "URL / 标题", fixed: true,
      render: (r) => (
        <>
          <a href={r.url} target="_blank" rel="noopener"
             className="mono text-[12.5px] text-[var(--accent)]"
             style={{ wordBreak: "break-all" }}>{r.url}</a>
          {r.title && <div className="sub-line">{r.title}</div>}
        </>
      ) },
    { key: "status", title: "状态", width: 74,
      render: (r) => r.status_code
        ? <Tag color={statusColor(r.status_code)}>{r.status_code}</Tag>
        : r.alive === 0 ? <Tag>失活</Tag> : <span className="muted">-</span> },
    { key: "hint", title: "分类", width: 100,
      render: (r) => r.hint && r.hint !== "other"
        ? <Tag color={hintColor(r.hint)}>{r.hint}</Tag> : <span className="muted">-</span> },
    { key: "level", title: "级别", width: 76,
      render: (r) => <Tag color={r.surface ? "red" : "default"}>{r.surface ? "攻击面" : "信息"}</Tag> },
    { key: "fingerprints", title: "指纹", width: 230,
      render: (r) => (
        <>
          {r.status_code || r.alive ? <FpTags raw={r.fingerprints} /> : <span className="muted">-</span>}
          {r.protection && <span className="text-[11px] text-[var(--orange)] ml-1">🛡 {r.protection}</span>}
        </>
      ) },
    { key: "screenshot", title: "截图", width: 92,
      render: (r) => r.screenshot ? (
        <a href={`/screenshots/${r.screenshot}`} target="_blank" rel="noopener">
          <img src={`/screenshots/${r.screenshot}`} loading="lazy" alt=""
            style={{ width: 72, border: "1px solid var(--border)", borderRadius: 4, display: "block" }} />
        </a>
      ) : <span className="muted">-</span> },
    { key: "pkt", title: "详情", width: 56,
      render: (r) => r.has_response
        ? <a className="text-[var(--accent)] cursor-pointer text-[12.5px]"
             onClick={(e) => { e.stopPropagation(); openPkt(r); }}>查看</a>
        : <span className="muted">-</span> },
    { key: "source", title: "来源", width: 140,
      render: (r) => (
        <span className="mono text-[11px] text-[var(--fg-3)]" style={{ wordBreak: "break-all" }}>
          {r.source || "-"}</span>
      ) },
    { key: "run", title: "轮次", width: 64,
      render: (r) => <span className="mono text-[12px]">#{r.run_id}</span> },
    { key: "time", title: "发现时间", width: 120,
      render: (r) => <span className="text-[12px]">{fmtTime(r.created_at)}</span> },
  ], []);

  const { shown, visible, save } = useColPrefs("target_exposure_cols", cols, 1);

  return (
    <div className="px-2 py-3">
      <div className="flex items-center justify-between mb-2.5">
        <span className="text-[13px] text-[var(--fg-2)]">
          测绘结果 <b className="text-[var(--fg)]">{rows.length}</b> 条
          {surfaceCount > 0 && (
            <>（攻击面 <b className="text-[var(--red)]">{surfaceCount}</b>）</>
          )}
          {lastRun && <span className="muted"> · 最近测绘 {fmtTime(lastRun)}</span>}
          {runningNow && <Tag color="processing" className="ml-2 pulsing">测绘中…</Tag>}
        </span>
        <div className="flex gap-1.5">
          <button className="btn btn-sm" onClick={load}>刷新</button>
          <ColSettings cols={cols} visible={visible} onChange={save} />
          <button className="btn btn-sm btn-pri" disabled={running}
            onClick={() => onScan(target)}>测绘本目标</button>
        </div>
      </div>
      <DataTable cols={shown} rows={rows} loading={loading} pageSize={10}
        empty={<div className="py-8 text-center text-[var(--fg-3)] text-[13px]">
          该目标还没有测绘结果，点击右上角「测绘本目标」</div>} />

      <Modal open={pkt.open} onClose={() => setPkt((p) => ({ ...p, open: false }))}
        title="回显数据包" width={880}>
        <div className="mono text-[12px] text-[var(--fg-3)] mb-2" style={{ wordBreak: "break-all" }}>{pkt.url}</div>
        {pkt.loading ? <Spin /> : (
          <pre className="max-h-[60vh] overflow-auto rounded-md p-3 text-[12px]"
            style={{ background: "#0a0c12", color: "#c9d1e0", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {pkt.response || "(空)"}
          </pre>
        )}
      </Modal>
    </div>
  );
}
