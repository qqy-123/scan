"use client";
import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import { fmtTime } from "@/lib/fmt";
import { FpTags } from "@/components/fp-tags";
import { Checkbox, Empty, Tag } from "@/components/ui";
import { ColSettings, DataTable, useColPrefs, type Col } from "@/components/data-table";

function parseCodeRange(v: string): { lo: number; hi: number } | null {
  const s = (v || "").trim();
  if (!s) return null;
  if (/^\d{3}$/.test(s)) return { lo: +s, hi: +s };
  const m = s.match(/^(\d)(xx|\d{2})$/);
  if (m) { const lo = +m[1] * 100; return { lo, hi: lo + 99 }; }
  const r = s.match(/^(\d{3})\s*-\s*(\d{3})$/);
  if (r) return { lo: +r[1], hi: +r[2] };
  return null;
}

function ScanResults() {
  const router = useRouter();
  const sp = useSearchParams();
  const sid = Number(sp.get("id"));
  const [scan, setScan] = useState<any>(null);
  const [page, setPage] = useState(Math.max(1, Number(sp.get("page")) || 1));
  const [size, setSize] = useState(Number(sp.get("size")) || 20);
  const [onlyAlive, setOnlyAlive] = useState(sp.get("alive") === "1");
  const [scanKw, setScanKw] = useState(sp.get("kw") || "");
  const [resCodeFilter, setResCodeFilter] = useState(sp.get("code") || "");

  useEffect(() => {
    api.getScan(sid).then(setScan);
  }, [sid]);

  /* URL-synced list state */
  useEffect(() => {
    const q = new URLSearchParams(sp.toString());
    const set = (k: string, v: string, keep: boolean) =>
      keep ? q.set(k, v) : q.delete(k);
    set("id", String(sid), true);
    set("page", String(page), page > 1);
    set("size", String(size), size !== 20);
    set("alive", "1", onlyAlive);
    set("kw", scanKw.trim(), !!scanKw.trim());
    set("code", resCodeFilter.trim(), !!resCodeFilter.trim());
    const qs = q.toString();
    if (qs !== sp.toString()) router.replace(`/scans/?${qs}`, { scroll: false });
  }, [page, size, onlyAlive, scanKw, resCodeFilter]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setPage(1); }, [onlyAlive, scanKw, resCodeFilter]);

  const filteredResults = useMemo(() => {
    const rows = scan?.results || [];
    const kw = scanKw.trim().toLowerCase();
    const range = parseCodeRange(resCodeFilter);
    return rows.filter((r: any) => {
      if (onlyAlive && !r.alive) return false;
      if (range && !(r.status_code >= range.lo && r.status_code <= range.hi)) return false;
      if (!kw) return true;
      return [r.final_url, r.url, r.title, r.fingerprints, r.protection]
        .filter(Boolean).join(" ").toLowerCase().includes(kw);
    });
  }, [scan, onlyAlive, scanKw, resCodeFilter]);

  const cols = useMemo<Col<any>[]>(() => [
    { key: "alive", title: "状态", width: 100,
      render: (r) => (
        <>
          <Tag color={r.alive ? "green" : "red"}>{r.alive ? "存活" : "失活"}</Tag>
          {r.protection && <Tag color="volcano" className="ml-1">防护</Tag>}
        </>
      ) },
    { key: "final_url", title: "URL",
      render: (r) => (
        <a href={r.final_url} target="_blank" rel="noopener"
          className="mono text-[12.5px] text-[var(--accent)]"
          style={{ wordBreak: "break-all" }}>{r.final_url}</a>
      ) },
    { key: "status_code", title: "HTTP", width: 70 },
    { key: "title", title: "标题",
      render: (r) => <span className="text-[12.5px]">{r.title}</span> },
    { key: "fps", title: "指纹", render: (r) => <FpTags raw={r.fingerprints} /> },
    { key: "shot", title: "截图", width: 130,
      render: (r) => r.screenshot ? (
        <Link href={`/result/?id=${r.id}`}>
          <img src={`/screenshots/${r.screenshot}`} alt=""
            style={{ width: 110, height: 62, objectFit: "cover", borderRadius: 4,
                     border: "1px solid var(--border)", display: "block" }} />
        </Link>
      ) : <span className="muted">-</span> },
    { key: "detail", title: "操作", width: 70, fixed: true,
      render: (r) => (
        <Link href={`/result/?id=${r.id}`}>
          <button className="btn btn-sm">详情</button>
        </Link>
      ) },
  ], []);

  const { shown, visible, save } = useColPrefs("scan_result_cols", cols, 1);

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <button className="btn btn-sm" onClick={() => router.back()}>
          <ArrowLeft size={13} /> 返回
        </button>
        <span className="muted text-[13px]">
          <Link href="/projects/" className="hover:text-[var(--fg)]">项目</Link>
          <span className="mx-1.5">/</span>
          {scan && (
            <Link href={`/project/?id=${scan.project_id}&tab=scans`}
              className="hover:text-[var(--fg)]">扫描记录</Link>
          )}
          <span className="mx-1.5">/</span>
          <span className="text-[var(--fg-2)]">轮次 #{sid}</span>
        </span>
      </div>

      <div className="card card-pad">
        <div className="flex items-center flex-wrap gap-x-3 gap-y-2 mb-1">
          <span className="font-semibold text-[15px]">
            扫描结果 · 轮次 #{sid}
          </span>
          {scan && (
            <>
              <Tag color={scan.kind === "rescan" ? "purple" : "blue"}>
                {scan.kind === "rescan" ? "二次扫描" : "全量扫描"}
              </Tag>
              <Tag>存活 {scan.alive}/{scan.total}</Tag>
            </>
          )}
          <Checkbox checked={onlyAlive} onChange={setOnlyAlive} label="只看存活" />
          <input className="ipt !py-1 text-[12px] w-44" placeholder="状态码：200 / 200-399 / 4xx"
            value={resCodeFilter} onChange={(e) => setResCodeFilter(e.target.value)} />
          <input className="ipt !py-1 text-[12px] w-56" placeholder="过滤 URL / 标题 / 指纹"
            value={scanKw} onChange={(e) => setScanKw(e.target.value)} />
          <ColSettings cols={cols} visible={visible} onChange={save} />
        </div>
        {scan && (
          <div className="text-[12px] text-[var(--fg-3)] mb-3">
            开始 {fmtTime(scan.started_at)}
            {scan.finished_at && <> · 结束 {fmtTime(scan.finished_at)}</>}
            {scan.options?.screenshot === false && " · 未截图"}
            {scan.options?.fingerprint === false && " · 未指纹识别"}
          </div>
        )}
        <DataTable cols={shown} rows={filteredResults} loading={!scan}
          pagerState={{ page, pageSize: size, onChange: (p, s) => { setSize(s); setPage(s !== size ? 1 : p); } }}
          empty={scan ? <Empty text="该轮没有结果" /> : undefined} />
      </div>
    </div>
  );
}

export default function ScansPage() {
  return (
    <Suspense>
      <ScanResults />
    </Suspense>
  );
}
