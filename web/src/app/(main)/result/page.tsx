"use client";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowLeft, ChevronLeft, ChevronRight, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { fpLevel } from "@/components/fp-tags";
import { Empty, Tag } from "@/components/ui";

const LV: Record<string, [string, string]> = {
  confirmed: ["确认", "green"], high: ["高可信", "orange"], low: ["低可信", "gray"],
};

function Desc({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2 py-1.5 text-[13px]">
      <span className="text-[var(--fg-3)] w-20 shrink-0">{label}</span>
      <span className="min-w-0" style={{ wordBreak: "break-all" }}>{children}</span>
    </div>
  );
}

function ResultDetail() {
  const router = useRouter();
  const sp = useSearchParams();
  const rid = Number(sp.get("id"));
  const [result, setResult] = useState<any>(null);
  const [siblings, setSiblings] = useState<number[]>([]);

  const idx = siblings.indexOf(rid);
  const prevId = idx > 0 ? siblings[idx - 1] : null;
  const nextId = idx >= 0 && idx < siblings.length - 1 ? siblings[idx + 1] : null;

  const load = useCallback(async () => {
    const r = await api.getResult(rid);
    setResult(r);
    if (r?.scan_id) {
      const scan = await api.getScan(r.scan_id);
      setSiblings((scan.results || []).map((x: any) => x.id).sort((a: number, b: number) => a - b));
    }
  }, [rid]);

  useEffect(() => { load(); }, [load]);

  const goto = (id: number | null) => { if (id) router.replace(`/result/?id=${id}`); };

  const fpCols = useMemo(() => [
    { key: "name", title: "指纹", width: 160 },
    { key: "category", title: "分类", width: 140 },
    {
      key: "confidence", title: "置信度", width: 90,
      render: (f: any) => {
        const lv = fpLevel(f);
        const [t, c] = LV[lv] || LV.low;
        return <Tag color={c}>{t}</Tag>;
      },
    },
    { key: "version", title: "版本", width: 100, render: (f: any) => f.version || "-" },
    {
      key: "evidence", title: "命中证据",
      render: (f: any) => (f.evidence || []).map((e: any, i: number) => (
        <div key={i} className="mono text-[12px] text-[var(--fg-3)]">
          {e.field}{e.key ? `[${e.key}]` : ""} ~ {e.pattern}
        </div>
      )),
    },
  ], []);

  if (!result) return <div className="py-20 text-center muted">加载中…</div>;

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <button className="btn btn-sm" onClick={() => router.back()}>
          <ArrowLeft size={13} /> 返回
        </button>
        <span className="muted text-[13px]">
          <Link href="/projects/" className="hover:text-[var(--fg)]">项目</Link>
          <span className="mx-1.5">/</span>
          {result.project_id && (
            <>
              <Link href={`/scans/?id=${result.scan_id}`} className="hover:text-[var(--fg)]">
                扫描记录</Link>
              <span className="mx-1.5">/</span>
            </>
          )}
          <span className="text-[var(--fg-2)]">结果详情</span>
        </span>
        {idx >= 0 && (
          <div className="ml-auto flex items-center gap-1.5">
            <button className="btn btn-sm" disabled={!prevId} onClick={() => goto(prevId)}>
              <ChevronLeft size={13} /> 上一条
            </button>
            <span className="text-[12px] muted">{idx + 1}/{siblings.length}</span>
            <button className="btn btn-sm" disabled={!nextId} onClick={() => goto(nextId)}>
              下一条 <ChevronRight size={13} />
            </button>
          </div>
        )}
      </div>

      {result.protection && (
        <div className="card card-pad mb-4 flex items-center gap-2 text-[13px]"
          style={{ borderColor: "rgba(245,158,11,.4)", background: "rgba(245,158,11,.06)" }}>
          <ShieldAlert size={15} className="text-[var(--orange)] shrink-0" />
          检测到前台保护：{result.protection}，识别结果可能来自防护页面
        </div>
      )}

      <div className="card card-pad mb-4">
        <div className="grid grid-cols-2 gap-x-8">
          <Desc label="原始 URL"><span className="mono text-[12.5px]">{result.url}</span></Desc>
          <Desc label="最终 URL">
            <a href={result.final_url} target="_blank" rel="noopener"
              className="mono text-[12.5px] text-[var(--accent)]">{result.final_url}</a>
          </Desc>
          <Desc label="状态">
            <Tag color={result.alive ? "green" : "red"}>{result.alive ? "存活" : "失活"}</Tag>
            {result.status_code && <Tag className="ml-1.5">{result.status_code}</Tag>}
          </Desc>
          <Desc label="标题">{result.title || "-"}</Desc>
          <Desc label="Server">{result.server || "-"}</Desc>
          <Desc label="耗时">{result.elapsed_ms ?? "-"} ms</Desc>
          {result.error && (
            <Desc label="错误"><span className="mono text-[12px] text-[var(--red)]">{result.error}</span></Desc>
          )}
        </div>
      </div>

      <div className={`grid gap-4 ${result.screenshot ? "grid-cols-[1.4fr_1fr]" : "grid-cols-1"}`}>
        <div className="card card-pad">
          <div className="text-[13.5px] font-medium mb-3">指纹识别</div>
          {result.fingerprints?.length ? (
            <table className="dt">
              <thead>
                <tr>{fpCols.map((c) => <th key={c.key as string} style={{ width: c.width }}>{c.title}</th>)}</tr>
              </thead>
              <tbody>
                {result.fingerprints.map((f: any) => (
                  <tr key={f.name}>
                    {fpCols.map((c) => (
                      <td key={c.key as string}>{(c as any).render ? (c as any).render(f) : f[c.key as string]}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty text="未识别到指纹" />}
        </div>
        {result.screenshot && (
          <div className="card card-pad">
            <div className="text-[13.5px] font-medium mb-3">页面截图</div>
            <a href={`/screenshots/${result.screenshot}`} target="_blank" rel="noopener">
              <img src={`/screenshots/${result.screenshot}`} alt=""
                className="w-full rounded-md border border-[var(--border)]" />
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ResultPage() {
  return (
    <Suspense>
      <ResultDetail />
    </Suspense>
  );
}
