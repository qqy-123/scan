"use client";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Radar, Crosshair, Info, Database, ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import { fmtTime } from "@/lib/fmt";
import { Confirm, Empty, Modal, Popover, Stat, Tabs, Tag, msg } from "@/components/ui";
import { DataTable, type Col } from "@/components/data-table";
import { ExposureScanModal } from "@/components/exposure-scan-modal";
import { ExposureResults } from "@/components/exposure-results";

const KIND_LABEL: Record<string, string> = {
  js: "JS接口", dir: "目录爆破", sub: "子域名", brute: "子域爆破",
  host: "Host碰撞", net: "网络空间", origin: "源站探测",
  takeover: "接管检测", wayback: "历史URL", port: "端口扫描",
};
const kindColor = (k: string) =>
  (({ js: "cyan", dir: "blue", sub: "purple", brute: "purple",
     host: "volcano", net: "green", origin: "red", takeover: "red",
     wayback: "geekblue", port: "orange" }) as Record<string, string>)[k] || "default";

const parseKinds = (r: any) => {
  try { return JSON.parse(r.options || "{}").kinds || []; } catch { return []; }
};

function ExposurePage() {
  const router = useRouter();
  const sp = useSearchParams();
  const [runs, setRuns] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [showScan, setShowScan] = useState(false);
  const [kw, setKw] = useState("");
  const [diff, setDiff] = useState<{ open: boolean; loading: boolean; data: any }>({
    open: false, loading: false, data: null,
  });
  const [diffTab, setDiffTab] = useState("new");
  const resultRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      api.exposureStats().then(setStats).catch(() => {});
      const list = await api.listExposureAll();
      setRuns(list);
      setSelected((sel: any) => {
        if (!sel) {
          const want = Number(sp.get("run"));
          const hit = want && list.find((r: any) => r.id === want);
          return hit || list.find((r: any) => r.status === "done") || list[0] || null;
        }
        return list.find((r: any) => r.id === sel.id) || sel;
      });
    } finally {
      setLoading(false);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(() => {
      if (runs.some((r) => r.status === "running" || r.deep_status === "running")) load();
    }, 3000);
    return () => clearInterval(t);
  }, [runs, load]);

  const viewRun = (r: any) => {
    setSelected(r);
    setKw("");
    router.replace(`/exposure/?run=${r.id}`, { scroll: false });
    setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
  };

  const download = async (rid: number, fmt: string) => {
    const blob = await api.exportExposure(rid, fmt);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `exposure_${rid}.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runCols = useMemo<Col<any>[]>(() => [
    { key: "id", title: "#", width: 60 },
    { key: "project_name", title: "项目" },
    { key: "kinds", title: "方式", width: 170,
      render: (r) => {
        const kinds = parseKinds(r);
        return (
          <>
            {kinds.slice(0, 3).map((k: string) => (
              <Tag key={k} color={kindColor(k)} className="mr-0.5">{KIND_LABEL[k] || k}</Tag>
            ))}
            {kinds.length > 3 && (
              <Popover trigger={<Tag className="cursor-pointer">+{kinds.length - 3}</Tag>}>
                <div className="flex flex-wrap gap-1 max-w-[240px]">
                  {kinds.map((k: string) => (
                    <Tag key={k} color={kindColor(k)}>{KIND_LABEL[k] || k}</Tag>
                  ))}
                </div>
              </Popover>
            )}
          </>
        );
      } },
    { key: "status", title: "状态", width: 130,
      render: (r) => r.status === "running"
        ? <Tag color="processing" className="pulsing">{r.done}/{r.total}</Tag>
        : r.status === "done" ? <Tag color="green">done</Tag>
        : <Tag color="red">{r.status}</Tag> },
    { key: "found", title: "发现", width: 80,
      render: (r) => (
        <span style={{ color: r.found ? "var(--red)" : "inherit", fontWeight: r.found ? 600 : 400 }}>
          {r.found}</span>
      ) },
    { key: "deep", title: "深扫", width: 140,
      render: (r) => r.deep_status === "running"
        ? <Tag color="processing" className="pulsing">深扫中 {r.deep_done}/{r.deep_total}</Tag>
        : r.deep_status === "done" ? <Tag color="green">已深扫</Tag>
        : r.deep_status === "failed" ? <Tag color="red">深扫失败</Tag>
        : <span className="muted">-</span> },
    { key: "started_at", title: "开始时间", width: 150, render: (r) => fmtTime(r.started_at) },
    { key: "finished_at", title: "结束时间", width: 150, render: (r) => fmtTime(r.finished_at) },
    { key: "op", title: "操作", width: 250,
      render: (r) => (
        <div className="flex gap-1 flex-wrap" onClick={(e) => e.stopPropagation()}>
          <button className="btn btn-sm" onClick={() => viewRun(r)}>查看</button>
          {r.status === "done" && r.deep_status !== "running" && (
            <button className="btn btn-sm" onClick={async () => {
              try { await api.deepScanExposure(r.id, 120); load(); } catch {}
            }}>{r.deep_status === "done" ? "重新深扫" : "深扫"}</button>
          )}
          {r.status === "done" && (
            <button className="btn btn-sm" onClick={async () => {
              setDiff({ open: true, loading: true, data: null });
              try { setDiff({ open: true, loading: false, data: await api.exposureDiff(r.id) }); }
              catch { setDiff((d) => ({ ...d, loading: false })); }
            }}>对比</button>
          )}
          {r.status === "done" && (
            <Popover trigger={<button className="btn btn-sm">导出</button>}>
              <div className="grid gap-1">
                <button className="btn btn-ghost btn-sm" onClick={() => download(r.id, "csv")}>CSV</button>
                <button className="btn btn-ghost btn-sm" onClick={() => download(r.id, "xlsx")}>Excel</button>
              </div>
            </Popover>
          )}
          <Confirm title="删除该次测绘及结果？" onOk={async () => {
            await api.deleteExposure(r.id);
            if (selected?.id === r.id) setSelected(null);
            load();
          }}>
            <button className="btn btn-sm btn-danger">删除</button>
          </Confirm>
        </div>
      ) },
  ], [selected, load]); // eslint-disable-line react-hooks/exhaustive-deps

  const diffCols = useMemo<Col<any>[]>(() => [
    { key: "url", title: "URL",
      render: (r) => <span className="mono text-[12px]" style={{ wordBreak: "break-all" }}>{r.url}</span> },
    { key: "kind", title: "类型", width: 80 },
    { key: "hint", title: "提示", width: 110 },
    { key: "status_code", title: "状态", width: 70, render: (r) => r.status_code ?? "-" },
  ], []);
  const diffChangedCols = useMemo<Col<any>[]>(() => [
    { key: "url", title: "URL",
      render: (r) => <span className="mono text-[12px]" style={{ wordBreak: "break-all" }}>{r.url}</span> },
    { key: "st", title: "状态", width: 120,
      render: (r) => `${r.old_status ?? "-"} → ${r.new_status ?? "-"}` },
    { key: "old_title", title: "旧标题" },
    { key: "new_title", title: "新标题" },
  ], []);

  return (
    <div>
      <div className="mb-5">
        <div className="text-xl font-semibold">暴露面测绘</div>
        <div className="text-[12.5px] text-[var(--fg-3)] mt-0.5">
          JS 接口提取 · 目录爆破 · 敏感信息/攻击点/源码泄露检测 · 攻击面深扫
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-4">
        <Stat label="测绘轮次" value={stats.runs ?? "-"} icon={<Radar size={18} />}
          hint={`覆盖 ${stats.projects ?? "-"} 个项目`} />
        <Stat label="攻击面" value={<span className="text-[var(--red)]">{stats.surfaces ?? "-"}</span>}
          icon={<Crosshair size={18} />} hint="已验证与首页不同的页面" />
        <Stat label="信息" value={stats.infos ?? "-"} icon={<Info size={18} />}
          hint="JS/泄露/攻击点等待验证线索" />
        <Stat label="发现总数" value={stats.findings ?? "-"} icon={<Database size={18} />}
          hint="JS接口 · 目录 · 子域 · 测绘资产" />
      </div>

      <div className="card card-pad mb-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-[14px] font-medium">测绘记录</div>
          <button className="btn btn-pri btn-sm" onClick={() => setShowScan(true)}>
            <Radar size={13} /> 发起测绘
          </button>
        </div>
        <DataTable cols={runCols} rows={runs} loading={loading} pageSize={8}
          onRow={viewRun}
          empty={
            <div className="py-8 text-center">
              <div className="text-[var(--fg-3)] text-[13px] mb-3">还没有测绘记录</div>
              <button className="btn btn-pri btn-sm" onClick={() => setShowScan(true)}>立即发起测绘</button>
            </div>
          } />
      </div>

      {selected && (
        <div className="card card-pad" ref={resultRef}>
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <div className="text-[14px] font-medium">
              攻击面结果 · 测绘 #{selected.id}
              <Tag className="ml-2">{selected.project_name}</Tag>
              <Tag color={selected.found ? "red" : "default"}>{selected.found} 条发现</Tag>
            </div>
            <div className="flex gap-2">
              <input className="ipt !py-1 text-[12px] w-64" placeholder="过滤 URL / 标题 / 指纹"
                value={kw} onChange={(e) => setKw(e.target.value)} />
              <button className="btn btn-sm" onClick={() => {
                setSelected(null);
                router.replace("/exposure/", { scroll: false });
              }}><ArrowLeft size={13} /> 返回列表</button>
            </div>
          </div>
          <ExposureResults runId={selected.id} filter={kw} />
        </div>
      )}

      <ExposureScanModal open={showScan} onClose={() => setShowScan(false)} onStarted={load} />

      <Modal open={diff.open} onClose={() => setDiff((d) => ({ ...d, open: false }))}
        title="与上一轮对比" width={780}>
        {diff.loading ? (
          <div className="py-8 text-center muted">加载中…</div>
        ) : diff.data && !diff.data.prev ? (
          <Empty text="该项目第一轮已完成的测绘，无可对比对象" />
        ) : diff.data ? (
          <>
            <div className="mb-3 text-[13px]">
              vs 测绘 #{diff.data.prev}（{fmtTime(diff.data.prev_time)}）
              <Tag color="green" className="ml-2">+{diff.data.new_count} 新增</Tag>
              <Tag className="ml-1">-{diff.data.gone_count} 消失</Tag>
              <Tag color="orange" className="ml-1">~{diff.data.changed_count} 变化</Tag>
            </div>
            <Tabs active={diffTab} onChange={setDiffTab} items={[
              { key: "new", label: `新增 ${diff.data.new_count}` },
              { key: "gone", label: `消失 ${diff.data.gone_count}` },
              { key: "changed", label: `变化 ${diff.data.changed_count}` },
            ]} />
            <div className="pt-3">
              {diffTab === "new" && <DataTable cols={diffCols} rows={diff.data.new || []} rowKey="url" pageSize={10} />}
              {diffTab === "gone" && <DataTable cols={diffCols} rows={diff.data.gone || []} rowKey="url" pageSize={10} />}
              {diffTab === "changed" && <DataTable cols={diffChangedCols} rows={diff.data.changed || []} rowKey="url" pageSize={10} />}
            </div>
          </>
        ) : null}
      </Modal>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense>
      <ExposurePage />
    </Suspense>
  );
}
