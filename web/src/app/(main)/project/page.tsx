"use client";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowLeft, Play, RefreshCw, Radar, Import, EllipsisVertical, Upload,
} from "lucide-react";
import { api } from "@/lib/api";
import { fmtTime } from "@/lib/fmt";
import { parseFps, FpTags } from "@/components/fp-tags";
import {
  Checkbox, Chip, Confirm, Empty, Modal, Popover, Progress, Radio,
  Switch, Tabs, Tag, msg,
} from "@/components/ui";
import { ColSettings, DataTable, useColPrefs, type Col } from "@/components/data-table";
import { ExposureScanModal } from "@/components/exposure-scan-modal";
import { TargetExposure } from "@/components/target-exposure";
import { ExposureResults } from "@/components/exposure-results";

const EXP_KIND_LABEL: Record<string, string> = {
  js: "JS接口", dir: "目录爆破", sub: "子域名", brute: "子域爆破",
  host: "Host碰撞", net: "网络空间", origin: "源站", takeover: "接管",
  wayback: "历史URL", port: "端口",
};
const expKindColor = (k: string) =>
  (({ js: "cyan", dir: "blue", sub: "purple", brute: "purple",
     host: "volcano", net: "green", origin: "red", takeover: "red",
     wayback: "geekblue", port: "orange" }) as Record<string, string>)[k] || "default";

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

const statusTag = (s: string) =>
  s === "running" ? <Tag color="processing" className="pulsing">进行中</Tag>
  : s === "done" ? <Tag color="green">done</Tag>
  : <Tag color="red">{s}</Tag>;

function ProjectDetail() {
  const router = useRouter();
  const sp = useSearchParams();
  const pid = Number(sp.get("id"));
  const [project, setProject] = useState<any>(null);
  const [running, setRunning] = useState<any>(null);
  const [tab, setTab] = useState(sp.get("tab") || "targets");
  const [expRuns, setExpRuns] = useState<any[]>([]);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const expTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  /* targets tab state (URL-synced) */
  const [targetSel, setTargetSel] = useState<(number | string)[]>([]);
  const [targetFilter, setTargetFilter] = useState(sp.get("tf") || "all");
  const [codeFilter, setCodeFilter] = useState(sp.get("tcode") || "");
  const [tpage, setTpage] = useState(Math.max(1, Number(sp.get("tpage")) || 1));
  const [tsize, setTsize] = useState(Number(sp.get("tsize")) || 20);

  /* modals */
  const [showImport, setShowImport] = useState(false);
  const [showImports, setShowImports] = useState(false);
  const [imports, setImports] = useState<any[]>([]);
  const [importText, setImportText] = useState("");
  const [importFiles, setImportFiles] = useState<File[]>([]);
  const [importTab, setImportTab] = useState("text");
  const [showScan, setShowScan] = useState(false);
  const [scanOpts, setScanOpts] = useState({
    scope: "all", active_probe: true, screenshot: true, fingerprint: true, concurrency: 50,
  });
  const settingsLoaded = useRef(false);
  const [showExposure, setShowExposure] = useState(false);
  const [expTargetIds, setExpTargetIds] = useState<number[]>([]);
  const [showEditProject, setShowEditProject] = useState(false);
  const [editProjectForm, setEditProjectForm] = useState({ name: "", description: "" });
  const [showEditTarget, setShowEditTarget] = useState(false);
  const [editTarget, setEditTarget] = useState<any>(null);
  const [editTargetUrl, setEditTargetUrl] = useState("");

  const expRunning = expRuns.some((r) => r.status === "running");

  /* ---------- data ---------- */
  const loadExposure = useCallback(async () => {
    const runs = await api.listExposure(pid);
    setExpRuns(runs);
  }, [pid]);

  const load = useCallback(async () => {
    const data = await api.getProject(pid);
    setProject(data);
    setRunning(data.running);
    if (!settingsLoaded.current) {
      settingsLoaded.current = true;
      api.getSettings().then((s) =>
        setScanOpts((o) => ({
          ...o,
          active_probe: s.active_probe,
          screenshot: s.screenshot,
          fingerprint: s.fingerprint !== false,
          concurrency: s.concurrency,
        })));
    }
    loadExposure();
    const ids = new Set((data.targets || []).map((t: any) => t.id));
    setTargetSel((sel) => sel.filter((id) => ids.has(id)));
    if (data.running && !timer.current) {
      timer.current = setInterval(async () => {
        await load();
      }, 2500);
    }
  }, [pid, loadExposure]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!running && timer.current) {
      clearInterval(timer.current);
      timer.current = null;
      if (project) msg.ok("扫描完成");
    }
  }, [running]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const busy = expRuns.some((r) => r.status === "running" || r.deep_status === "running");
    if (busy && !expTimer.current) {
      expTimer.current = setInterval(loadExposure, 4000);
    } else if (!busy && expTimer.current) {
      clearInterval(expTimer.current);
      expTimer.current = null;
    }
  }, [expRuns, loadExposure]);
  useEffect(() => () => {
    if (timer.current) clearInterval(timer.current);
    if (expTimer.current) clearInterval(expTimer.current);
  }, []);

  /* ---------- derived ---------- */
  const latest = project?.latest || {};
  const aliveCount = Object.values(latest).filter((r: any) => r.alive).length;
  const deadCount = Object.values(latest).filter((r: any) => !r.alive).length;
  const unscannedCount = (project?.targets?.length || 0) - aliveCount - deadCount;

  const targetRows = useMemo(
    () => (project?.targets || []).map((t: any) => {
      const l = latest[String(t.id)] || null;
      return { ...t, latest: l, fps: l ? parseFps(l.fingerprints) : [] };
    }),
    [project, latest],
  );

  const filteredTargets = useMemo(() => {
    let rows = targetRows;
    if (targetFilter === "alive") rows = rows.filter((r: any) => r.latest?.alive);
    else if (targetFilter === "dead") rows = rows.filter((r: any) => r.latest && !r.latest.alive);
    else if (targetFilter === "unscanned") rows = rows.filter((r: any) => !r.latest);
    const range = parseCodeRange(codeFilter);
    if (range) rows = rows.filter((r: any) => {
      const c = r.latest?.status_code;
      return c != null && c >= range[0] && c <= range[1];
    });
    return rows;
  }, [targetRows, targetFilter, codeFilter]);

  /* URL query sync for targets tab */
  useEffect(() => {
    const q = new URLSearchParams(sp.toString());
    const set = (k: string, v: string, keep: boolean) =>
      keep ? q.set(k, v) : q.delete(k);
    set("id", String(pid), true);
    set("tab", tab, tab !== "targets");
    set("tpage", String(tpage), tpage > 1);
    set("tsize", String(tsize), tsize !== 20);
    set("tf", targetFilter, targetFilter !== "all");
    set("tcode", codeFilter.trim(), !!codeFilter.trim());
    const qs = q.toString();
    const cur = sp.toString();
    if (qs !== cur) router.replace(`/project/?${qs}`, { scroll: false });
  }, [tab, tpage, tsize, targetFilter, codeFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { setTpage(1); }, [targetFilter, codeFilter]);

  /* ---------- actions ---------- */
  const delSelected = async () => {
    if (!targetSel.length) return;
    const res = await api.batchDeleteTargets(targetSel as number[]);
    msg.ok(`已删除 ${res.deleted} 个目标`);
    setTargetSel([]);
    load();
  };
  const delTarget = async (tid: number) => {
    await api.deleteTarget(tid);
    setTargetSel((s) => s.filter((id) => id !== tid));
    load();
  };
  const startScan = async (opts?: any) => {
    const o = opts || { ...scanOpts };
    if (o.scope === "alive" && !aliveCount) return msg.err("没有存活目标");
    try {
      await api.createScan(pid, o);
      setShowScan(false);
      msg.ok("扫描已开始");
      load();
    } catch (e: any) {
      msg.err(e.message || "启动失败");
    }
  };
  const doImport = async () => {
    try {
      if (importFiles.length) {
        let parsed = 0, added = 0, duplicates = 0;
        const failed: string[] = [];
        for (const f of importFiles) {
          try {
            const r = await api.uploadTargets(pid, f);
            parsed += r.parsed; added += r.added; duplicates += r.duplicates;
          } catch (e: any) {
            failed.push(`${f.name}: ${e.message || "解析失败"}`);
          }
        }
        msg.ok(`解析 ${parsed} 个，新增 ${added}，重复 ${duplicates}`);
        if (failed.length) msg.err(`部分文件失败——${failed.join("；")}`);
      } else {
        const res = await api.addTargets(pid, importText.split("\n"));
        msg.ok(`解析 ${res.parsed} 个，新增 ${res.added}，重复 ${res.duplicates}`);
      }
      setShowImport(false);
      setImportText("");
      setImportFiles([]);
      load();
    } catch (e: any) {
      msg.err(e.message || "导入失败");
    }
  };

  /* ---------- columns ---------- */
  const targetCols = useMemo<Col<any>[]>(() => [
    { key: "idx", title: "#", width: 50, fixed: true,
      render: (_r, i) => <span className="muted">{i + 1}</span> },
    { key: "url", title: "URL", fixed: true,
      render: (t) => (
        <span className="mono text-[12.5px]" style={{ wordBreak: "break-all" }}>{t.url}</span>
      ) },
    { key: "status", title: "状态", width: 100,
      render: (t) => (
        <>
          {t.latest
            ? <Tag color={t.latest.alive ? "green" : "red"}>{t.latest.alive ? "存活" : "失活"}</Tag>
            : <span className="muted">未扫描</span>}
          {t.latest?.protection && <Tag color="volcano" className="ml-1">防护</Tag>}
        </>
      ) },
    { key: "code", title: "HTTP", width: 76,
      render: (t) => t.latest?.status_code
        ? <Tag>{t.latest.status_code}</Tag> : <span className="muted">-</span> },
    { key: "title", title: "标题",
      render: (t) => <span className="text-[12.5px]">{t.latest?.title || "-"}</span> },
    { key: "fps", title: "指纹", render: (t) => <FpTags raw={t.fps} /> },
    { key: "shot", title: "截图", width: 110,
      render: (t) => t.latest?.screenshot ? (
        <a href={`/screenshots/${t.latest.screenshot}`} target="_blank" rel="noopener">
          <img src={`/screenshots/${t.latest.screenshot}`} loading="lazy" alt=""
            style={{ width: 90, border: "1px solid var(--border)", borderRadius: 4, display: "block" }} />
        </a>
      ) : <span className="muted">-</span> },
    { key: "src", title: "来源", width: 170,
      render: (t) => t.import_filename || t.import_source ? (
        <>
          <div className="mono text-[12px]">{t.import_filename || "粘贴输入"}</div>
          <div className="sub-line">{fmtTime(t.imported_at)}</div>
        </>
      ) : <span className="muted">历史导入</span> },
    { key: "op", title: "操作", width: 210, fixed: true,
      render: (t) => (
        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
          {t.latest && (
            <Link href={`/result/?id=${t.latest.id}`}>
              <button className="btn btn-sm">详情</button>
            </Link>
          )}
          <button className="btn btn-sm" onClick={() => {
            setEditTarget(t); setEditTargetUrl(t.url); setShowEditTarget(true);
          }}>编辑</button>
          <button className="btn btn-sm" disabled={expRunning}
            onClick={() => { setExpTargetIds([t.id]); setShowExposure(true); }}>测绘</button>
          <Confirm title="删除该目标？" onOk={() => delTarget(t.id)}>
            <button className="btn btn-sm btn-danger">删除</button>
          </Confirm>
        </div>
      ) },
  ], [expRunning]); // eslint-disable-line react-hooks/exhaustive-deps

  const { shown: shownTargetCols, visible: visibleTargetCols, save: saveTargetCols } =
    useColPrefs("target_cols", targetCols, 2);

  const scanCols = useMemo<Col<any>[]>(() => [
    { key: "id", title: "#", width: 70 },
    { key: "kind", title: "类型", width: 110,
      render: (s) => <Tag color={s.kind === "rescan" ? "purple" : "blue"}>
        {s.kind === "rescan" ? "二次扫描" : "全量扫描"}</Tag> },
    { key: "status", title: "状态", width: 130,
      render: (s) => s.status === "running"
        ? <Tag color="processing" className="pulsing">{s.done}/{s.total}</Tag>
        : statusTag(s.status) },
    { key: "n", title: "存活/总数", width: 110,
      render: (s) => `${s.alive}/${s.total}` },
    { key: "started_at", title: "开始时间", width: 160,
      render: (s) => fmtTime(s.started_at) },
    { key: "finished_at", title: "结束时间", width: 160,
      render: (s) => fmtTime(s.finished_at) },
    { key: "op", title: "操作", width: 90,
      render: (s) => (
        <Link href={`/scans/?id=${s.id}`} onClick={(e) => e.stopPropagation()}>
          <button className="btn btn-sm" disabled={s.status !== "done"}>查看</button>
        </Link>
      ) },
  ], []);

  const impCols = useMemo<Col<any>[]>(() => [
    { key: "created_at", title: "时间", width: 150,
      render: (r) => fmtTime(r.created_at) },
    { key: "source", title: "方式", width: 70,
      render: (r) => <Tag color={r.source === "file" ? "blue" : "default"}>
        {r.source === "file" ? "文件" : "文本"}</Tag> },
    { key: "filename", title: "文件名",
      render: (r) => <span className="mono text-[12px]">{r.filename || "粘贴输入"}</span> },
    { key: "parsed", title: "解析", width: 70 },
    { key: "added", title: "新增", width: 70 },
    { key: "duplicates", title: "重复", width: 70 },
  ], []);

  const expCols = useMemo<Col<any>[]>(() => [
    { key: "id", title: "#", width: 60 },
    { key: "kinds", title: "方式", width: 170,
      render: (r) => {
        let kinds: string[] = [];
        try { kinds = JSON.parse(r.options || "{}").kinds || []; } catch {}
        return (
          <>
            {kinds.slice(0, 3).map((k) => (
              <Tag key={k} color={expKindColor(k)} className="mr-0.5">{EXP_KIND_LABEL[k] || k}</Tag>
            ))}
            {kinds.length > 3 && (
              <Popover trigger={<Tag className="cursor-pointer">+{kinds.length - 3}</Tag>}>
                <div className="flex flex-wrap gap-1 max-w-[240px]">
                  {kinds.map((k) => <Tag key={k} color={expKindColor(k)}>{EXP_KIND_LABEL[k] || k}</Tag>)}
                </div>
              </Popover>
            )}
          </>
        );
      } },
    { key: "status", title: "状态", width: 130,
      render: (r) => r.status === "running"
        ? <Tag color="processing" className="pulsing">{r.done}/{r.total}</Tag>
        : statusTag(r.status) },
    { key: "found", title: "发现", width: 80,
      render: (r) => <span style={{ color: r.found ? "var(--red)" : "inherit" }}>{r.found}</span> },
    { key: "deep", title: "深扫", width: 140,
      render: (r) => r.deep_status === "running"
        ? <Tag color="processing" className="pulsing">深扫中 {r.deep_done}/{r.deep_total}</Tag>
        : r.deep_status === "done" ? <Tag color="green">已深扫</Tag>
        : r.deep_status === "failed" ? <Tag color="red">深扫失败</Tag>
        : <span className="muted">-</span> },
    { key: "started_at", title: "开始时间", width: 160, render: (r) => fmtTime(r.started_at) },
    { key: "finished_at", title: "结束时间", width: 160, render: (r) => fmtTime(r.finished_at) },
    { key: "op", title: "操作", width: 190,
      render: (r) => (
        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
          {r.status === "done" && r.deep_status !== "running" && (
            <button className="btn btn-sm" onClick={async () => {
              try {
                await api.deepScanExposure(r.id, 120);
                msg.ok("攻击面深扫已开始（指纹+截图）");
                loadExposure();
              } catch (e: any) { msg.err(e.message || "启动失败"); }
            }}>{r.deep_status === "done" ? "重新深扫" : "深扫"}</button>
          )}
          <Link href={`/exposure/?run=${r.id}`}>
            <button className="btn btn-sm" disabled={r.status !== "done"}>查看</button>
          </Link>
          <Confirm title="删除该次测绘及结果？" onOk={async () => {
            await api.deleteExposure(r.id); loadExposure();
          }}>
            <button className="btn btn-sm btn-danger">删除</button>
          </Confirm>
        </div>
      ) },
  ], [loadExposure]);

  if (!project) return <div className="py-20 text-center muted">加载中…</div>;

  const pct = running?.total ? Math.round((running.done / running.total) * 100) : 0;

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <button className="btn btn-sm" onClick={() => router.back()}>
          <ArrowLeft size={13} /> 返回
        </button>
        <span className="muted text-[13px]">
          <Link href="/projects/" className="hover:text-[var(--fg)]">项目</Link>
          <span className="mx-1.5">/</span>
          <span className="text-[var(--fg-2)]">{project.name}</span>
        </span>
      </div>

      <div className="card card-pad mb-4">
        <div className="flex items-center gap-8 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <div className="text-xl font-semibold">{project.name}</div>
            <div className="text-[12.5px] text-[var(--fg-3)] mt-1">{project.description}</div>
          </div>
          {[
            ["目标", project.targets?.length || 0, undefined],
            ["存活", aliveCount, "var(--green)"],
            ["失活", deadCount, "var(--red)"],
            ["未探测", unscannedCount, undefined],
            ["扫描轮次", project.scans?.length || 0, undefined],
          ].map(([l, v, c]) => (
            <div key={l as string} className="text-center">
              <div className="text-[11px] text-[var(--fg-3)]">{l}</div>
              <div className="text-[22px] font-semibold" style={{ color: c as string }}>{v as number}</div>
            </div>
          ))}
          <div className="flex gap-2 flex-wrap">
            <button className="btn" onClick={() => setShowImport(true)}>
              <Import size={13} /> 导入目标
            </button>
            <button className="btn btn-pri" disabled={!project.targets?.length || !!running}
              onClick={() => setShowScan(true)}>
              <Play size={13} /> 发起扫描
            </button>
            <button className="btn" disabled={!aliveCount || !!running}
              onClick={() => startScan({ scope: "alive", active_probe: true, screenshot: true, fingerprint: true, concurrency: 50 })}>
              <RefreshCw size={13} /> 二次扫描
            </button>
            <button className="btn" disabled={!aliveCount || expRunning}
              onClick={() => { setExpTargetIds([]); setShowExposure(true); }}>
              <Radar size={13} /> 暴露面测绘
            </button>
            <Popover trigger={<button className="btn"><EllipsisVertical size={14} /></button>}>
              <div className="grid gap-1">
                <button className="btn btn-ghost btn-sm justify-start"
                  onClick={() => {
                    setEditProjectForm({ name: project.name, description: project.description || "" });
                    setShowEditProject(true);
                  }}>编辑项目</button>
                <Confirm title="删除项目及全部目标、扫描、测绘记录？" onOk={async () => {
                  await api.deleteProject(pid);
                  msg.ok("项目已删除");
                  router.push("/projects/");
                }}>
                  <button className="btn btn-ghost btn-sm btn-danger justify-start">删除项目</button>
                </Confirm>
              </div>
            </Popover>
          </div>
        </div>
        {running && (
          <div className="mt-4">
            <div className="flex justify-between text-[12px] muted mb-1">
              <span>扫描 #{running.id} 进行中</span><span>{running.done}/{running.total}</span>
            </div>
            <Progress pct={pct} status="running" />
          </div>
        )}
      </div>

      <div className="card">
        <div className="px-4 pt-1">
          <Tabs
            active={tab}
            onChange={setTab}
            items={[
              { key: "targets", label: `目标 (${project.targets?.length || 0})` },
              { key: "scans", label: `扫描记录 (${project.scans?.length || 0})` },
              { key: "exposure", label: `暴露面 (${expRuns.length})` },
            ]}
          />
        </div>
        <div className="p-4">
          {tab === "targets" && (
            <>
              <div className="flex items-center gap-2 flex-wrap mb-3">
                <Confirm title={`删除选中的 ${targetSel.length} 个目标？`} onOk={delSelected}>
                  <button className="btn btn-sm btn-danger" disabled={!targetSel.length}>
                    删除选中{targetSel.length ? ` (${targetSel.length})` : ""}
                  </button>
                </Confirm>
                <button className="btn btn-sm" disabled={!targetSel.length || expRunning}
                  onClick={() => { setExpTargetIds(targetSel as number[]); setShowExposure(true); }}>
                  测绘选中{targetSel.length ? ` (${targetSel.length})` : ""}
                </button>
                <div className="flex rounded-md overflow-hidden border border-[var(--border)]">
                  {([["all", "全部"], ["alive", "存活"], ["dead", "失活"], ["unscanned", "未扫描"]] as const).map(([v, l]) => (
                    <button key={v}
                      className="px-3 py-1 text-[12px] border-r border-[var(--border)] last:border-r-0"
                      style={{
                        background: targetFilter === v ? "var(--accent)" : "var(--panel-2)",
                        color: targetFilter === v ? "#fff" : "var(--fg-2)",
                      }}
                      onClick={() => setTargetFilter(v)}>{l}</button>
                  ))}
                </div>
                <input className="ipt !py-1 text-[12px] w-44"
                  placeholder="状态码：200 / 200-399 / 4xx"
                  value={codeFilter} onChange={(e) => setCodeFilter(e.target.value)} />
                <ColSettings cols={targetCols} visible={visibleTargetCols} onChange={saveTargetCols} />
                <button className="btn btn-sm" onClick={async () => {
                  setShowImports(true);
                  setImports((await api.listImports(pid)).imports);
                }}>导入记录</button>
              </div>
              <DataTable
                cols={shownTargetCols}
                rows={filteredTargets}
                selection={{ keys: targetSel, onChange: setTargetSel }}
                expandable={(t) => (
                  <TargetExposure target={t} running={expRunning}
                    onScan={(tt) => { setExpTargetIds([tt.id]); setShowExposure(true); }} />
                )}
                pagerState={{ page: tpage, pageSize: tsize, onChange: (p, s) => { setTsize(s); setTpage(s !== tsize ? 1 : p); } }}
              />
            </>
          )}

          {tab === "scans" && (
            project.scans?.length ? (
              <DataTable cols={scanCols} rows={project.scans} pageSize={10}
                onRow={(s) => s.status === "done" && router.push(`/scans/?id=${s.id}`)} />
            ) : <Empty text="还没有扫描记录" />
          )}

          {tab === "exposure" && (
            expRuns.length ? (
              <DataTable cols={expCols} rows={expRuns} pageSize={10}
                expandable={(r) => <div className="p-3"><ExposureResults runId={r.id} /></div>} />
            ) : <Empty text="还没有测绘记录，点击右上角「暴露面测绘」" />
          )}
        </div>
      </div>

      {/* exposure scan modal */}
      <ExposureScanModal open={showExposure} onClose={() => setShowExposure(false)}
        project={project} targetIds={expTargetIds}
        onStarted={() => { setTab("exposure"); loadExposure(); }} />

      {/* import */}
      <Modal open={showImport} onClose={() => setShowImport(false)} title="导入目标"
        width={640}
        footer={<>
          <button className="btn" onClick={() => setShowImport(false)}>取消</button>
          <button className="btn btn-pri" onClick={doImport}>导入</button>
        </>}>
        <Tabs active={importTab} onChange={setImportTab}
          items={[{ key: "text", label: "粘贴 URL" }, { key: "file", label: "上传 xlsx / xls / txt" }]} />
        <div className="pt-4">
          {importTab === "text" ? (
            <textarea className="ipt w-full" rows={8}
              placeholder="每行一个，支持 http(s)://host/path、域名、IP:端口"
              value={importText} onChange={(e) => setImportText(e.target.value)} />
          ) : (
            <label className="block border border-dashed border-[var(--border)] rounded-lg p-8 text-center cursor-pointer hover:border-[var(--accent)] transition-colors">
              <Upload size={20} className="mx-auto mb-2 text-[var(--fg-3)]" />
              <div className="text-[13px] text-[var(--fg-2)]">点击或拖拽文件（可多选），xlsx/xls 自动提取所有 URL</div>
              <input type="file" multiple accept=".xlsx,.xls,.xlsm,.txt,.csv" className="hidden"
                onChange={(e) => setImportFiles(Array.from(e.target.files || []))} />
            </label>
          )}
          {importFiles.length > 0 && (
            <div className="mono text-[12px] mt-2 space-y-0.5">
              {importFiles.map((f) => <div key={f.name}>{f.name}</div>)}
            </div>
          )}
        </div>
      </Modal>

      {/* imports history */}
      <Modal open={showImports} onClose={() => setShowImports(false)} title="导入记录" width={680}>
        {imports.length
          ? <DataTable cols={impCols} rows={imports} pageSize={10} />
          : <Empty text="暂无导入记录" />}
      </Modal>

      {/* edit project */}
      <Modal open={showEditProject} onClose={() => setShowEditProject(false)} title="编辑项目"
        width={480}
        footer={<>
          <button className="btn" onClick={() => setShowEditProject(false)}>取消</button>
          <button className="btn btn-pri" onClick={async () => {
            if (!editProjectForm.name.trim()) return msg.err("名称不能为空");
            await api.updateProject(pid, editProjectForm);
            msg.ok("已保存");
            setShowEditProject(false);
            load();
          }}>保存</button>
        </>}>
        <div className="space-y-4">
          <div>
            <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">项目名称 *</div>
            <input className="ipt w-full" value={editProjectForm.name}
              onChange={(e) => setEditProjectForm({ ...editProjectForm, name: e.target.value })} />
          </div>
          <div>
            <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">描述</div>
            <textarea className="ipt w-full" rows={3} value={editProjectForm.description}
              onChange={(e) => setEditProjectForm({ ...editProjectForm, description: e.target.value })} />
          </div>
        </div>
      </Modal>

      {/* edit target */}
      <Modal open={showEditTarget} onClose={() => setShowEditTarget(false)} title="编辑目标 URL"
        width={480}
        footer={<>
          <button className="btn" onClick={() => setShowEditTarget(false)}>取消</button>
          <button className="btn btn-pri" onClick={async () => {
            if (!editTargetUrl.trim()) return msg.err("URL 不能为空");
            await api.updateTarget(editTarget.id, editTargetUrl.trim());
            msg.ok("已保存");
            setShowEditTarget(false);
            load();
          }}>保存</button>
        </>}>
        <div>
          <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">URL *</div>
          <input className="ipt w-full mono" value={editTargetUrl}
            onChange={(e) => setEditTargetUrl(e.target.value)} />
        </div>
      </Modal>

      {/* scan options */}
      <Modal open={showScan} onClose={() => setShowScan(false)} title="发起扫描" width={520}
        footer={<>
          <button className="btn" onClick={() => setShowScan(false)}>取消</button>
          <button className="btn btn-pri" onClick={() => startScan()}>开始</button>
        </>}>
        <div className="space-y-4">
          <div>
            <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">扫描范围</div>
            <div className="grid gap-2">
              <Radio value="all" current={scanOpts.scope}
                onChange={(v) => setScanOpts({ ...scanOpts, scope: v })}>
                全部目标（{project.targets?.length || 0}）
              </Radio>
              <Radio value="alive" current={scanOpts.scope}
                onChange={(v) => setScanOpts({ ...scanOpts, scope: v })}>
                仅存活目标（{aliveCount}，二次扫描）
              </Radio>
            </div>
          </div>
          {([
            ["active_probe", "主动探测（请求特征路径二次确认，可提高精度）"],
            ["screenshot", "网页截图（Playwright，同时采集渲染后 DOM/JS 信号）"],
            ["fingerprint", "指纹识别（规则库匹配；关闭后更快且不产出指纹列）"],
          ] as const).map(([k, l]) => (
            <div key={k} className="flex items-center justify-between gap-4">
              <span className="text-[13px]">{l}</span>
              <Switch checked={(scanOpts as any)[k]}
                onChange={(v) => setScanOpts({ ...scanOpts, [k]: v })} />
            </div>
          ))}
          <div className="flex items-center justify-between">
            <span className="text-[13px]">并发数</span>
            <input type="number" className="ipt w-24" min={1} max={200}
              value={scanOpts.concurrency}
              onChange={(e) => setScanOpts({ ...scanOpts, concurrency: Number(e.target.value) })} />
          </div>
        </div>
      </Modal>
    </div>
  );
}

export default function ProjectPage() {
  return (
    <Suspense>
      <ProjectDetail />
    </Suspense>
  );
}
