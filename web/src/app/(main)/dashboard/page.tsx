"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LabelList,
} from "recharts";
import {
  Crosshair, Globe, CloudCog, Zap, Fingerprint, Plus, Database, Activity,
} from "lucide-react";
import { api } from "@/lib/api";
import { ago } from "@/lib/fmt";
import { Stat, Tag, Empty } from "@/components/ui";

const CHART_TIP = {
  contentStyle: {
    background: "var(--panel-2)", border: "1px solid var(--border)",
    borderRadius: 8, fontSize: 12,
  },
  labelStyle: { color: "var(--fg)" },
  itemStyle: { color: "var(--fg-2)" },
};

export default function DashboardPage() {
  const [data, setData] = useState<any>(null);
  const [projects, setProjects] = useState<any[]>([]);

  useEffect(() => {
    Promise.all([api.overview(), api.listProjects()]).then(([ov, pj]) => {
      setData(ov);
      setProjects(pj.slice(0, 6));
    });
  }, []);

  const d = data || {};
  const donut = [
    { name: "存活", value: d.alive ?? 0, color: "#22c55e" },
    { name: "失活", value: d.dead ?? 0, color: "#ef4444" },
    { name: "未探测", value: d.unscanned ?? 0, color: "#3a4358" },
  ];
  const statusDist = Object.entries(d.status_dist || {}).map(([k, v]) => ({
    name: k, value: v as number,
    color: k.startsWith("2") ? "#3b82f6" : k.startsWith("3") ? "#a855f7"
      : k.startsWith("4") ? "#f59e0b" : "#ef4444",
  }));
  const topFps = (d.top_fingerprints || []).slice(0, 10).reverse();

  const unscanned = (p: any) => p.target_count - p.alive_count - p.dead_count;
  const pct = (n: number, p: any) => (p.target_count ? `${(n / p.target_count) * 100}%` : "0%");

  return (
    <div>
      <div className="flex items-start justify-between mb-5">
        <div>
          <div className="text-xl font-semibold">总览</div>
          <div className="text-[12.5px] text-[var(--fg-3)] mt-0.5">系统全局状态 · 实时刷新</div>
        </div>
        <Link href="/projects/">
          <button className="btn btn-pri"><Plus size={14} /> 新建项目</button>
        </Link>
      </div>

      <div className="grid grid-cols-5 gap-4 mb-4">
        <Stat label="项目" value={d.projects ?? 0} icon={<Crosshair size={18} />}
          hint={`${d.targets ?? 0} 目标`} />
        <Stat label="存活目标" value={d.alive ?? 0} icon={<Globe size={18} />}
          hint={<span><span className="text-[var(--red)]">失活 {d.dead ?? 0}</span> · 未探测 {d.unscanned ?? 0}</span>} />
        <Stat label="扫描轮次" value={d.scans ?? 0} icon={<CloudCog size={18} />}
          hint={<span className="text-[var(--accent)]">运行中 {d.running ?? 0}</span>} />
        <Stat label="HTTP 200" value={d.status_dist?.["200"] ?? 0} icon={<Zap size={18} />}
          hint={`${Object.keys(d.status_dist || {}).length} 种状态码`} />
        <Stat label="指纹规则" value={d.rules_count ?? 0} icon={<Fingerprint size={18} />}
          hint="内置 + 自定义" />
      </div>

      <div className="grid grid-cols-3 gap-4 mb-4">
        <div className="card card-pad">
          <div className="text-[13px] font-medium mb-2">目标存活占比</div>
          <div className="relative">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={donut} innerRadius="58%" outerRadius="80%" dataKey="value"
                     stroke="var(--bg)" strokeWidth={2}>
                  {donut.map((s) => <Cell key={s.name} fill={s.color} />)}
                </Pie>
                <Tooltip {...CHART_TIP} />
                <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none" style={{ paddingBottom: 34 }}>
              <div className="text-[26px] font-semibold">{d.alive ?? 0}</div>
              <div className="text-[11px] text-[var(--fg-3)]">存活</div>
            </div>
          </div>
        </div>
        <div className="card card-pad">
          <div className="text-[13px] font-medium mb-2">HTTP 状态码分布</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={statusDist} innerRadius="45%" outerRadius="72%" dataKey="value"
                   label={{ fontSize: 11, fill: "var(--fg-2)" }} stroke="var(--bg)" strokeWidth={2}>
                {statusDist.map((s) => <Cell key={s.name} fill={s.color} />)}
              </Pie>
              <Tooltip {...CHART_TIP} />
              <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="card card-pad">
          <div className="text-[13px] font-medium mb-2">指纹命中 TOP 10</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={topFps} layout="vertical" margin={{ left: 8, right: 24 }}>
              <CartesianGrid stroke="var(--border-soft)" horizontal={false} />
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={110}
                     tick={{ fontSize: 11, fill: "var(--fg-2)" }} axisLine={false} tickLine={false} />
              <Tooltip {...CHART_TIP} />
              <Bar dataKey="count" fill="#3b82f6" barSize={11} radius={[0, 5, 5, 0]}>
                <LabelList dataKey="count" position="right" style={{ fontSize: 10, fill: "var(--fg-3)" }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card card-pad">
          <div className="flex items-center justify-between mb-1">
            <div className="text-[13px] font-medium flex items-center gap-1.5">
              <Activity size={14} className="text-[var(--accent)]" /> 最近扫描
            </div>
            <Link href="/projects/" className="text-[12px] text-[var(--accent)]">全部 →</Link>
          </div>
          {d.recent_scans?.length ? (
            <div className="divide-y divide-[var(--border-soft)]">
              {d.recent_scans.map((s: any) => (
                <div key={s.id} className="flex items-center gap-2.5 py-2.5">
                  <Tag color={s.kind === "rescan" ? "purple" : "blue"}>
                    {s.kind === "rescan" ? "二次" : "全量"}
                  </Tag>
                  <div className="flex-1 min-w-0">
                    <div className="text-[13.5px] font-medium truncate">{s.project_name}</div>
                    <div className="text-[11.5px] text-[var(--fg-3)]">
                      轮次 #{s.id} · {s.status === "running" ? `进行中 ${s.done}/${s.total}` : `存活 ${s.alive}/${s.total}`}
                    </div>
                  </div>
                  <span className="text-[11.5px] text-[var(--fg-3)] whitespace-nowrap">{ago(s.started_at)}</span>
                  <Link href={`/scans/?id=${s.id}`}>
                    <button className="btn btn-sm">查看</button>
                  </Link>
                </div>
              ))}
            </div>
          ) : <Empty text="暂无扫描" />}
        </div>
        <div className="card card-pad">
          <div className="flex items-center justify-between mb-1">
            <div className="text-[13px] font-medium flex items-center gap-1.5">
              <Database size={14} className="text-[var(--accent)]" /> 项目存活概览
            </div>
            <Link href="/projects/" className="text-[12px] text-[var(--accent)]">全部 →</Link>
          </div>
          {projects.length ? (
            <div className="divide-y divide-[var(--border-soft)]">
              {projects.map((p) => (
                <div key={p.id} className="py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 text-[13.5px] font-medium truncate">{p.name}</div>
                    <Link href={`/project/?id=${p.id}`}>
                      <button className="btn btn-sm">查看</button>
                    </Link>
                  </div>
                  <div className="flex h-2 rounded overflow-hidden bg-[var(--border)] my-2">
                    <div style={{ width: pct(p.alive_count, p), background: "var(--green)" }} />
                    <div style={{ width: pct(p.dead_count, p), background: "var(--red)" }} />
                    <div style={{ width: pct(unscanned(p), p), background: "#3a4358" }} />
                  </div>
                  <div className="flex gap-3 text-[11.5px]">
                    <span className="text-[var(--green)]">{p.alive_count} 存活</span>
                    <span className="text-[var(--red)]">{p.dead_count} 失活</span>
                    <span className="muted">{unscanned(p)} 未探测</span>
                  </div>
                </div>
              ))}
            </div>
          ) : <Empty text="暂无项目" />}
        </div>
      </div>
    </div>
  );
}
