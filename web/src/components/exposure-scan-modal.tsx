"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { Checkbox, Modal, Radio, msg } from "@/components/ui";

const IN_SITE = [
  { v: "js", t: "JS 接口提取（隐藏 API / 后台路径 / sourcemap + 参数攻击点分类 + 敏感信息检测）" },
  { v: "dir", t: "目录爆破（字典探测后台/备份/配置；命中目录自动递归多级；覆盖存活子域根与入口前缀）" },
];
const DOMAIN = [
  { v: "sub", t: "子域名收集（crt.name / crt.sh 证书透明日志 + 页面提取，解析到的自动探活）" },
  { v: "brute", t: "子域爆破（内置字典 DNS 枚举 + HTTP 验证）" },
  { v: "host", t: "Host 碰撞（对目标 IP 用 SNI+Host 探隐藏虚拟主机，依赖子域发现结果）" },
  { v: "origin", t: "源站探测 fuckcdn（对子域/测绘 IP 及所在 C 段做 SNI 碰撞，定位 CDN 后真实源站 IP）" },
  { v: "takeover", t: "子域接管检测（CNAME 悬空指向 GitHub/Heroku/S3 等可认领服务的子域）" },
  { v: "wayback", t: "历史 URL（web.archive.org CDX 档案：已下线但可能仍存活的老接口/带参端点）" },
  { v: "port", t: "端口扫描（存活主机 TOP 端口 + banner 识别 + Redis/ES/Mongo/Docker 未授权检测）" },
];

export function ExposureScanModal({
  open,
  onClose,
  project,          // fixed project; undefined → picker
  targetIds = [],
  onStarted,
}: {
  open: boolean;
  onClose: () => void;
  project?: any;
  targetIds?: number[];
  onStarted: () => void;
}) {
  const [opts, setOpts] = useState({
    scope: "alive",
    kinds: ["js", "dir", "sub"],
    auto_deep: true,
    deep_limit: 200,
    fingerprint: true,
  });
  const [projects, setProjects] = useState<any[]>([]);
  const [pid, setPid] = useState<number | null>(null);
  const [picked, setPicked] = useState<any>(null);
  const [engines, setEngines] = useState({ fofa: false, hunter: false, quake: false, any: false });
  const [starting, setStarting] = useState(false);

  const active = project || picked;
  const targetCount = active?.targets?.length || 0;
  const aliveCount = (active?.targets || []).filter((t: any) => t.alive).length;

  useEffect(() => {
    if (!open) return;
    api.getSettings().then((s) => {
      const fofa = !!(s.fofa_email && s.fofa_key);
      const hunter = !!s.hunter_key;
      const quake = !!s.quake_key;
      setEngines({ fofa, hunter, quake, any: fofa || hunter || quake });
    });
    if (!project && !projects.length) {
      api.listProjects().then(setProjects);
    }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const pickProject = async (id: number) => {
    setPicked(null);
    if (!id) return;
    setPicked(await api.getProject(id));
  };

  const toggleKind = (v: string, on: boolean) =>
    setOpts((o) => ({
      ...o,
      kinds: on ? [...o.kinds, v] : o.kinds.filter((k) => k !== v),
    }));

  const start = async () => {
    const p = active;
    if (!p) return msg.err("先选择一个项目");
    if (!opts.kinds.length) return msg.err("至少选一种测绘方式");
    setStarting(true);
    try {
      await api.createExposure(p.id, { ...opts, target_ids: targetIds });
      msg.ok("测绘任务已开始");
      onClose();
      onStarted();
    } catch (e: any) {
      msg.err(e.message || "发起失败");
    } finally {
      setStarting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="发起暴露面测绘"
      width={680}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button className="btn btn-pri" onClick={start} disabled={starting}>
            {starting ? "发起中…" : "开始测绘"}
          </button>
        </>
      }
    >
      <div className="space-y-4">
        {!project && (
          <div>
            <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">选择项目</div>
            <select
              className="ipt w-full"
              value={pid ?? ""}
              onChange={(e) => {
                const id = Number(e.target.value);
                setPid(id || null);
                pickProject(id);
              }}
            >
              <option value="">选择要测绘的项目</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
        )}
        <div>
          <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">扫描范围</div>
          {targetIds.length ? (
            <div className="text-[12.5px] text-[var(--accent)] bg-[var(--accent-soft)] rounded px-3 py-2">
              已选 {targetIds.length} 个目标，仅对所选目标测绘
            </div>
          ) : (
            <div className="flex gap-5">
              <Radio value="alive" current={opts.scope}
                onChange={(v) => setOpts({ ...opts, scope: v })}>
                存活目标（{aliveCount}）
              </Radio>
              <Radio value="all" current={opts.scope}
                onChange={(v) => setOpts({ ...opts, scope: v })}>
                全部目标（{targetCount}）
              </Radio>
            </div>
          )}
        </div>

        <div>
          <div className="text-[12px] font-medium text-[var(--fg-3)] mb-1">站内测绘</div>
          <div className="grid gap-1.5">
            {IN_SITE.map((o) => (
              <Checkbox key={o.v} checked={opts.kinds.includes(o.v)}
                onChange={(v) => toggleKind(o.v, v)} label={o.t} />
            ))}
          </div>
        </div>
        <div>
          <div className="text-[12px] font-medium text-[var(--fg-3)] mb-1">域名扩展</div>
          <div className="grid gap-1.5">
            {DOMAIN.map((o) => (
              <Checkbox key={o.v} checked={opts.kinds.includes(o.v)}
                onChange={(v) => toggleKind(o.v, v)} label={o.t} />
            ))}
          </div>
        </div>
        <div>
          <div className="text-[12px] font-medium text-[var(--fg-3)] mb-1">
            网络空间测绘
            <Link href="/settings/" target="_blank"
              className="text-[var(--accent)] text-[11px] ml-2">去配置 →</Link>
          </div>
          <Checkbox
            checked={opts.kinds.includes("net")}
            onChange={(v) => toggleKind("net", v)}
            label={`资产搜索引擎（${engines.fofa ? "FOFA✓" : "FOFA✗"} · ${engines.hunter ? "鹰图✓" : "鹰图✗"} · ${engines.quake ? "Quake✓" : "Quake✗"}）`}
          />
          {!engines.any && (
            <div className="text-[11.5px] text-[var(--fg-3)] mt-1">
              未配置任何引擎 key —— 到系统设置里填 FOFA / 鹰图 / Quake key 即可启用
            </div>
          )}
        </div>
        <div>
          <Checkbox
            checked={opts.auto_deep}
            onChange={(v) => setOpts({ ...opts, auto_deep: v })}
            label="完成后自动深扫（对真实攻击面截图 + 指纹识别，与首页相同的回声页不算攻击面）"
          />
        </div>
        {opts.auto_deep && (
          <div className="flex items-center gap-3">
            <span className="text-[12.5px] text-[var(--fg-2)]">截图上限</span>
            <input
              type="number" className="ipt w-28" min={10} max={1000}
              value={opts.deep_limit}
              onChange={(e) => setOpts({ ...opts, deep_limit: Number(e.target.value) })}
            />
            <Checkbox
              checked={opts.fingerprint}
              onChange={(v) => setOpts({ ...opts, fingerprint: v })}
              label="指纹识别"
            />
          </div>
        )}
      </div>
    </Modal>
  );
}
