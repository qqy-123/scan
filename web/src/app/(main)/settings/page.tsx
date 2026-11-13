"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Switch, Tag, msg } from "@/components/ui";

const DEFAULTS = {
  concurrency: 50, browser_concurrency: 4,
  active_probe: true, screenshot: true, fingerprint: true,
  fp_probe_budget: 80,
  connect_timeout: 8, read_timeout: 15, proxy: "",
  fofa_email: "", fofa_key: "", hunter_key: "", quake_key: "",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">{label}</div>
      {children}
    </div>
  );
}

export default function SettingsPage() {
  const [form, setForm] = useState<any>({ ...DEFAULTS });
  const [info, setInfo] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  useEffect(() => {
    Promise.all([api.getSettings(), api.systemInfo()]).then(([s, i]) => {
      setForm((f: any) => ({ ...f, ...s }));
      setInfo(i);
    });
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const payload: any = { ...form };
      for (const k of ["fofa_key", "hunter_key", "quake_key"]) {
        if (!payload[k] || String(payload[k]).includes("****")) delete payload[k];
      }
      if (newPassword) {
        if (newPassword.length < 6) { msg.err("密码至少 6 位"); setSaving(false); return; }
        payload.new_password = newPassword;
      }
      const data = await api.updateSettings(payload);
      setForm((f: any) => ({ ...f, ...data }));
      if (newPassword) {
        msg.ok("密码已修改，请重新登录");
        localStorage.removeItem("scan_token");
        setTimeout(() => (location.href = "/login/"), 800);
        return;
      }
      msg.ok("已保存");
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    const { fofa_email, fofa_key, hunter_key, quake_key, ...rest } = DEFAULTS;
    setForm((f: any) => ({ ...f, ...rest }));
  };

  const num = (k: string, min = 1, max = 500) => (
    <input type="number" className="ipt w-full" min={min} max={max}
      value={form[k]}
      onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} />
  );
  const pw = (k: string, ph: string) => (
    <input type="password" className="ipt w-full" placeholder={ph}
      value={form[k] || ""}
      onChange={(e) => setForm({ ...form, [k]: e.target.value })} />
  );

  return (
    <div>
      <div className="flex items-start justify-between mb-5">
        <div>
          <div className="text-xl font-semibold">系统配置</div>
          <div className="text-[12.5px] text-[var(--fg-3)] mt-0.5">扫描默认值 · 探测参数 · 系统信息</div>
        </div>
        <div className="flex gap-2">
          <button className="btn" onClick={reset}>恢复默认</button>
          <button className="btn btn-pri" onClick={save} disabled={saving}>
            {saving ? "保存中…" : "保存"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-[1.4fr_1fr] gap-4">
        <div>
          <div className="card card-pad mb-4">
            <div className="text-[14px] font-medium mb-4">扫描默认值</div>
            <div className="grid grid-cols-2 gap-4">
              <Field label="目标并发（存活探测）">{num("concurrency", 1, 500)}</Field>
              <Field label="浏览器并发（抓包/截图，耗内存）">{num("browser_concurrency", 1, 16)}</Field>
              <Field label="连接超时（秒）">{num("connect_timeout", 1, 60)}</Field>
              <Field label="读取超时（秒）">{num("read_timeout", 1, 120)}</Field>
              <Field label="主动探测路径配额/目标（0=仅首页评估）">{num("fp_probe_budget", 0, 500)}</Field>
            </div>
            {([
              ["active_probe", "主动探测默认开启（请求特征路径二次确认）"],
              ["screenshot", "网页截图默认开启（同时采集渲染后信号）"],
              ["fingerprint", "指纹识别默认开启（关闭的扫描不产出指纹列）"],
            ] as const).map(([k, l]) => (
              <div key={k} className="flex items-center justify-between py-1.5">
                <span className="text-[13px]">{l}</span>
                <Switch checked={!!form[k]} onChange={(v) => setForm({ ...form, [k]: v })} />
              </div>
            ))}
            <Field label="出站代理（扫描流量走代理；Host碰撞/源站探测为直连 IP 不受代理影响）">
              <input className="ipt w-full max-w-[420px]"
                placeholder="http://127.0.0.1:8080 或 socks5://127.0.0.1:1080，留空直连"
                value={form.proxy || ""}
                onChange={(e) => setForm({ ...form, proxy: e.target.value })} />
            </Field>
            <div className="border-t border-[var(--border)] my-3" />
            <Field label="平台登录密码（修改后需要重新登录，至少 6 位；留空则不修改）">
              <input type="password" className="ipt w-full max-w-[320px]"
                placeholder="留空保持不变"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)} />
            </Field>
            <div className="text-[11.5px] text-[var(--fg-3)]">
              这些值作为「发起扫描」弹窗的默认值和引擎的全局参数；单次扫描仍可在弹窗里覆盖。
            </div>
          </div>

          <div className="card card-pad">
            <div className="text-[14px] font-medium mb-4">网络空间测绘 API</div>
            <div className="grid grid-cols-2 gap-4">
              <Field label="FOFA 邮箱">
                <input className="ipt w-full" placeholder="fofa.info 账号邮箱"
                  value={form.fofa_email || ""}
                  onChange={(e) => setForm({ ...form, fofa_email: e.target.value })} />
              </Field>
              <Field label="FOFA Key">{pw("fofa_key", "fofa.info API key")}</Field>
              <Field label="Hunter（鹰图）Key">{pw("hunter_key", "hunter.qianxin.com API key")}</Field>
              <Field label="Quake（360）Key">{pw("quake_key", "quake.360.net API key")}</Field>
            </div>
            <div className="text-[11.5px] text-[var(--fg-3)]">
              用于暴露面扫描的「网络空间测绘」选项（FOFA / 鹰图 / Quake 资产搜索）。
              已配置的 key 以 **** 掩码显示，输入新值才会覆盖，留空保存不会改变已存 key。
            </div>
          </div>
        </div>

        <div>
          <div className="card card-pad mb-4">
            <div className="text-[14px] font-medium mb-3">系统信息</div>
            {info ? (
              <div className="space-y-2 text-[13px]">
                {([
                  ["平台版本", info.version],
                  ["Python", `${info.python} · ${info.platform}`],
                  ["指纹规则", `${info.rules_total} 条（自定义 ${info.rules_custom} · 禁用 ${info.rules_disabled}）`],
                ] as const).map(([l, v]) => (
                  <div key={l} className="flex gap-3">
                    <span className="text-[var(--fg-3)] w-20 shrink-0">{l}</span>
                    <span>{v}</span>
                  </div>
                ))}
                <div className="flex gap-3">
                  <span className="text-[var(--fg-3)] w-20 shrink-0">浏览器引擎</span>
                  <Tag color={info.browser === "running" ? "green" : "default"}>
                    {info.browser === "running" ? "运行中" : "空闲"}
                  </Tag>
                </div>
                <div className="flex gap-3">
                  <span className="text-[var(--fg-3)] w-20 shrink-0">数据库</span>
                  <span>{info.db_engine}（{info.db_size_mb} MB）</span>
                </div>
                <div className="flex gap-3">
                  <span className="text-[var(--fg-3)] w-20 shrink-0">截图存档</span>
                  <span>{info.screenshots} 张 / {info.screenshots_mb} MB</span>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-4 rounded bg-[var(--border)] animate-pulse"
                    style={{ width: `${85 - i * 12}%` }} />
                ))}
              </div>
            )}
          </div>
          <div className="card card-pad">
            <div className="text-[14px] font-medium mb-3">关于</div>
            <div className="text-[13px] text-[var(--fg-2)] leading-7">
              SCAN 安全检测平台 — 项目化资产测绘 + 源码指纹识别。<br />
              指纹学习 / 规则自定义 / 浏览器抓包识别 / 存活探测 / 截图分析。
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
