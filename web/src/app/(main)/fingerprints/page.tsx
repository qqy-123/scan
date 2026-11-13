"use client";
import { useMemo, useState } from "react";
import { useEffect } from "react";
import { api } from "@/lib/api";
import {
  Checkbox, Confirm, Empty, Modal, Switch, Tabs, Tag, TagsInput, msg,
} from "@/components/ui";
import { DataTable, type Col } from "@/components/data-table";

const LIST_FIELDS = [
  { key: "html", label: "html（页面源码正则）", ph: "回车添加，如 wp-content/" },
  { key: "scriptSrc", label: "scriptSrc（脚本 URL 正则）", ph: "如 wp-includes/js/" },
  { key: "scripts", label: "scripts（内联脚本正则）", ph: "内联 <script> 内容匹配" },
  { key: "url", label: "url（任意数据包 URL 正则）", ph: "匹配所有请求包 URL" },
  { key: "xhr", label: "xhr（XHR/fetch URL 正则）", ph: "匹配接口请求 URL" },
  { key: "favicon", label: "favicon（mmh3 哈希）", ph: "favicon mmh3 值" },
  { key: "implies", label: "implies（命中后推断）", ph: "如 PHP" },
  { key: "excludes", label: "excludes（互斥剔除）", ph: "如 Apache" },
  { key: "requires", label: "requires（依赖指纹命中才评估）", ph: "如 WordPress" },
  { key: "requiresCategory", label: "requiresCategory（依赖分类）", ph: "如 CMS" },
];
const MAP_FIELDS = [
  { key: "headers", label: "headers", kph: "响应头名（正则）" },
  { key: "cookies", label: "cookies", kph: "Cookie 名（正则）" },
  { key: "meta", label: "meta", kph: "meta name" },
  { key: "js", label: "js（JS 全局变量）", kph: "如 jQuery.fn.jquery" },
  { key: "probe", label: "probe（主动探测路径）", kph: "如 /wp-login.php" },
];

const pktColor = (t: string) =>
  (({ document: "blue", xhr: "purple", fetch: "purple", script: "cyan",
     stylesheet: "geekblue", image: "default", font: "default" }) as Record<string, string>)[t] || "default";

const splitKV = (m: string): [string, string] => {
  const i = m.indexOf("=");
  return i === -1 ? [m, ".*"] : [m.slice(0, i), m.slice(i + 1)];
};

interface EditState {
  name: string; category: string; website: string;
  lists: Record<string, string[]>;
  maps: Record<string, { k: string; p: string[] }[]>;
  domText: string;
}
const blankEdit = (): EditState => ({
  name: "", category: "", website: "",
  lists: Object.fromEntries(LIST_FIELDS.map((f) => [f.key, []])),
  maps: Object.fromEntries(MAP_FIELDS.map((f) => [f.key, []])),
  domText: "",
});

function rawToEdit(raw: any): EditState {
  const e = blankEdit();
  e.name = raw.name || "";
  e.category = raw.category || "";
  e.website = raw.website || "";
  for (const f of LIST_FIELDS) e.lists[f.key] = (raw[f.key] || []).map(String);
  for (const f of MAP_FIELDS)
    e.maps[f.key] = Object.entries(raw[f.key] || {})
      // probe 条件组（{all/any/headers/status}）表单表达不了 — 跳过，
      // 保存时由 editToRule 原样带回；JSON 模式可编辑
      .filter(([, v]) => f.key !== "probe" || !v || Array.isArray(v))
      .map(([k, v]) => ({
        k, p: (Array.isArray(v) ? v : [v]).map(String),
      }));
  e.domText = raw.dom ? JSON.stringify(raw.dom, null, 2) : "";
  return e;
}
function editToRule(e: EditState, orig?: any) {
  const rule: any = { name: e.name.trim(), category: e.category.trim() || "自定义" };
  if (e.website.trim()) rule.website = e.website.trim();
  for (const f of LIST_FIELDS) {
    const v = e.lists[f.key].filter((x) => x && x.trim());
    if (v.length) rule[f.key] = v;
  }
  for (const f of MAP_FIELDS) {
    const m: Record<string, string[]> = {};
    for (const row of e.maps[f.key])
      if (row.k.trim()) m[row.k.trim()] = row.p.length ? row.p : [".*"];
    if (Object.keys(m).length) rule[f.key] = m;
  }
  // carry over probe condition groups the form can't express
  for (const [k, v] of Object.entries((orig && orig.probe) || {}))
    if (v && typeof v === "object" && !Array.isArray(v))
      (rule.probe ||= {})[k] = v;
  if (e.domText.trim()) rule.dom = JSON.parse(e.domText);
  return rule;
}

export default function FingerprintsPage() {
  const [rules, setRules] = useState<any[]>([]);
  const [learnUrl, setLearnUrl] = useState("");
  const [extracting, setExtracting] = useState(false);
  const [preview, setPreview] = useState<any>(null);
  const [learnTab, setLearnTab] = useState("features");
  const [fpName, setFpName] = useState("");
  const [fpCategory, setFpCategory] = useState("自定义");
  const [probePaths, setProbePaths] = useState("");
  const [sel, setSel] = useState<any>({
    paths: [], keywords: [], meta: [], cookies: [], favicon: true,
    urls: [], xhr: [], headers: [], js: [], pktKeys: [],
  });

  const metaKeys = useMemo(
    () => (preview ? Object.entries(preview.meta || {}).map(([k, v]) => `${k}=${v}`) : []),
    [preview],
  );

  const loadRules = async () => setRules(await api.rulesDetail());
  useEffect(() => { loadRules(); }, []);

  /* ---------- learn ---------- */
  const extract = async () => {
    if (!learnUrl.trim()) return msg.err("请输入 URL");
    setExtracting(true);
    setPreview(null);
    try {
      const data = await api.learnPreview(learnUrl.trim());
      setPreview(data);
      if (data.ok) {
        setLearnTab("features");
        setSel({
          paths: data.paths.slice(0, 3), keywords: [], meta: metaKeys,
          cookies: data.cookies, favicon: !!data.favicon,
          urls: data.url_suggest.slice(0, 3), xhr: data.xhr_suggest,
          headers: data.headers, js: data.js, pktKeys: [],
        });
        setFpName("");
      }
    } catch (e: any) {
      msg.err(e.message || "提取失败");
    } finally {
      setExtracting(false);
    }
  };

  const canSave = fpName.trim() &&
    (sel.paths.length || sel.keywords.length || sel.meta.length ||
      sel.cookies.length || sel.favicon || probePaths.trim() ||
      sel.urls.length || sel.xhr.length || sel.headers.length ||
      sel.js.length || sel.pktKeys.length);

  const save = async () => {
    const pktUrls = sel.pktKeys.map((u: string) => {
      try { return new URL(u).pathname || u; } catch { return u; }
    });
    const selected = {
      html: [...sel.paths, ...sel.keywords],
      scriptSrc: sel.paths.filter((p: string) => p.includes("/")),
      url: [...sel.urls, ...pktUrls],
      xhr: sel.xhr,
      headers: Object.fromEntries(sel.headers.map(splitKV)),
      js: sel.js,
      meta: Object.fromEntries(sel.meta.map(splitKV)),
      cookies: sel.cookies,
      favicon: sel.favicon ? preview.favicon : null,
      probe: probePaths.split(",").map((s) => s.trim()).filter(Boolean),
    };
    try {
      await api.saveCustomRule({ name: fpName, category: fpCategory, selected });
      msg.ok(`指纹「${fpName}」已入库`);
      setPreview(null);
      setLearnUrl("");
      loadRules();
    } catch (e: any) {
      msg.err(e.message || "保存失败");
    }
  };

  /* ---------- rule editor ---------- */
  const [showEdit, setShowEdit] = useState(false);
  const [editTab, setEditTab] = useState("form");
  const [editName, setEditName] = useState("");
  const [editDisabled, setEditDisabled] = useState(false);
  const [editJson, setEditJson] = useState("");
  const [editError, setEditError] = useState("");
  const [edit, setEdit] = useState<EditState>(blankEdit());
  const [editRaw, setEditRaw] = useState<any>(null);

  const openEdit = async (r: any) => {
    setEditError("");
    setEditTab("form");
    const data = await api.ruleRaw(r.name);
    setEditName(r.name);
    setEditDisabled(!!data.disabled);
    const raw = data.rule || { name: r.name, category: "自定义", html: [] };
    setEditRaw(raw);
    setEdit(rawToEdit(raw));
    setEditJson(JSON.stringify(raw, null, 2));
    setShowEdit(true);
  };

  const onEditTab = (key: string) => {
    setEditError("");
    if (key === "json") {
      try { setEditJson(JSON.stringify(editToRule(edit, editRaw), null, 2)); setEditTab(key); }
      catch (e: any) { setEditError(`dom JSON 错误：${e.message}`); }
    } else {
      try { setEdit(rawToEdit(JSON.parse(editJson))); setEditTab(key); }
      catch (e: any) { setEditError(`JSON 格式错误：${e.message}`); }
    }
  };

  const saveEdit = async () => {
    setEditError("");
    let rule;
    try {
      rule = editTab === "json" ? JSON.parse(editJson) : editToRule(edit, editRaw);
    } catch (e: any) {
      setEditError(`格式错误：${e.message}`);
      return;
    }
    if (!rule.name?.trim()) { setEditError("名称不能为空"); return; }
    if (editDisabled) rule._disabled = true;
    try {
      await api.updateRule(rule);
      msg.ok("已保存（同名覆盖生效）");
      setShowEdit(false);
      loadRules();
    } catch (e: any) {
      setEditError(e.message || "保存失败");
    }
  };

  /* ---------- columns ---------- */
  const ruleCols = useMemo<Col<any>[]>(() => [
    { key: "name", title: "名称", width: 180 },
    { key: "category", title: "分类", width: 140 },
    { key: "signals", title: "信号",
      render: (r) => r.disabled ? <span className="muted">-</span> : (
        <>
          {Object.entries(r.signals || {}).map(([k, v]) => (
            <Tag key={k} className="mb-0.5 mr-0.5">{k}{typeof v === "number" ? `×${v}` : ""}</Tag>
          ))}
        </>
      ) },
    { key: "file", title: "来源", width: 110,
      render: (r) => r.disabled ? <Tag color="red">已禁用</Tag>
        : r.file === "custom.json" ? <Tag color="purple">自定义</Tag>
        : <Tag>{r.file}</Tag> },
    { key: "op", title: "操作", width: 190,
      render: (r) => (
        <div className="flex gap-1">
          <button className="btn btn-sm" onClick={() => openEdit(r)}>编辑</button>
          <button className="btn btn-sm" onClick={async () => {
            await api.setRuleDisabled(r.name, !r.disabled);
            msg.ok(r.disabled ? "已启用" : "已禁用");
            loadRules();
          }}>{r.disabled ? "启用" : "禁用"}</button>
          {r.file === "custom.json" && !r.disabled && (
            <Confirm title="删除自定义规则？" onOk={async () => {
              await api.deleteCustomRule(r.name);
              msg.ok("已删除");
              loadRules();
            }}>
              <button className="btn btn-sm btn-danger">删除</button>
            </Confirm>
          )}
        </div>
      ) },
  ], []); // eslint-disable-line react-hooks/exhaustive-deps

  const pktCols = useMemo<Col<any>[]>(() => [
    { key: "type", title: "类型", width: 90,
      render: (r) => <Tag color={pktColor(r.type)}>{r.type}</Tag> },
    { key: "url", title: "URL",
      render: (r) => <span className="mono text-[12px]" style={{ wordBreak: "break-all" }}>{r.url}</span> },
    { key: "status", title: "状态", width: 90,
      render: (r) => <Tag color={r.status < 400 ? "green" : "red"}>{r.status}</Tag> },
  ], []);

  const checkList = (opts: string[], val: string[], k: string, cols = 2) => (
    <div className={`grid gap-1.5`} style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
      {opts.map((o) => (
        <Checkbox key={o} checked={val.includes(o)}
          onChange={(v) =>
            setSel((s: any) => ({
              ...s,
              [k]: v ? [...s[k], o] : s[k].filter((x: string) => x !== o),
            }))}
          label={<span className="mono text-[12px]" style={{ wordBreak: "break-all" }}>{o}</span>} />
      ))}
    </div>
  );

  return (
    <div>
      <div className="mb-5">
        <div className="text-xl font-semibold">指纹库</div>
        <div className="text-[12.5px] text-[var(--fg-3)] mt-0.5">
          源码/系统指纹规则 · 学习 · 编辑 · 启停
        </div>
      </div>

      {/* learn */}
      <div className="card card-pad mb-4">
        <div className="text-[14px] font-medium mb-3">指纹学习</div>
        <div className="flex gap-0 max-w-[560px]">
          <input className="ipt flex-1 !rounded-r-none" value={learnUrl}
            placeholder="输入已知系统的 URL，例如 https://xxx.com"
            onChange={(e) => setLearnUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && extract()} />
          <button className="btn btn-pri !rounded-l-none" onClick={extract} disabled={extracting}>
            {extracting ? "提取中…" : "提取特征"}
          </button>
        </div>
        <div className="text-[11.5px] text-[var(--fg-3)] mt-2">
          浏览器访问站点，抓全部触发数据包并提取源码特征，勾选后保存为指纹
        </div>

        {preview && !preview.ok && (
          <div className="mt-4 text-[13px] text-[var(--red)] bg-[rgba(239,68,68,.08)] border border-[rgba(239,68,68,.3)] rounded px-3 py-2">
            {preview.error}
          </div>
        )}
        {preview?.ok && (
          <>
            <div className="grid grid-cols-2 gap-x-8 mt-4 text-[13px]">
              <div className="flex gap-2 py-1"><span className="text-[var(--fg-3)] w-20">最终 URL</span><span className="mono text-[12px]" style={{ wordBreak: "break-all" }}>{preview.final_url}</span></div>
              <div className="flex gap-2 py-1"><span className="text-[var(--fg-3)] w-20">标题</span><span>{preview.title}</span></div>
              <div className="flex gap-2 py-1"><span className="text-[var(--fg-3)] w-20">favicon mmh3</span><span className="mono">{preview.favicon ?? "未获取"}</span></div>
              <div className="flex gap-2 py-1"><span className="text-[var(--fg-3)] w-20">已识别</span>
                <span>{preview.detected.length
                  ? preview.detected.map((d: any) => (
                      <Tag key={d.name} color={d.confidence === "confirmed" ? "green" : "orange"} className="mr-0.5">{d.name}</Tag>
                    ))
                  : <span className="muted">无（新指纹）</span>}
                </span>
              </div>
            </div>
            <div className="mt-3">
              <Tabs active={learnTab} onChange={setLearnTab} items={[
                { key: "features", label: "特征选择" },
                { key: "packets", label: `数据包（${preview.packets.length}）` },
              ]} />
              <div className="pt-4 space-y-5">
                {learnTab === "features" ? (
                  <>
                    {!!preview.url_suggest.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">数据包路径特征（url 字段 · 匹配访问触发的所有请求 URL）</div>
                        {checkList(preview.url_suggest, sel.urls, "urls", 3)}
                      </div>
                    )}
                    {!!preview.xhr_suggest.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">接口特征（xhr 字段 · 匹配 XHR/fetch 请求）</div>
                        {checkList(preview.xhr_suggest, sel.xhr, "xhr", 3)}
                      </div>
                    )}
                    {!!preview.headers.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">响应头特征（headers 字段 · 来自数据包响应头）</div>
                        {checkList(preview.headers, sel.headers, "headers")}
                      </div>
                    )}
                    {!!preview.js.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">JS 全局变量（js 字段 · 渲染后探测）</div>
                        {checkList(preview.js, sel.js, "js")}
                      </div>
                    )}
                    {!!preview.paths.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">页面路径特征（html/scriptSrc 字段 · 来自 HTML src/href）</div>
                        {checkList(preview.paths, sel.paths, "paths", 3)}
                      </div>
                    )}
                    {!!preview.keywords.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">页面关键字（html 字段 · 注释 / Powered-by 等）</div>
                        {checkList(preview.keywords, sel.keywords, "keywords")}
                      </div>
                    )}
                    {!!metaKeys.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">Meta</div>
                        {checkList(metaKeys, sel.meta, "meta")}
                      </div>
                    )}
                    {!!preview.cookies.length && (
                      <div>
                        <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">Cookie 名</div>
                        {checkList(preview.cookies, sel.cookies, "cookies", 4)}
                      </div>
                    )}
                    {preview.favicon && (
                      <Checkbox checked={sel.favicon}
                        onChange={(v) => setSel((s: any) => ({ ...s, favicon: v }))}
                        label={`使用 favicon hash (${preview.favicon})`} />
                    )}
                    <div>
                      <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">自定义探测路径（probe 字段 · 可选，逗号分隔，如 /admin/login）</div>
                      <input className="ipt w-[480px]" value={probePaths} placeholder="/path1, /path2"
                        onChange={(e) => setProbePaths(e.target.value)} />
                    </div>
                    <div className="flex gap-2">
                      <input className="ipt w-60" placeholder="指纹名称（必填）" value={fpName}
                        onChange={(e) => setFpName(e.target.value)} />
                      <input className="ipt w-40" placeholder="分类" value={fpCategory}
                        onChange={(e) => setFpCategory(e.target.value)} />
                      <button className="btn btn-pri" disabled={!canSave} onClick={save}>保存指纹</button>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="text-[11.5px] text-[var(--fg-3)]">
                      访问该站点时浏览器触发的全部请求包。勾选某行可将其路径加入 url 指纹特征。
                    </div>
                    <DataTable cols={pktCols} rows={preview.packets} rowKey="url" pageSize={10}
                      selection={{ keys: sel.pktKeys, onChange: (k) => setSel((s: any) => ({ ...s, pktKeys: k })) }} />
                  </>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* rule library */}
      <div className="card card-pad">
        <div className="text-[14px] font-medium mb-3">
          指纹库（{rules.filter((r) => !r.disabled).length} 生效 / {rules.length} 总计）
        </div>
        <DataTable cols={ruleCols} rows={rules} rowKey="name" />
      </div>

      {/* rule editor */}
      <Modal open={showEdit} onClose={() => setShowEdit(false)}
        title={`编辑指纹：${edit.name || editName}`} width={820}
        footer={<>
          <button className="btn" onClick={() => setShowEdit(false)}>取消</button>
          <button className="btn btn-pri" onClick={saveEdit}>保存</button>
        </>}>
        <div className="text-[11.5px] text-[var(--fg-3)] mb-2">
          所有字段均可修改，保存到 custom.json 同名覆盖内置；删除自定义覆盖即恢复。
          模式支持 <code className="mono">\;confidence:N</code> 权重和 <code className="mono">\;version:\1</code> 版本提取。
          {editDisabled && <Tag color="red" className="ml-2">当前禁用</Tag>}
        </div>
        <Tabs active={editTab} onChange={onEditTab} items={[
          { key: "form", label: "结构化编辑" },
          { key: "json", label: "JSON 源码" },
        ]} />
        <div className="pt-4">
          {editTab === "form" ? (
            <div className="space-y-3.5">
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <div className="text-[12px] text-[var(--fg-2)] mb-1">名称</div>
                  <input className="ipt w-full" value={edit.name}
                    onChange={(e) => setEdit({ ...edit, name: e.target.value })} />
                </div>
                <div>
                  <div className="text-[12px] text-[var(--fg-2)] mb-1">分类</div>
                  <input className="ipt w-full" value={edit.category}
                    onChange={(e) => setEdit({ ...edit, category: e.target.value })} />
                </div>
                <div>
                  <div className="text-[12px] text-[var(--fg-2)] mb-1">官网</div>
                  <input className="ipt w-full" placeholder="https://" value={edit.website}
                    onChange={(e) => setEdit({ ...edit, website: e.target.value })} />
                </div>
              </div>
              {LIST_FIELDS.map((f) => (
                <div key={f.key}>
                  <div className="text-[12px] text-[var(--fg-2)] mb-1">{f.label}</div>
                  <TagsInput value={edit.lists[f.key]} placeholder={f.ph}
                    onChange={(v) =>
                      setEdit({ ...edit, lists: { ...edit.lists, [f.key]: v } })} />
                </div>
              ))}
              {MAP_FIELDS.map((f) => (
                <div key={f.key}>
                  <div className="text-[12px] text-[var(--fg-2)] mb-1">{f.label}</div>
                  {edit.maps[f.key].map((row, i) => (
                    <div key={i} className="flex gap-2 mb-1.5">
                      <input className="ipt w-52 !py-1 text-[12px]" placeholder={f.kph} value={row.k}
                        onChange={(e) => {
                          const m = [...edit.maps[f.key]];
                          m[i] = { ...m[i], k: e.target.value };
                          setEdit({ ...edit, maps: { ...edit.maps, [f.key]: m } });
                        }} />
                      <div className="flex-1">
                        <TagsInput value={row.p} placeholder="匹配模式（回车添加多条）"
                          onChange={(v) => {
                            const m = [...edit.maps[f.key]];
                            m[i] = { ...m[i], p: v };
                            setEdit({ ...edit, maps: { ...edit.maps, [f.key]: m } });
                          }} />
                      </div>
                      <button className="btn btn-sm btn-danger" onClick={() => {
                        const m = edit.maps[f.key].filter((_, j) => j !== i);
                        setEdit({ ...edit, maps: { ...edit.maps, [f.key]: m } });
                      }}>删</button>
                    </div>
                  ))}
                  <button className="btn btn-sm" onClick={() =>
                    setEdit({ ...edit, maps: { ...edit.maps, [f.key]: [...edit.maps[f.key], { k: "", p: [] }] } })
                  }>+ 添加</button>
                </div>
              ))}
              <div>
                <div className="text-[12px] text-[var(--fg-2)] mb-1">dom（选择器 → 条件 JSON，可选）</div>
                <textarea className="ipt w-full mono text-[12px]" rows={3}
                  placeholder='{"#app": {"text": ["Powered by"]}}'
                  value={edit.domText}
                  onChange={(e) => setEdit({ ...edit, domText: e.target.value })} />
              </div>
            </div>
          ) : (
            <textarea className="ipt w-full mono text-[12px]" rows={20} spellCheck={false}
              value={editJson} onChange={(e) => setEditJson(e.target.value)} />
          )}
          {editError && (
            <div className="mt-2 text-[12.5px] text-[var(--red)]">{editError}</div>
          )}
        </div>
      </Modal>
    </div>
  );
}
