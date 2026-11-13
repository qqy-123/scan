"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Plus } from "lucide-react";
import { api } from "@/lib/api";
import { fmtFull } from "@/lib/fmt";
import { Confirm, Empty, Modal, Tag, msg } from "@/components/ui";
import { DataTable, type Col } from "@/components/data-table";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<any>(null);
  const [form, setForm] = useState({ name: "", description: "" });

  const load = async () => {
    setLoading(true);
    try {
      setProjects(await api.listProjects());
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const submit = async () => {
    if (!form.name.trim()) return msg.err("请输入项目名称");
    if (editing) {
      await api.updateProject(editing.id, form);
      msg.ok("已保存");
    } else {
      await api.createProject(form);
      msg.ok("项目已创建");
    }
    setShowForm(false);
    load();
  };

  const cols = useMemo<Col<any>[]>(
    () => [
      {
        key: "name", title: "项目名称",
        render: (p) => <span className="font-medium">{p.name}</span>,
      },
      { key: "target_count", title: "目标数", width: 90 },
      {
        key: "alive", title: "存活/失活", width: 130,
        render: (p) => (
          <span>
            <Tag color="green">{p.alive_count}</Tag>
            <span className="muted mx-1.5">/</span>
            <Tag color="red">{p.dead_count}</Tag>
          </span>
        ),
      },
      { key: "scan_count", title: "扫描轮次", width: 90 },
      {
        key: "created_at", title: "创建时间", width: 180,
        render: (p) => <span className="mono text-[12px]">{fmtFull(p.created_at)}</span>,
      },
      {
        key: "op", title: "操作", width: 190,
        render: (p) => (
          <div className="flex gap-1.5">
            <Link href={`/project/?id=${p.id}`}>
              <button className="btn btn-sm">查看</button>
            </Link>
            <button
              className="btn btn-sm"
              onClick={() => {
                setEditing(p);
                setForm({ name: p.name, description: p.description || "" });
                setShowForm(true);
              }}
            >编辑</button>
            <Confirm
              title="删除项目及其全部目标和扫描记录？"
              onOk={async () => {
                await api.deleteProject(p.id);
                msg.ok("项目已删除");
                load();
              }}
            >
              <button className="btn btn-sm btn-danger">删除</button>
            </Confirm>
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div>
      <div className="flex items-start justify-between mb-5">
        <div>
          <div className="text-xl font-semibold">项目</div>
          <div className="text-[12.5px] text-[var(--fg-3)] mt-0.5">
            资产管理 · 共 {projects.length} 个项目
          </div>
        </div>
        <button
          className="btn btn-pri"
          onClick={() => {
            setEditing(null);
            setForm({ name: "", description: "" });
            setShowForm(true);
          }}
        >
          <Plus size={14} /> 新建项目
        </button>
      </div>

      <div className="card card-pad">
        <DataTable cols={cols} rows={projects} loading={loading}
          empty={<Empty text="还没有项目，点击右上角新建" />} />
      </div>

      <Modal
        open={showForm}
        onClose={() => setShowForm(false)}
        title={editing ? "编辑项目" : "新建项目"}
        width={480}
        footer={
          <>
            <button className="btn" onClick={() => setShowForm(false)}>取消</button>
            <button className="btn btn-pri" onClick={submit}>
              {editing ? "保存" : "创建"}
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">项目名称 *</div>
            <input
              className="ipt w-full"
              placeholder="例如：2026Q4 资产梳理"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div>
            <div className="text-[12.5px] text-[var(--fg-2)] mb-1.5">描述</div>
            <textarea
              className="ipt w-full"
              rows={3}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
        </div>
      </Modal>
    </div>
  );
}
