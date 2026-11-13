"use client";
import { useMemo, useState, type ReactNode } from "react";
import { Settings2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { loadColPrefs, saveColPrefs } from "@/lib/colprefs";
import { Checkbox, Empty, Pager, Popover, Spin } from "@/components/ui";

export interface Col<T> {
  key: string;
  title: ReactNode;
  width?: number | string;
  render?: (row: T, idx: number) => ReactNode;
  fixed?: boolean; // not hideable via col settings
}

export function ColSettings<T>({
  cols,
  visible,
  onChange,
}: {
  cols: Col<T>[];
  visible: string[];
  onChange: (v: string[]) => void;
}) {
  const hideable = cols.filter((c) => !c.fixed);
  return (
    <Popover
      trigger={
        <button className="btn btn-sm">
          <Settings2 size={13} /> 列设置
        </button>
      }
    >
      <div className="grid gap-2 max-h-64 overflow-y-auto">
        {hideable.map((c) => (
          <Checkbox
            key={c.key}
            checked={visible.includes(c.key)}
            onChange={(v) =>
              onChange(
                v
                  ? [...visible, c.key]
                  : visible.filter((k) => k !== c.key),
              )
            }
            label={c.title}
          />
        ))}
      </div>
    </Popover>
  );
}

export function useColPrefs(key: string, cols: Col<any>[], version = 1) {
  const all = useMemo(() => cols.map((c) => c.key), [cols]);
  const [visible, setVisible] = useState<string[]>(() =>
    typeof window === "undefined" ? all : loadColPrefs(key, all, version),
  );
  const shown = useMemo(
    () => cols.filter((c) => c.fixed || visible.includes(c.key)),
    [cols, visible],
  );
  const save = (v: string[]) => {
    setVisible(v);
    saveColPrefs(key, v, all, version);
  };
  return { shown, visible, save };
}

export function DataTable<T extends Record<string, any>>({
  cols,
  rows,
  rowKey = "id",
  loading,
  pageSize = 20,
  pageSizeOptions,
  expandable,
  selection,
  onRow,
  empty,
  scrollY,
  pagerState,
}: {
  cols: Col<T>[];
  rows: T[];
  rowKey?: string | ((r: T) => string | number);
  loading?: boolean;
  pageSize?: number;
  pageSizeOptions?: number[];
  expandable?: (row: T) => ReactNode;
  selection?: {
    keys: (string | number)[];
    onChange: (keys: (string | number)[]) => void;
  };
  onRow?: (row: T) => void;
  empty?: ReactNode;
  scrollY?: number;
  /** external pagination control: when provided, paging state is owned by caller */
  pagerState?: { page: number; pageSize: number; onChange: (p: number, s: number) => void };
}) {
  const [page, setPage] = useState(1);
  const [ps, setPs] = useState(pageSize);
  const [expanded, setExpanded] = useState<Set<string | number>>(new Set());
  const keyOf = (r: T) => (typeof rowKey === "function" ? rowKey(r) : r[rowKey]);

  const cur = pagerState
    ? { page: pagerState.page, ps: pagerState.pageSize }
    : { page, ps };
  const total = rows.length;
  const slice = rows.slice((cur.page - 1) * cur.ps, cur.page * cur.ps);
  const setPager = (p: number, s: number) => {
    if (pagerState) pagerState.onChange(p, s);
    else {
      setPage(p);
      setPs(s);
    }
  };

  const selKeys = selection?.keys ?? [];
  const allChecked = slice.length > 0 && slice.every((r) => selKeys.includes(keyOf(r)));
  const toggleAll = (v: boolean) => {
    if (!selection) return;
    const ids = slice.map(keyOf);
    selection.onChange(v ? [...new Set([...selKeys, ...ids])] : selKeys.filter((k) => !ids.includes(k)));
  };
  const toggle = (r: T, v: boolean) => {
    if (!selection) return;
    const k = keyOf(r);
    selection.onChange(v ? [...selKeys, k] : selKeys.filter((x) => x !== k));
  };

  return (
    <div>
      <div className="overflow-x-auto" style={scrollY ? { maxHeight: scrollY, overflowY: "auto" } : undefined}>
        <table className="dt">
          <thead>
            <tr>
              {expandable && <th style={{ width: 30 }} />}
              {selection && (
                <th style={{ width: 34 }}>
                  <Checkbox checked={allChecked} onChange={toggleAll}
                    indeterminate={!allChecked && slice.some((r) => selKeys.includes(keyOf(r)))} />
                </th>
              )}
              {cols.map((c) => (
                <th key={c.key} style={{ width: c.width }}>
                  {c.title}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={cols.length + 2}>
                  <Spin />
                </td>
              </tr>
            ) : slice.length === 0 ? (
              <tr>
                <td colSpan={cols.length + 2}>{empty ?? <Empty />}</td>
              </tr>
            ) : (
              slice.map((r, i) => {
                const k = keyOf(r);
                const isExp = expanded.has(k);
                return [
                  <tr
                    key={k}
                    className={cn(isExp && "expanded", onRow && "cursor-pointer")}
                    onClick={() => onRow?.(r)}
                  >
                    {expandable && (
                      <td
                        className="!py-2 w-[30px] cursor-pointer text-[var(--fg-3)]"
                        onClick={(e) => {
                          e.stopPropagation();
                          const s = new Set(expanded);
                          isExp ? s.delete(k) : s.add(k);
                          setExpanded(s);
                        }}
                      >
                        <span
                          className="inline-block transition-transform"
                          style={{ transform: isExp ? "rotate(90deg)" : "none" }}
                        >
                          ›
                        </span>
                      </td>
                    )}
                    {selection && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selKeys.includes(k)}
                          onChange={(v) => toggle(r, v)}
                        />
                      </td>
                    )}
                    {cols.map((c) => (
                      <td key={c.key}>{c.render ? c.render(r, i) : r[c.key]}</td>
                    ))}
                  </tr>,
                  isExp && expandable ? (
                    <tr key={`${k}-x`}>
                      <td colSpan={cols.length + 2} className="!p-0">
                        {expandable(r)}
                      </td>
                    </tr>
                  ) : null,
                ];
              })
            )}
          </tbody>
        </table>
      </div>
      <div className="flex justify-end pt-3">
        <Pager page={cur.page} pageSize={cur.ps} total={total} onChange={setPager} sizes={pageSizeOptions} />
      </div>
    </div>
  );
}
