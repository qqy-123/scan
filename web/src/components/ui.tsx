"use client";
import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { X, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

/* ---------- Tag ---------- */
const TAG_COLORS: Record<string, string> = {
  green: "badge-green", red: "badge-red", orange: "badge-orange",
  blue: "badge-blue", geekblue: "badge-blue", purple: "badge-purple",
  cyan: "badge-cyan", magenta: "badge-magenta", volcano: "badge-orange",
  gold: "badge-orange", default: "badge-gray", gray: "badge-gray",
  processing: "badge-blue",
};
export function Tag({
  color = "default",
  children,
  className,
  style,
  onClick,
}: {
  color?: string;
  children: ReactNode;
  className?: string;
  style?: React.CSSProperties;
  onClick?: () => void;
}) {
  return (
    <span
      className={cn("tag", TAG_COLORS[color] || "badge-gray", className)}
      style={style}
      onClick={onClick}
    >
      {children}
    </span>
  );
}

/* ---------- Checkable tag (filter chips) ---------- */
export function Chip({
  checked,
  onChange,
  children,
  activeColor,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  children: ReactNode;
  activeColor?: string;
}) {
  return (
    <span
      className={cn(
        "tag cursor-pointer select-none border border-transparent",
        checked ? "badge-blue" : "badge-gray opacity-60",
      )}
      style={checked && activeColor ? { background: `${activeColor}22`, color: activeColor } : undefined}
      onClick={() => onChange(!checked)}
    >
      {children}
    </span>
  );
}

/* ---------- Modal ---------- */
export function Modal({
  open,
  onClose,
  title,
  width = 640,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  width?: number;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  if (!open || typeof document === "undefined") return null;
  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center bg-black/60 backdrop-blur-[2px] overflow-y-auto py-[6vh]"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="card w-full mx-4"
        style={{ maxWidth: width, background: "var(--panel)" }}
      >
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--border)]">
          <div className="text-[15px] font-medium">{title}</div>
          <button className="btn-ghost btn btn-sm" onClick={onClose}>
            <X size={15} />
          </button>
        </div>
        <div className="px-5 py-4 max-h-[70vh] overflow-y-auto">{children}</div>
        {footer !== undefined && (
          <div className="flex justify-end gap-2 px-5 py-3 border-t border-[var(--border)]">
            {footer}
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}

/* ---------- Popover ---------- */
export function Popover({
  trigger,
  children,
  align = "right",
}: {
  trigger: ReactNode;
  children: ReactNode;
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);
  return (
    <div className="relative inline-block" ref={ref}>
      <span onClick={() => setOpen((v) => !v)} className="inline-flex">
        {trigger}
      </span>
      {open && (
        <div
          className="pop"
          style={{ [align === "right" ? "right" : "left"]: 0, top: "calc(100% + 6px)" }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

/* ---------- Checkbox ---------- */
export function Checkbox({
  checked,
  onChange,
  label,
  indeterminate,
}: {
  checked: boolean;
  onChange?: (v: boolean) => void;
  label?: ReactNode;
  indeterminate?: boolean;
}) {
  return (
    <label className="inline-flex items-center gap-2 cursor-pointer select-none text-[13px]">
      <input
        type="checkbox"
        checked={checked}
        ref={(el) => {
          if (el) el.indeterminate = !!indeterminate && !checked;
        }}
        onChange={(e) => onChange?.(e.target.checked)}
        className="accent-[#3b82f6] w-3.5 h-3.5"
      />
      {label}
    </label>
  );
}

/* ---------- Spin / Empty / Progress ---------- */
export function Spin({ tip }: { tip?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-[var(--fg-3)]">
      <Loader2 size={16} className="animate-spin" />
      {tip && <span className="text-[13px]">{tip}</span>}
    </div>
  );
}

export function Empty({ text = "暂无数据" }: { text?: string }) {
  return (
    <div className="py-12 text-center text-[var(--fg-3)] text-[13px]">{text}</div>
  );
}

export function Progress({ pct, status }: { pct: number; status?: string }) {
  const color =
    status === "failed" ? "var(--red)"
    : status === "done" || pct >= 100 ? "var(--green)"
    : "var(--accent)";
  return (
    <div className="w-full h-1.5 rounded bg-[var(--border)] overflow-hidden">
      <div
        className={cn("h-full rounded transition-all", status === "running" && "pulsing")}
        style={{ width: `${Math.min(100, pct)}%`, background: color }}
      />
    </div>
  );
}

/* ---------- Pagination ---------- */
export function Pager({
  page,
  pageSize,
  total,
  onChange,
  sizes = [10, 20, 30, 50, 100],
}: {
  page: number;
  pageSize: number;
  total: number;
  onChange: (p: number, ps: number) => void;
  sizes?: number[];
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const btn = (p: number, label: ReactNode, dis = false, act = false) => (
    <button
      key={label as string}
      disabled={dis}
      onClick={() => onChange(p, pageSize)}
      className={cn(
        "btn btn-sm min-w-[28px] justify-center",
        act && "btn-pri",
      )}
    >
      {label}
    </button>
  );
  const items: ReactNode[] = [btn(page - 1, "‹", page <= 1)];
  const lo = Math.max(1, Math.min(page - 2, pages - 4));
  const hi = Math.min(pages, lo + 4);
  if (lo > 1) items.push(btn(1, "1"), <span key="e1" className="muted">…</span>);
  for (let i = lo; i <= hi; i++) items.push(btn(i, String(i), false, i === page));
  if (hi < pages)
    items.push(<span key="e2" className="muted">…</span>, btn(pages, String(pages)));
  items.push(btn(page + 1, "›", page >= pages));
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className="muted text-[12px] mr-1">共 {total} 条</span>
      {items}
      <select
        className="ipt ml-1 !py-1 text-[12px]"
        value={pageSize}
        onChange={(e) => onChange(1, Number(e.target.value))}
      >
        {sizes.map((s) => (
          <option key={s} value={s}>
            {s} / 页
          </option>
        ))}
      </select>
    </div>
  );
}

/* ---------- Tabs ---------- */
export function Tabs({
  items,
  active,
  onChange,
  extra,
}: {
  items: { key: string; label: ReactNode }[];
  active: string;
  onChange: (k: string) => void;
  extra?: ReactNode;
}) {
  return (
    <div className="flex items-center gap-1 border-b border-[var(--border)]">
      {items.map((t) => (
        <button
          key={t.key}
          onClick={() => onChange(t.key)}
          className={cn(
            "px-4 py-2.5 text-[13.5px] border-b-2 -mb-px transition-colors",
            active === t.key
              ? "border-[var(--accent)] text-[var(--fg)] font-medium"
              : "border-transparent text-[var(--fg-3)] hover:text-[var(--fg-2)]",
          )}
        >
          {t.label}
        </button>
      ))}
      {extra && <div className="ml-auto pb-1">{extra}</div>}
    </div>
  );
}

/* ---------- Stat card ---------- */
export function Stat({
  label,
  value,
  hint,
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="card card-pad flex items-center gap-3.5">
      {icon && (
        <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[var(--accent-soft)] text-[var(--accent)] shrink-0">
          {icon}
        </div>
      )}
      <div className="min-w-0">
        <div className="text-[12px] text-[var(--fg-3)]">{label}</div>
        <div className="text-[22px] font-semibold leading-7 truncate">{value}</div>
        {hint && <div className="text-[11px] text-[var(--fg-3)] mt-0.5">{hint}</div>}
      </div>
    </div>
  );
}

/* ---------- Tags input (multi-value chips) ---------- */
export function TagsInput({
  value,
  onChange,
  placeholder,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const v = draft.trim();
    if (v && !value.includes(v)) onChange([...value, v]);
    setDraft("");
  };
  return (
    <div className="flex flex-wrap items-center gap-1.5 ipt !py-1.5 cursor-text"
      onClick={(e) => (e.currentTarget.querySelector("input") as HTMLInputElement)?.focus()}>
      {value.map((v) => (
        <span key={v} className="tag badge-blue flex items-center gap-1">
          {v}
          <X size={11} className="cursor-pointer"
            onClick={() => onChange(value.filter((x) => x !== v))} />
        </span>
      ))}
      <input
        className="bg-transparent outline-none flex-1 min-w-[120px] text-[12.5px]"
        placeholder={value.length ? "" : placeholder}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") { e.preventDefault(); add(); }
          if (e.key === "Backspace" && !draft && value.length)
            onChange(value.slice(0, -1));
        }}
        onBlur={add}
      />
    </div>
  );
}

/* ---------- Switch ---------- */
export function Switch({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="relative inline-flex h-5 w-9 rounded-full transition-colors shrink-0"
      style={{ background: checked ? "var(--accent)" : "var(--border)" }}
    >
      <span
        className="absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform"
        style={{ transform: checked ? "translateX(18px)" : "translateX(2px)" }}
      />
    </button>
  );
}

/* ---------- Radio group ---------- */
export function Radio({
  value,
  current,
  onChange,
  children,
  disabled,
}: {
  value: string;
  current: string;
  onChange: (v: string) => void;
  children: ReactNode;
  disabled?: boolean;
}) {
  return (
    <label
      className={cn(
        "inline-flex items-center gap-2 text-[13px]",
        disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
      )}
    >
      <input
        type="radio"
        checked={current === value}
        disabled={disabled}
        onChange={() => onChange(value)}
        className="accent-[#3b82f6] w-3.5 h-3.5"
      />
      {children}
    </label>
  );
}

/* ---------- Confirm ---------- */
export function Confirm({
  title,
  onOk,
  children,
}: {
  title: string;
  onOk: () => void;
  children: ReactNode;
}) {
  return (
    <Popover trigger={children}>
      <div className="text-[13px] mb-2.5 max-w-[240px]">{title}</div>
      <div className="flex justify-end gap-2">
        <button className="btn btn-sm btn-danger" onClick={onOk}>确认</button>
      </div>
    </Popover>
  );
}

/* ---------- Message (light toast) ---------- */
import { toast } from "sonner";
export const msg = {
  ok: (t: string) => toast.success(t),
  err: (t: string) => toast.error(t),
  info: (t: string) => toast(t),
};
