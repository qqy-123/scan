import { format, formatDistanceToNow } from "date-fns";
import { zhCN } from "date-fns/locale";

export function fmtTime(s?: string | null): string {
  if (!s) return "-";
  try {
    return format(new Date(String(s).replace(" ", "T")), "MM-dd HH:mm");
  } catch {
    return String(s).slice(0, 16);
  }
}

export function fmtFull(s?: string | null): string {
  if (!s) return "-";
  try {
    return format(new Date(String(s).replace(" ", "T")), "yyyy-MM-dd HH:mm:ss");
  } catch {
    return String(s);
  }
}

export function ago(s?: string | null): string {
  if (!s) return "-";
  try {
    return formatDistanceToNow(new Date(String(s).replace(" ", "T")), {
      addSuffix: true,
      locale: zhCN,
    });
  } catch {
    return fmtTime(s);
  }
}

export function fmtDur(a?: string | null, b?: string | null): string {
  if (!a || !b) return "-";
  const ms = new Date(String(b).replace(" ", "T")).getTime()
    - new Date(String(a).replace(" ", "T")).getTime();
  if (ms < 0) return "-";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60 ? ` ${s % 60}s` : ""}`;
  return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m`;
}
