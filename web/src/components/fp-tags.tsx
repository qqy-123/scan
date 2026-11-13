"use client";
import { useMemo } from "react";
import { Tag } from "@/components/ui";

export interface Fp {
  name: string;
  version?: string;
  category?: string;
  score?: number;
  level?: string;
  confidence?: string;
  evidence?: { field: string; key?: string; pattern?: string }[];
}

const LV: Record<string, { text: string; color: string }> = {
  confirmed: { text: "确认", color: "green" },
  high: { text: "高可信", color: "orange" },
  low: { text: "低可信", color: "default" },
};
const lvText = (l: string) => (LV[l] || LV.low).text;
const lvColor = (l: string) => (LV[l] || LV.low).color;

export function fpLevel(f: Fp): string {
  if (f.level) return f.level;
  if (f.confidence === "implied") return "low";
  const fields = new Set((f.evidence || []).map((e) => e.field));
  if (["probe", "favicon", "dom"].some((x) => fields.has(x))) return "confirmed";
  return (f.score || 0) >= 100 ? "high" : "low";
}

export function parseFps(raw?: string | Fp[] | null): Fp[] {
  if (Array.isArray(raw)) return raw;
  if (!raw) return [];
  try {
    return JSON.parse(raw) || [];
  } catch {
    return [];
  }
}

export function FpTags({ raw }: { raw?: string | Fp[] | null }) {
  const list = useMemo(() => parseFps(raw), [raw]);
  if (!list.length) return <Tag>无记录</Tag>;
  return (
    <>
      {list.map((f) => {
        const lv = fpLevel(f);
        const fields = [
          ...new Set((f.evidence || []).map((e) => e.field)),
        ].join("/");
        return (
          <span
            key={f.name}
            title={`${f.category || ""} · score ${f.score ?? "-"}${
              fields ? " · 证据 " + fields : ""
            }`}
          >
            <Tag color={lvColor(lv)} className="mb-0.5">
              {lvText(lv)}·{f.name}
              {f.version ? ` ${f.version}` : ""}
            </Tag>{" "}
          </span>
        );
      })}
    </>
  );
}
