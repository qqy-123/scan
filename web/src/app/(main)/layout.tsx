"use client";
import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import Link from "next/link";
import {
  LayoutDashboard,
  Crosshair,
  Radar,
  Fingerprint,
  Settings,
  LogOut,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/cn";

const NAV = [
  { href: "/dashboard/", label: "仪表盘", icon: LayoutDashboard },
  { href: "/projects/", label: "项目管理", icon: Crosshair },
  { href: "/exposure/", label: "暴露面测绘", icon: Radar },
  { href: "/fingerprints/", label: "指纹规则", icon: Fingerprint },
  { href: "/settings/", label: "系统设置", icon: Settings },
];

export default function MainLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ok, setOk] = useState(false);

  useEffect(() => {
    if (!localStorage.getItem("scan_token")) {
      router.replace("/login/?next=" + encodeURIComponent(pathname));
    } else {
      setOk(true);
    }
  }, [router, pathname]);

  if (!ok) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="w-[196px] shrink-0 border-r border-[var(--border)] bg-[var(--bg-soft)] flex flex-col fixed inset-y-0">
        <div className="flex items-center gap-2.5 px-4 h-14 border-b border-[var(--border)]">
          <div className="w-8 h-8 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)] flex items-center justify-center">
            <ShieldCheck size={17} />
          </div>
          <div>
            <div className="font-semibold text-[15px] leading-4">scan</div>
            <div className="text-[10px] text-[var(--fg-3)]">资产测绘平台</div>
          </div>
        </div>
        <nav className="flex-1 py-3 px-2 space-y-0.5">
          {NAV.map((n) => {
            const active = pathname.startsWith(n.href);
            return (
              <Link
                key={n.href}
                href={n.href}
                className={cn(
                  "flex items-center gap-2.5 px-3 py-2 rounded-md text-[13.5px] transition-colors",
                  active
                    ? "bg-[var(--accent-soft)] text-[var(--accent)] font-medium"
                    : "text-[var(--fg-2)] hover:bg-[var(--panel)] hover:text-[var(--fg)]",
                )}
              >
                <n.icon size={15} />
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="p-2 border-t border-[var(--border)]">
          <button
            className="flex items-center gap-2.5 px-3 py-2 rounded-md text-[13px] text-[var(--fg-3)] hover:text-[var(--fg)] hover:bg-[var(--panel)] w-full"
            onClick={() => {
              localStorage.removeItem("scan_token");
              router.push("/login/");
            }}
          >
            <LogOut size={15} /> 退出登录
          </button>
        </div>
      </aside>
      <main className="flex-1 ml-[196px] min-w-0">
        <div className="max-w-[1560px] mx-auto px-6 py-5">{children}</div>
      </main>
    </div>
  );
}
