"use client";
import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { msg } from "@/components/ui";

function LoginForm() {
  const [pw, setPw] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const next = useSearchParams().get("next") || "/dashboard/";

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pw) return;
    setLoading(true);
    try {
      const { data } = await api.login(pw);
      localStorage.setItem("scan_token", data.token);
      router.push(next.startsWith("/") ? next : "/dashboard/");
    } catch (err: any) {
      msg.err(err.message === "401" ? "密码错误" : `登录失败：${err.message}`);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <form onSubmit={submit} className="card card-pad w-full max-w-sm">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)] flex items-center justify-center">
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="text-lg font-semibold">scan</div>
            <div className="text-[12px] text-[var(--fg-3)]">资产测绘与安全分析平台</div>
          </div>
        </div>
        <input
          type="password"
          className="ipt w-full mb-4 !py-2.5"
          placeholder="访问密码"
          value={pw}
          autoFocus
          onChange={(e) => setPw(e.target.value)}
        />
        <button className="btn btn-pri w-full justify-center !py-2" disabled={loading || !pw}>
          {loading ? "登录中…" : "登 录"}
        </button>
      </form>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
