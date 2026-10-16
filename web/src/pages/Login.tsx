import { useState } from "react";
import { KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Input } from "../components/ui";

export default function Login() {
  const { setUser } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const r = await api.login(username, password, code);
      setUser(r.user);
    } catch (e) {
      setErr((e as Error).message);
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-full grid place-items-center px-4 py-10 relative overflow-hidden">
      <div aria-hidden className="pointer-events-none absolute inset-0 [background:radial-gradient(600px_circle_at_50%_0%,color-mix(in_oklab,var(--accent)_18%,transparent),transparent_70%)]" />
      <div className="relative w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="size-12 rounded-2xl bg-gradient-to-br from-cyan-500 to-cyan-700 grid place-items-center shadow-xl shadow-cyan-500/25 mb-4">
            <ShieldCheck className="size-6 text-white" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">WAF 安全网关</h1>
          <p className="text-muted text-sm mt-1">登录管理控制台</p>
        </div>
        <form onSubmit={submit} className="bg-surface border border-border rounded-2xl p-6 shadow-xl shadow-black/5 space-y-4">
          <div className="space-y-1.5">
            <label className="text-[13px] font-medium" htmlFor="u">用户名</label>
            <Input id="u" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
          </div>
          <div className="space-y-1.5">
            <label className="text-[13px] font-medium" htmlFor="p">密码</label>
            <Input id="p" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <label className="text-[13px] font-medium flex items-center gap-1.5" htmlFor="c">
              <KeyRound className="size-3.5 text-muted" /> 两步验证码
            </label>
            <Input
              id="c"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="6 位数字"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              className="font-mono tracking-[0.4em] text-center text-base"
              required
            />
          </div>
          {err && <p className="text-sm text-danger bg-danger-soft rounded-lg px-3 py-2">{err}</p>}
          <button
            type="submit"
            disabled={busy || code.length !== 6}
            className="w-full h-10 rounded-lg bg-accent text-accent-fg font-medium hover:brightness-110 transition disabled:opacity-50 inline-flex items-center justify-center gap-2"
          >
            {busy && <Loader2 className="size-4 animate-spin" />}
            登录
          </button>
        </form>
        <p className="text-center text-xs text-muted mt-6">连续 5 次失败将锁定 15 分钟 · 所有登录均会记录并推送通知</p>
      </div>
    </div>
  );
}
