import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtTime } from "../lib/format";
import { Button, Card, Field, Input, PageHeader, useAction } from "../components/ui";

export default function Account() {
  const { user, setUser } = useAuth();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const { run, busy } = useAction();

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (f.next !== f.confirm) return run(() => Promise.reject(new Error("两次输入的新密码不一致")));
    // Changing the password ends every session, including this one.
    if (await run(() => api.changePassword(f.current, f.next), "密码已修改，请重新登录")) setUser(null);
  };

  return (
    <>
      <PageHeader title="账号安全" />
      <div className="grid lg:grid-cols-2 gap-4 max-w-4xl">
        <Card title="账号信息">
          <dl className="space-y-3 text-sm">
            <div className="flex justify-between"><dt className="text-muted">用户名</dt><dd className="font-medium">{user?.username}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">角色</dt><dd>{user?.role === "admin" ? "管理员" : "只读"}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">本次登录</dt><dd className="tabular">{fmtTime(user?.last_login_at ?? 0)}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">登录 IP</dt><dd className="font-mono">{user?.last_login_ip}</dd></div>
            <div className="flex justify-between items-center"><dt className="text-muted">两步验证</dt><dd className="text-ok flex items-center gap-1"><ShieldCheck className="size-4" />已启用</dd></div>
          </dl>
          <p className="text-xs text-muted mt-4 pt-4 border-t border-border">手机丢失时，请让其他管理员在「用户管理」中重置凭据，或在服务器上执行 <code className="font-mono">waf user reset -name {user?.username}</code>。</p>
        </Card>
        <Card title="修改密码">
          <form onSubmit={save} className="space-y-4">
            <Field label="当前密码"><Input type="password" autoComplete="current-password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} required /></Field>
            <Field label="新密码" hint="至少 10 位，修改后所有设备需要重新登录"><Input type="password" autoComplete="new-password" value={f.next} onChange={(e) => setF({ ...f, next: e.target.value })} required /></Field>
            <Field label="确认新密码"><Input type="password" autoComplete="new-password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} required /></Field>
            <Button type="submit" variant="primary" loading={busy}>修改密码</Button>
          </form>
        </Card>
      </div>
    </>
  );
}
