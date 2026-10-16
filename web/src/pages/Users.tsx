import { useState } from "react";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { api, type Enrollment, type Role, type User } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useLoad } from "../lib/hooks";
import { fmtRelative } from "../lib/format";
import { TotpEnroll } from "../components/TotpEnroll";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner, Switch, Table, Td, useAction, useToast } from "../components/ui";

export default function Users() {
  const { user: me } = useAuth();
  const { data, loading, reload } = useLoad(() => api.users().then((r) => r.users));
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<User | null>(null);
  const [enroll, setEnroll] = useState<Enrollment | null>(null);
  const { confirm } = useToast();
  const { run } = useAction();

  const update = async (u: User, patch: Partial<User>) => {
    const next = { role: patch.role ?? u.role, disabled: patch.disabled ?? u.disabled };
    if (await run(() => api.updateUser(u.id, next), "已更新")) reload();
  };
  const del = async (u: User) => {
    if (!(await confirm(`删除用户 ${u.username}？`, { danger: true, ok: "删除" }))) return;
    if (await run(() => api.deleteUser(u.id), "已删除")) reload();
  };

  return (
    <>
      <PageHeader
        title="用户管理"
        desc="所有账号强制启用两步验证。只读用户可以查看数据，但不能修改任何配置。"
        actions={<Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setCreating(true)}>新建用户</Button>}
      />
      <Card>
        {loading && !data ? (
          <Spinner />
        ) : (
          <Table head={["用户名", "角色", "状态", "最近登录", ""]}>
            {data?.map((u) => (
              <tr key={u.id}>
                <Td className="font-medium">
                  {u.username} {u.id === me?.id && <Badge tone="accent">我</Badge>}
                </Td>
                <Td>
                  <Select value={u.role} disabled={u.id === me?.id} onChange={(e) => update(u, { role: e.target.value as Role })} className="w-28 h-8">
                    <option value="admin">管理员</option>
                    <option value="viewer">只读</option>
                  </Select>
                </Td>
                <Td>
                  <Switch checked={!u.disabled} disabled={u.id === me?.id} onChange={(v) => update(u, { disabled: !v })} label={u.disabled ? "已停用" : "正常"} />
                </Td>
                <Td className="text-[13px] text-muted whitespace-nowrap">
                  {fmtRelative(u.last_login_at)}
                  {u.last_login_ip && <span className="font-mono"> · {u.last_login_ip}</span>}
                </Td>
                <Td className="text-right whitespace-nowrap">
                  <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} onClick={() => setResetting(u)}>重置凭据</Button>
                  {u.id !== me?.id && (
                    <Button size="sm" variant="ghost" onClick={() => del(u)} aria-label="删除"><Trash2 className="size-4" /></Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {creating && <CreateUser onClose={() => setCreating(false)} onCreated={(e) => { setCreating(false); setEnroll(e); reload(); }} />}
      {resetting && <ResetUser user={resetting} onClose={() => setResetting(null)} onDone={(e) => { setResetting(null); setEnroll(e); }} />}
      <TotpEnroll data={enroll} onClose={() => setEnroll(null)} />
    </>
  );
}

function CreateUser({ onClose, onCreated }: { onClose: () => void; onCreated: (e: Enrollment) => void }) {
  const [f, setF] = useState({ username: "", password: "", role: "viewer" as Role });
  const { run, busy } = useAction();
  const save = async () => {
    const r = await run(() => api.createUser(f));
    if (r) onCreated(r);
  };
  return (
    <Modal open onClose={onClose} title="新建用户" footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" loading={busy} onClick={save}>创建</Button></>}>
      <div className="space-y-4">
        <Field label="用户名"><Input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} autoFocus /></Field>
        <Field label="初始密码" hint="至少 10 位"><Input type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
        <Field label="角色">
          <Select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value as Role })}>
            <option value="viewer">只读</option>
            <option value="admin">管理员</option>
          </Select>
        </Field>
      </div>
    </Modal>
  );
}

function ResetUser({ user, onClose, onDone }: { user: User; onClose: () => void; onDone: (e: Enrollment) => void }) {
  const [pw, setPw] = useState("");
  const { run, busy } = useAction();
  const save = async () => {
    const r = await run(() => api.resetUser(user.id, pw));
    if (r) onDone(r);
  };
  return (
    <Modal open onClose={onClose} title={`重置 ${user.username} 的凭据`} footer={<><Button onClick={onClose}>取消</Button><Button variant="danger" loading={busy} onClick={save}>重置</Button></>}>
      <p className="text-sm text-muted mb-4">将设置新密码并生成新的两步验证密钥，该用户的所有登录会话会立即失效。</p>
      <Field label="新密码" hint="至少 10 位"><Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus /></Field>
    </Modal>
  );
}
