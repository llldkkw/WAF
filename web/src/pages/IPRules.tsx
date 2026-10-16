import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { api, type IPRule } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useLoad, useSites } from "../lib/hooks";
import { fmtRelative, fmtTime } from "../lib/format";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Segmented, Select, Spinner, Table, Td, useAction, useToast } from "../components/ui";

const sourceLabels: Record<string, string> = { manual: "手动", "auto-ban": "自动封禁", cli: "命令行" };

export default function IPRules() {
  const { isAdmin } = useAuth();
  const { sites, name } = useSites();
  const { data, loading, reload } = useLoad(() => api.ipRules().then((r) => r.rules));
  const [tab, setTab] = useState<"all" | "deny" | "allow" | "auto">("all");
  const [adding, setAdding] = useState(false);
  const { confirm } = useToast();
  const { run } = useAction();

  const rules = (data ?? []).filter((r) =>
    tab === "all" ? true : tab === "auto" ? r.source === "auto-ban" : r.action === tab,
  );

  const del = async (r: IPRule) => {
    if (!(await confirm(`删除规则 ${r.action === "allow" ? "白名单" : "黑名单"} ${r.cidr}？`, { danger: true, ok: "删除" }))) return;
    if (await run(() => api.deleteIPRule(r.id), "已删除")) reload();
  };

  return (
    <>
      <PageHeader
        title="IP 黑白名单"
        desc="白名单中的地址跳过所有检查（优先级最高）；黑名单直接拒绝。自动封禁的条目到期后自动移除。"
        actions={isAdmin && <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setAdding(true)}>添加规则</Button>}
      />
      <Card>
        <div className="mb-4">
          <Segmented
            value={tab}
            onChange={setTab}
            options={[
              { value: "all", label: `全部 ${data?.length ?? ""}` },
              { value: "deny", label: "黑名单" },
              { value: "allow", label: "白名单" },
              { value: "auto", label: "自动封禁" },
            ]}
          />
        </div>
        {loading && !data ? (
          <Spinner />
        ) : (
          <Table head={["地址", "动作", "范围", "来源", "备注", "过期", "创建", ""]} empty={rules.length === 0}>
            {rules.map((r) => (
              <tr key={r.id}>
                <Td mono>{r.cidr}</Td>
                <Td>{r.action === "allow" ? <Badge tone="ok">白名单</Badge> : <Badge tone="danger">黑名单</Badge>}</Td>
                <Td>{name(r.site_id)}</Td>
                <Td><Badge tone={r.source === "auto-ban" ? "warn" : "muted"}>{sourceLabels[r.source] ?? r.source}</Badge></Td>
                <Td className="max-w-[260px] truncate text-muted">{r.note || "—"}</Td>
                <Td className="whitespace-nowrap text-[13px]">{r.expires_at ? fmtTime(r.expires_at) : <span className="text-muted">永久</span>}</Td>
                <Td className="whitespace-nowrap text-[13px] text-muted" >{r.created_by} · {fmtRelative(r.created_at)}</Td>
                <Td className="text-right">
                  {isAdmin && (
                    <Button size="sm" variant="ghost" onClick={() => del(r)} aria-label="删除">
                      <Trash2 className="size-4" />
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <AddRule open={adding} sites={sites} onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />
    </>
  );
}

function AddRule({ open, sites, onClose, onSaved }: { open: boolean; sites: { id: number; name: string }[]; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ cidr: "", action: "deny", site_id: 0, note: "", minutes: 0 });
  const { run, busy } = useAction();
  const save = async () => {
    if (await run(() => api.addIPRule(f), "已添加，2 秒内生效")) {
      setF({ cidr: "", action: "deny", site_id: 0, note: "", minutes: 0 });
      onSaved();
    }
  };
  return (
    <Modal open={open} onClose={onClose} title="添加 IP 规则" footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" loading={busy} onClick={save}>添加</Button></>}>
      <div className="space-y-4">
        <Field label="IP 或网段" hint="例如 203.0.113.7 或 203.0.113.0/24，支持 IPv6">
          <Input value={f.cidr} onChange={(e) => setF({ ...f, cidr: e.target.value })} placeholder="203.0.113.7" autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="动作">
            <Select value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })}>
              <option value="deny">黑名单（拒绝）</option>
              <option value="allow">白名单（放行）</option>
            </Select>
          </Field>
          <Field label="范围">
            <Select value={f.site_id} onChange={(e) => setF({ ...f, site_id: Number(e.target.value) })}>
              <option value={0}>全局（所有站点）</option>
              {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </Select>
          </Field>
        </div>
        <Field label="有效期">
          <Select value={f.minutes} onChange={(e) => setF({ ...f, minutes: Number(e.target.value) })}>
            <option value={0}>永久</option>
            <option value={60}>1 小时</option>
            <option value={1440}>1 天</option>
            <option value={10080}>7 天</option>
            <option value={43200}>30 天</option>
          </Select>
        </Field>
        <Field label="备注">
          <Input value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} placeholder="例如：办公室出口 IP" />
        </Field>
      </div>
    </Modal>
  );
}
