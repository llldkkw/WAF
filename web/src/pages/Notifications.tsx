import { useState } from "react";
import { BellRing, Pencil, Plus, Send, Trash2 } from "lucide-react";
import { api, type Channel, type ChannelType, type Level } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { Badge, Button, Card, Empty, Field, Input, Modal, PageHeader, Select, Spinner, Switch, useAction, useToast } from "../components/ui";

const levelLabels: Record<Level, string> = { info: "全部（含通知）", warning: "警告及以上", critical: "仅严重" };

const events: { level: Level; items: string[] }[] = [
  { level: "critical", items: ["后端服务宕机", "管理后台新 IP 登录", "高危攻击（命令执行 / Java / PHP / RFI）", "配置加载失败"] },
  { level: "warning", items: ["攻击量突增", "IP 被自动封禁", "高危等级攻击被拦截", "后台登录多次失败"] },
  { level: "info", items: ["配置变更", "后端恢复", "网关启动", "其他攻击拦截"] },
];

export default function Notifications() {
  const types = useLoad(() => api.channelTypes().then((r) => r.types));
  const { data, loading, reload } = useLoad(() => api.channels().then((r) => r.channels));
  const [editing, setEditing] = useState<Partial<Channel> | null>(null);
  const { confirm } = useToast();
  const { run } = useAction();
  const [testing, setTesting] = useState(0);

  const typeLabel = (t: string) => types.data?.find((x) => x.type === t)?.label ?? t;

  const test = async (c: Channel) => {
    setTesting(c.id);
    await run(() => api.testChannel(c.id), `测试消息已发送到「${c.name}」`);
    setTesting(0);
  };
  const del = async (c: Channel) => {
    if (!(await confirm(`删除通知渠道「${c.name}」？`, { danger: true, ok: "删除" }))) return;
    if (await run(() => api.deleteChannel(c.id), "已删除")) reload();
  };

  return (
    <>
      <PageHeader
        title="推送通知"
        desc="把安全事件实时推送到手机。同一类事件 5 分钟内只推送一次，之后汇总，避免告警轰炸。"
        actions={<Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditing({ type: "telegram", min_level: "warning", enabled: true, config: {} })}>添加渠道</Button>}
      />
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          {loading && !data ? (
            <Spinner />
          ) : !data?.length ? (
            <div className="bg-surface border border-dashed border-border rounded-xl">
              <Empty text="还没有通知渠道。支持 Telegram、企业微信、钉钉、飞书、Bark、邮件和 Webhook。" />
            </div>
          ) : (
            <div className="space-y-3">
              {data.map((c) => (
                <div key={c.id} className="bg-surface border border-border rounded-xl p-4 flex flex-wrap items-center gap-3">
                  <div className="size-10 rounded-xl bg-accent-soft text-accent grid place-items-center">
                    <BellRing className="size-5" />
                  </div>
                  <div className="flex-1 min-w-40">
                    <div className="font-medium flex items-center gap-2">
                      {c.name}
                      {!c.enabled && <Badge>已停用</Badge>}
                    </div>
                    <div className="text-xs text-muted mt-0.5">
                      {typeLabel(c.type)} · {levelLabels[c.min_level]}
                      {c.config.quiet_hours && ` · 免打扰 ${c.config.quiet_hours}`}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" icon={<Send className="size-3.5" />} loading={testing === c.id} onClick={() => test(c)}>测试</Button>
                    <Button size="sm" icon={<Pencil className="size-3.5" />} onClick={() => setEditing(structuredClone(c))}>编辑</Button>
                    <Button size="sm" variant="ghost" onClick={() => del(c)} aria-label="删除"><Trash2 className="size-4" /></Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <Card title="推送的事件">
          <div className="space-y-4">
            {events.map((g) => (
              <div key={g.level}>
                <Badge tone={g.level === "critical" ? "danger" : g.level === "warning" ? "warn" : "info"}>
                  {g.level === "critical" ? "🔴 严重" : g.level === "warning" ? "🟠 警告" : "🔵 通知"}
                </Badge>
                <ul className="mt-2 space-y-1 text-[13px] text-muted list-disc pl-5">
                  {g.items.map((i) => <li key={i}>{i}</li>)}
                </ul>
              </div>
            ))}
            <p className="text-xs text-muted border-t border-border pt-3">严重级别的消息会无视免打扰时段。</p>
          </div>
        </Card>
      </div>
      {editing && types.data && (
        <ChannelEditor
          value={editing}
          types={types.data}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            reload();
          }}
        />
      )}
    </>
  );
}

function ChannelEditor({ value, types, onClose, onSaved }: { value: Partial<Channel>; types: ChannelType[]; onClose: () => void; onSaved: () => void }) {
  const [c, setC] = useState<Partial<Channel>>(value);
  const { run, busy } = useAction();
  const t = types.find((x) => x.type === c.type);
  const setCfg = (k: string, v: string) => setC({ ...c, config: { ...c.config, [k]: v } });

  const save = async () => {
    if (await run(() => api.saveChannel(c), "已保存，可点击「测试」验证")) onSaved();
  };

  return (
    <Modal open wide onClose={onClose} title={c.id ? "编辑通知渠道" : "添加通知渠道"} footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" loading={busy} onClick={save}>保存</Button></>}>
      <div className="space-y-4">
        <div className="grid sm:grid-cols-2 gap-4">
          <Field label="类型">
            <Select value={c.type} disabled={!!c.id} onChange={(e) => setC({ ...c, type: e.target.value, config: {} })}>
              {types.map((x) => <option key={x.type} value={x.type}>{x.label}</option>)}
            </Select>
          </Field>
          <Field label="名称">
            <Input value={c.name ?? ""} onChange={(e) => setC({ ...c, name: e.target.value })} placeholder="例如：运维群" />
          </Field>
        </div>
        <div className="grid sm:grid-cols-2 gap-4">
          {t?.fields.map((f) => (
            <Field key={f.key} label={<>{f.label}{f.required && <span className="text-danger"> *</span>}</>}>
              <Input
                type={f.secret ? "password" : "text"}
                autoComplete="off"
                value={c.config?.[f.key] ?? ""}
                placeholder={f.placeholder}
                onChange={(e) => setCfg(f.key, e.target.value)}
                className={f.secret ? "font-mono" : undefined}
              />
            </Field>
          ))}
        </div>
        <div className="grid sm:grid-cols-2 gap-4">
          <Field label="推送级别">
            <Select value={c.min_level} onChange={(e) => setC({ ...c, min_level: e.target.value as Level })}>
              {Object.entries(levelLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </Select>
          </Field>
          <Field label="免打扰时段" hint="例如 23:00-07:00，严重告警不受影响">
            <Input value={c.config?.quiet_hours ?? ""} onChange={(e) => setCfg("quiet_hours", e.target.value)} placeholder="23:00-07:00" />
          </Field>
        </div>
        <Switch checked={!!c.enabled} onChange={(v) => setC({ ...c, enabled: v })} label="启用" />
        <p className="text-xs text-muted">密钥类字段加密存储，保存后不会再显示明文。编辑时保持「••••••」表示不修改。</p>
      </div>
    </Modal>
  );
}
