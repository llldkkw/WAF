import { useState } from "react";
import { BellRing, Pencil, Plus, Send, Trash2 } from "lucide-react";
import { api, type Channel, type ChannelType, type Level, type ReportSettings } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { Badge, Button, Card, Empty, Field, Input, Modal, PageHeader, Select, Spinner, Switch, Textarea, useAction, useToast } from "../components/ui";

const levelLabels: Record<Level, string> = { info: "全部（含通知）", warning: "警告及以上", critical: "仅严重" };

const events: { level: Level; items: string[] }[] = [
  { level: "critical", items: ["后端服务宕机", "管理后台新 IP 登录", "高危攻击（命令执行 / Java / PHP / RFI）", "配置加载失败", "证书已过期"] },
  { level: "warning", items: ["攻击量突增", "IP 被自动封禁", "高危等级攻击被拦截", "后台登录多次失败", "证书 14 天内到期"] },
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
                      {c.config.reports === "1" && " · 接收安全报告"}
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
            <p className="text-xs text-muted border-t border-border pt-3">严重级别的消息会无视免打扰时段。攻击和封禁告警附带「一键封禁 / 解封 / 加白」链接（需在配置中设置 admin.public_url）。</p>
          </div>
        </Card>
      </div>
      <ReportSettingsCard />
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
              {f.options ? (
                <Select value={c.config?.[f.key] ?? ""} onChange={(e) => setCfg(f.key, e.target.value)}>
                  {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </Select>
              ) : (
                <Input
                  type={f.secret ? "password" : "text"}
                  autoComplete="off"
                  value={c.config?.[f.key] ?? ""}
                  placeholder={f.placeholder}
                  onChange={(e) => setCfg(f.key, e.target.value)}
                  className={f.secret ? "font-mono" : undefined}
                />
              )}
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
        <Switch
          checked={c.config?.reports === "1"}
          onChange={(v) => setCfg("reports", v ? "1" : "")}
          label="接收每日 / 每周安全报告"
          desc="报告不受推送级别和免打扰时段限制，按设定时间发送"
        />
        <Switch checked={!!c.enabled} onChange={(v) => setC({ ...c, enabled: v })} label="启用" />
        <p className="text-xs text-muted">密钥类字段加密存储，保存后不会再显示明文。编辑时保持「••••••」表示不修改。</p>
      </div>
    </Modal>
  );
}

const weekdays = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];

function ReportSettingsCard() {
  const { data, reload } = useLoad(() => api.reportSettings());
  const [s, setS] = useState<ReportSettings | null>(null);
  const [preview, setPreview] = useState("");
  const { run, busy } = useAction();
  const cur = s ?? data?.settings ?? null;
  if (!cur) return null;
  const up = (p: Partial<ReportSettings>) => setS({ ...cur, ...p });

  const save = async () => {
    if (await run(() => api.saveReportSettings(cur), "已保存")) {
      setS(null);
      reload();
    }
  };
  const sendNow = async (period: "daily" | "weekly") => {
    const r = await run(() => api.sendReport(period), "报告已发送到订阅的渠道");
    if (r) setPreview(r.preview);
  };

  return (
    <Card title="安全报告" className="mt-4">
      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <p className="text-[13px] text-muted">定时汇总请求量、拦截数、攻击类型、Top 攻击 IP / 地区 / 路径，并与上一期对比。只发送到开启了「接收安全报告」的渠道。时区：{data?.timezone}</p>
          <div className="flex flex-wrap items-center gap-3">
            <Switch checked={cur.daily} onChange={(v) => up({ daily: v })} label="每日报告" />
            <Input type="time" value={cur.daily_time} disabled={!cur.daily} onChange={(e) => up({ daily_time: e.target.value })} className="w-32" />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Switch checked={cur.weekly} onChange={(v) => up({ weekly: v })} label="每周报告" />
            <Select value={cur.weekly_day} disabled={!cur.weekly} onChange={(e) => up({ weekly_day: Number(e.target.value) })} className="w-24">
              {weekdays.map((d, i) => <option key={i} value={i + 1}>{d}</option>)}
            </Select>
            <Input type="time" value={cur.weekly_time} disabled={!cur.weekly} onChange={(e) => up({ weekly_time: e.target.value })} className="w-32" />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" loading={busy} disabled={!s} onClick={save}>保存设置</Button>
            <Button loading={busy} onClick={() => sendNow("daily")}>立即发送近 24 小时报告</Button>
            <Button loading={busy} onClick={() => sendNow("weekly")}>立即发送近 7 天报告</Button>
          </div>
        </div>
        <Field label="最近一次报告预览">
          <Textarea readOnly rows={12} value={preview || "点击「立即发送」后在这里预览内容"} className="font-sans text-[13px]" />
        </Field>
      </div>
    </Card>
  );
}
