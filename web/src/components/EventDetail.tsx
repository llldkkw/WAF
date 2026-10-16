import { useState } from "react";
import { Ban, Filter, ShieldOff } from "lucide-react";
import { api, type WafEvent } from "../lib/api";
import { useAuth } from "../lib/auth";
import { actionLabels, actionTone, categoryLabel, countryName, decodeUri, flag, fmtTime } from "../lib/format";
import { Badge, Button, Drawer, Field, Input, Select, useAction } from "./ui";

export function EventDetail({ event, siteName, onClose, onFilterIP }: {
  event: WafEvent | null;
  siteName: (id: number) => string;
  onClose: () => void;
  onFilterIP?: (ip: string) => void;
}) {
  const { isAdmin } = useAuth();
  const { run, busy } = useAction();
  const [banMinutes, setBanMinutes] = useState(1440);
  const [exPath, setExPath] = useState("");
  const [exRule, setExRule] = useState(0);

  if (!event) return null;
  const e = event;
  const path = e.uri.split("?")[0];
  const ruleOptions = (e.matches ?? []).filter((m) => m.rule_id < 949000 || m.rule_id >= 960000);

  const ban = () =>
    run(() => api.addIPRule({ cidr: e.client_ip, action: "deny", site_id: 0, note: `手动封禁: ${categoryLabel(e.category)} ${e.rule_id || ""}`.trim(), minutes: banMinutes }), `已封禁 ${e.client_ip}`);

  const exclude = () =>
    run(
      () => api.addExclusion(e.site_id, { rule_id: exRule || e.rule_id, path: exPath, note: `误报: ${e.message}`.slice(0, 200) }),
      "已添加误报排除，规则将在 2 秒内生效",
    );

  const row = (k: string, v: React.ReactNode, mono = false) => (
    <div className="grid grid-cols-[88px_1fr] gap-3 py-2 border-b border-border last:border-0">
      <dt className="text-muted text-[13px]">{k}</dt>
      <dd className={mono ? "font-mono text-[13px] break-all" : "text-sm break-words"}>{v}</dd>
    </div>
  );

  return (
    <Drawer open onClose={onClose} title="事件详情">
      <div className="flex flex-wrap items-center gap-2 mb-4">
        <Badge tone={actionTone(e.action)}>{actionLabels[e.action]}</Badge>
        {e.category && <Badge tone="accent">{categoryLabel(e.category)}</Badge>}
        {e.severity && <Badge tone={e.severity === "critical" ? "danger" : "muted"}>{e.severity}</Badge>}
        {e.status > 0 && <Badge>HTTP {e.status}</Badge>}
      </div>
      {e.message && <p className="text-[15px] font-medium mb-4">{e.message}</p>}

      <dl className="mb-6">
        {row("时间", fmtTime(e.ts))}
        {row("来源 IP", <span className="font-mono">{e.client_ip}</span>)}
        {row("地区", e.country ? `${flag(e.country)} ${countryName(e.country)}` : "未知")}
        {row("站点", `${siteName(e.site_id)} · ${e.host}`)}
        {row("请求", `${e.method} ${decodeUri(e.uri)}`, true)}
        {decodeUri(e.uri) !== e.uri && row("原始 URI", e.uri, true)}
        {row("User-Agent", e.user_agent || "—", true)}
        {e.rule_id > 0 && row("规则 ID", e.rule_id, true)}
      </dl>

      {e.matches && e.matches.length > 0 && (
        <div className="mb-6">
          <h4 className="text-[13px] font-semibold text-muted mb-2">命中规则 ({e.matches.length})</h4>
          <div className="space-y-2">
            {e.matches.map((m, i) => (
              <div key={i} className="rounded-lg border border-border bg-surface-2/50 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-accent">{m.rule_id}</span>
                  <span className="text-sm font-medium">{m.message}</span>
                </div>
                {m.variable && <div className="text-xs text-muted">位置: <span className="font-mono">{m.variable}</span></div>}
                {m.data && <pre className="mt-1.5 text-xs font-mono whitespace-pre-wrap break-all text-muted">{m.data}</pre>}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-6">
        {onFilterIP && (
          <Button size="sm" icon={<Filter className="size-3.5" />} onClick={() => onFilterIP(e.client_ip)}>
            查看该 IP 全部记录
          </Button>
        )}
      </div>

      {isAdmin && (
        <div className="space-y-4">
          <div className="rounded-xl border border-border p-4">
            <h4 className="font-medium flex items-center gap-2 mb-1">
              <Ban className="size-4 text-danger" /> 封禁此 IP
            </h4>
            <p className="text-xs text-muted mb-3">加入全局黑名单，所有站点生效。</p>
            <div className="flex gap-2">
              <Select value={banMinutes} onChange={(ev) => setBanMinutes(Number(ev.target.value))} className="max-w-40">
                <option value={60}>1 小时</option>
                <option value={1440}>1 天</option>
                <option value={10080}>7 天</option>
                <option value={0}>永久</option>
              </Select>
              <Button variant="danger" loading={busy} onClick={ban}>
                封禁 {e.client_ip}
              </Button>
            </div>
          </div>

          {e.rule_id > 0 && e.site_id > 0 && (
            <div className="rounded-xl border border-border p-4">
              <h4 className="font-medium flex items-center gap-2 mb-1">
                <ShieldOff className="size-4 text-warn" /> 这是误报
              </h4>
              <p className="text-xs text-muted mb-3">对站点「{siteName(e.site_id)}」关闭该规则。建议限定路径，避免整站放开。</p>
              <div className="grid sm:grid-cols-2 gap-3 mb-3">
                <Field label="规则">
                  <Select value={exRule || e.rule_id} onChange={(ev) => setExRule(Number(ev.target.value))}>
                    {(ruleOptions.length ? ruleOptions : [{ rule_id: e.rule_id, message: e.message }]).map((m) => (
                      <option key={m.rule_id} value={m.rule_id}>
                        {m.rule_id} · {m.message.slice(0, 40)}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="仅限路径前缀（留空 = 整站）">
                  <Input value={exPath} placeholder={path} onChange={(ev) => setExPath(ev.target.value)} />
                </Field>
              </div>
              <div className="flex gap-2">
                <Button size="sm" onClick={() => setExPath(path)}>
                  使用当前路径
                </Button>
                <Button size="sm" variant="primary" loading={busy} onClick={exclude}>
                  添加排除
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
