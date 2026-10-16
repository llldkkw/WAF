import { useState, type ReactNode } from "react";
import { ArrowRight, Globe2, Lock, Pencil, Plus, Trash2 } from "lucide-react";
import { api, type Mode, type PathRule, type Site } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useLoad } from "../lib/hooks";
import { countryName, flag, modeLabels } from "../lib/format";
import {
  Badge,
  Button,
  Drawer,
  Empty,
  Field,
  Input,
  LinesInput,
  PageHeader,
  Segmented,
  Select,
  Spinner,
  Switch,
  useAction,
  useToast,
} from "../components/ui";

const blank = (): Site => ({
  id: 0,
  name: "",
  enabled: true,
  created_at: 0,
  updated_at: 0,
  hosts: [],
  upstreams: [],
  preserve_host: true,
  mode: "block",
  paranoia_level: 1,
  anomaly_threshold: 5,
  upstream_insecure: false,
  https: false,
  force_https: false,
  rate_limit: { enabled: true, rps: 20, burst: 40, ban_threshold: 60, ban_minutes: 30 },
  attack_ban: { enabled: true, threshold: 20, minutes: 60 },
  block_countries: [],
  rule_exclusions: [],
  path_rules: [],
  health_check: { enabled: true, path: "/", interval_sec: 10 },
});

const modeTone: Record<Mode, "ok" | "info" | "muted"> = { block: "ok", detect: "info", off: "muted" };

export default function Sites() {
  const { isAdmin } = useAuth();
  const { data, loading, reload } = useLoad(() => api.sites().then((r) => r.sites));
  const [editing, setEditing] = useState<Site | null>(null);
  const { confirm } = useToast();
  const { run } = useAction();

  const del = async (s: Site) => {
    if (!(await confirm(`确定删除站点「${s.name}」？该站点的流量将不再被代理。`, { danger: true, ok: "删除" }))) return;
    if (await run(() => api.deleteSite(s.id), "站点已删除")) reload();
  };

  return (
    <>
      <PageHeader
        title="站点防护"
        desc="每个站点把一组域名反向代理到后端服务器，并应用独立的防护策略。修改保存后 2 秒内热加载，无需重启。"
        actions={isAdmin && <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditing(blank())}>新建站点</Button>}
      />
      {loading && !data ? (
        <Spinner />
      ) : !data?.length ? (
        <div className="bg-surface border border-dashed border-border rounded-xl">
          <Empty text="还没有站点。点击「新建站点」把第一个服务接入网关。" />
        </div>
      ) : (
        <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
          {data.map((s) => (
            <article key={s.id} className="bg-surface border border-border rounded-xl p-4 flex flex-col">
              <div className="flex items-start justify-between gap-2 mb-3">
                <div className="min-w-0">
                  <h3 className="font-semibold truncate flex items-center gap-2">
                    {s.name}
                    {!s.enabled && <Badge>已停用</Badge>}
                  </h3>
                  <div className="text-xs text-muted mt-0.5 flex items-center gap-1 truncate">
                    {s.https ? <Lock className="size-3 text-ok" /> : <Globe2 className="size-3" />}
                    {s.hosts.join(", ")}
                  </div>
                </div>
                <Badge tone={modeTone[s.mode]}>{modeLabels[s.mode]}</Badge>
              </div>
              <div className="text-xs font-mono text-muted space-y-0.5 mb-3">
                {s.upstreams.map((u) => (
                  <div key={u} className="flex items-center gap-1.5 truncate">
                    <ArrowRight className="size-3 shrink-0" />
                    {u}
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-1.5 mb-4">
                {s.mode !== "off" && <Badge tone="accent">CRS PL{s.paranoia_level}</Badge>}
                {s.rate_limit.enabled && <Badge>限流 {s.rate_limit.rps}/s</Badge>}
                {s.attack_ban.enabled && <Badge>自动封禁</Badge>}
                {s.block_countries.length > 0 && <Badge>封禁 {s.block_countries.length} 个地区</Badge>}
                {s.path_rules.length > 0 && <Badge>路径规则 {s.path_rules.length}</Badge>}
                {s.rule_exclusions.length > 0 && <Badge tone="warn">排除 {s.rule_exclusions.length}</Badge>}
                {s.health_check.enabled && <Badge>健康检查</Badge>}
              </div>
              <div className="mt-auto flex gap-2">
                <Button size="sm" icon={<Pencil className="size-3.5" />} onClick={() => setEditing(structuredClone(s))}>
                  {isAdmin ? "编辑" : "查看"}
                </Button>
                {isAdmin && (
                  <Button size="sm" variant="ghost" onClick={() => del(s)} aria-label="删除">
                    <Trash2 className="size-4" />
                  </Button>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
      {editing && (
        <SiteEditor
          site={editing}
          readOnly={!isAdmin}
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

function Section({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <section className="pb-6 mb-6 border-b border-border last:border-0 last:mb-0">
      <h3 className="font-semibold text-[15px]">{title}</h3>
      {desc && <p className="text-xs text-muted mt-0.5">{desc}</p>}
      <div className="mt-4 space-y-4">{children}</div>
    </section>
  );
}

function SiteEditor({ site, readOnly, onClose, onSaved }: { site: Site; readOnly: boolean; onClose: () => void; onSaved: () => void }) {
  const [s, setS] = useState<Site>(site);
  const { run, busy } = useAction();
  const up = (patch: Partial<Site>) => setS((x) => ({ ...x, ...patch }));

  const save = async () => {
    if (await run(() => api.saveSite(s), s.id ? "已保存，2 秒内生效" : "站点已创建")) onSaved();
  };

  const setPathRule = (i: number, patch: Partial<PathRule>) =>
    up({ path_rules: s.path_rules.map((r, j) => (j === i ? { ...r, ...patch } : r)) });

  return (
    <Drawer
      open
      onClose={onClose}
      title={s.id ? `编辑站点 · ${site.name}` : "新建站点"}
      footer={
        <>
          <Button onClick={onClose}>{readOnly ? "关闭" : "取消"}</Button>
          {!readOnly && (
            <Button variant="primary" loading={busy} onClick={save}>
              保存
            </Button>
          )}
        </>
      }
    >
      <fieldset disabled={readOnly} className="min-w-0">
        <Section title="基本信息">
          <div className="grid sm:grid-cols-2 gap-4">
            <Field label="站点名称">
              <Input value={s.name} onChange={(e) => up({ name: e.target.value })} placeholder="例如：官网" />
            </Field>
            <Field label="状态">
              <div className="h-9 flex items-center">
                <Switch checked={s.enabled} onChange={(v) => up({ enabled: v })} label={s.enabled ? "已启用" : "已停用"} />
              </div>
            </Field>
          </div>
          <Field label="域名（每行一个）" hint="支持通配符，如 *.example.com。请把这些域名的 DNS 解析到本网关的公网 IP。">
            <LinesInput value={s.hosts} onChange={(v) => up({ hosts: v })} placeholder={"example.com\nwww.example.com"} />
          </Field>
        </Section>

        <Section title="后端服务器" desc="多个后端时轮询负载均衡，健康检查失败的后端会被自动摘除。">
          <Field label="后端地址（每行一个）" hint="通常是内网地址，如 http://10.0.0.11:8080">
            <LinesInput value={s.upstreams} onChange={(v) => up({ upstreams: v })} placeholder="http://10.0.0.11:8080" />
          </Field>
          <Switch checked={s.preserve_host} onChange={(v) => up({ preserve_host: v })} label="保留原始 Host 头" desc="后端按域名区分虚拟主机时需要开启" />
          <Switch checked={s.upstream_insecure} onChange={(v) => up({ upstream_insecure: v })} label="跳过后端 HTTPS 证书校验" desc="仅在后端使用自签名证书时开启" />
          <Switch checked={s.health_check.enabled} onChange={(v) => up({ health_check: { ...s.health_check, enabled: v } })} label="健康检查" desc="后端连续 3 次检查失败会推送「后端宕机」告警" />
          {s.health_check.enabled && (
            <div className="grid grid-cols-2 gap-3 pl-12">
              <Field label="检查路径">
                <Input value={s.health_check.path} onChange={(e) => up({ health_check: { ...s.health_check, path: e.target.value } })} />
              </Field>
              <Field label="间隔（秒）">
                <Input type="number" min={5} value={s.health_check.interval_sec} onChange={(e) => up({ health_check: { ...s.health_check, interval_sec: Number(e.target.value) } })} />
              </Field>
            </div>
          )}
        </Section>

        <Section title="HTTPS">
          <Switch checked={s.https} onChange={(v) => up({ https: v, force_https: v && s.force_https })} label="自动申请 HTTPS 证书" desc="使用 Let's Encrypt 自动签发和续期（需在配置文件中启用 acme）" />
          <Switch checked={s.force_https} disabled={!s.https} onChange={(v) => up({ force_https: v })} label="强制跳转 HTTPS" />
        </Section>

        <Section title="WAF 防护" desc="基于 OWASP Core Rule Set，防护 SQL 注入、XSS、命令执行、文件包含、扫描器等攻击。">
          <Field label="防护模式">
            <Segmented<Mode>
              value={s.mode}
              onChange={(v) => up({ mode: v })}
              options={[
                { value: "block", label: "拦截" },
                { value: "detect", label: "观察（只记录）" },
                { value: "off", label: "关闭" },
              ]}
            />
          </Field>
          <p className="text-xs text-muted -mt-2">新站点建议先用「观察」模式运行几天，确认没有误报后再切换到「拦截」。</p>
          <div className="grid sm:grid-cols-2 gap-4">
            <Field label="防护等级（Paranoia Level）" hint="等级越高检测越严格，误报也越多">
              <Select value={s.paranoia_level} onChange={(e) => up({ paranoia_level: Number(e.target.value) })}>
                <option value={1}>PL1 · 标准（推荐）</option>
                <option value={2}>PL2 · 增强</option>
                <option value={3}>PL3 · 严格</option>
                <option value={4}>PL4 · 极严格</option>
              </Select>
            </Field>
            <Field label="异常分数阈值" hint="达到该分数即拦截，默认 5，越低越严格">
              <Input type="number" min={1} value={s.anomaly_threshold} onChange={(e) => up({ anomaly_threshold: Number(e.target.value) })} />
            </Field>
          </div>
          {s.rule_exclusions.length > 0 && (
            <Field label="误报排除" hint="在攻击日志中点击「这是误报」添加">
              <ul className="rounded-lg border border-border divide-y divide-border">
                {s.rule_exclusions.map((ex, i) => (
                  <li key={i} className="flex items-center gap-3 px-3 py-2 text-sm">
                    <span className="font-mono text-accent">{ex.rule_id}</span>
                    <span className="font-mono text-xs text-muted">{ex.path || "整站"}</span>
                    <span className="truncate flex-1 text-xs text-muted">{ex.note}</span>
                    <Button size="sm" variant="ghost" onClick={() => up({ rule_exclusions: s.rule_exclusions.filter((_, j) => j !== i) })} aria-label="移除">
                      <Trash2 className="size-3.5" />
                    </Button>
                  </li>
                ))}
              </ul>
            </Field>
          )}
        </Section>

        <Section title="CC 防护与自动封禁">
          <Switch checked={s.rate_limit.enabled} onChange={(v) => up({ rate_limit: { ...s.rate_limit, enabled: v } })} label="单 IP 限流" desc="超过速率返回 429" />
          {s.rate_limit.enabled && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pl-12">
              <Field label="每秒请求">
                <Input type="number" min={0.1} step={0.1} value={s.rate_limit.rps} onChange={(e) => up({ rate_limit: { ...s.rate_limit, rps: Number(e.target.value) } })} />
              </Field>
              <Field label="突发上限">
                <Input type="number" min={1} value={s.rate_limit.burst} onChange={(e) => up({ rate_limit: { ...s.rate_limit, burst: Number(e.target.value) } })} />
              </Field>
              <Field label="封禁阈值/分钟" hint="0 不封禁">
                <Input type="number" min={0} value={s.rate_limit.ban_threshold} onChange={(e) => up({ rate_limit: { ...s.rate_limit, ban_threshold: Number(e.target.value) } })} />
              </Field>
              <Field label="封禁分钟">
                <Input type="number" min={1} value={s.rate_limit.ban_minutes} onChange={(e) => up({ rate_limit: { ...s.rate_limit, ban_minutes: Number(e.target.value) } })} />
              </Field>
            </div>
          )}
          <Switch checked={s.attack_ban.enabled} onChange={(v) => up({ attack_ban: { ...s.attack_ban, enabled: v } })} label="攻击者自动封禁" desc="5 分钟内被 WAF 拦截达到阈值的 IP 自动加入黑名单（对付扫描器）" />
          {s.attack_ban.enabled && (
            <div className="grid grid-cols-2 gap-3 pl-12">
              <Field label="拦截次数 / 5 分钟">
                <Input type="number" min={1} value={s.attack_ban.threshold} onChange={(e) => up({ attack_ban: { ...s.attack_ban, threshold: Number(e.target.value) } })} />
              </Field>
              <Field label="封禁分钟">
                <Input type="number" min={1} value={s.attack_ban.minutes} onChange={(e) => up({ attack_ban: { ...s.attack_ban, minutes: Number(e.target.value) } })} />
              </Field>
            </div>
          )}
        </Section>

        <Section title="访问控制">
          <Field label="封禁地区" hint="ISO 两位国家代码，逗号分隔，如 RU, KP。需要配置 GeoIP 数据库。">
            <Input
              value={s.block_countries.join(", ")}
              onChange={(e) => up({ block_countries: e.target.value.split(/[,\s]+/).map((c) => c.trim().toUpperCase()).filter(Boolean) })}
              placeholder="RU, KP"
            />
            {s.block_countries.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {s.block_countries.map((c) => (
                  <Badge key={c}>{flag(c)} {countryName(c)}</Badge>
                ))}
              </div>
            )}
          </Field>
          <Field label="路径访问规则" hint="例如：/admin 只允许 VPN 网段 10.8.0.0/24 访问">
            <div className="space-y-2">
              {s.path_rules.map((r, i) => (
                <div key={i} className="grid grid-cols-[1fr_120px_1.4fr_auto] gap-2 items-start">
                  <Input value={r.path} placeholder="/admin" onChange={(e) => setPathRule(i, { path: e.target.value })} className="font-mono" />
                  <Select value={r.action} onChange={(e) => setPathRule(i, { action: e.target.value as PathRule["action"] })}>
                    <option value="allow">仅允许</option>
                    <option value="deny">禁止访问</option>
                  </Select>
                  <Input
                    value={r.cidrs.join(", ")}
                    disabled={r.action === "deny"}
                    placeholder={r.action === "deny" ? "所有人" : "10.8.0.0/24, 1.2.3.4"}
                    onChange={(e) => setPathRule(i, { cidrs: e.target.value.split(/[,\s]+/).filter(Boolean) })}
                    className="font-mono"
                  />
                  <Button variant="ghost" onClick={() => up({ path_rules: s.path_rules.filter((_, j) => j !== i) })} aria-label="移除">
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              ))}
              <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => up({ path_rules: [...s.path_rules, { path: "/", action: "allow", cidrs: [] }] })}>
                添加路径规则
              </Button>
            </div>
          </Field>
        </Section>
      </fieldset>
    </Drawer>
  );
}
