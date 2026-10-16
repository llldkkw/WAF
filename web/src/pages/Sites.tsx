import { useEffect, useState, type ReactNode } from "react";
import { ArrowRight, Globe2, Lock, Pencil, Plus, Trash2 } from "lucide-react";
import { api, type CaptchaProviders, type Challenge, type GeoPolicy, type Mode, type PathRule, type Site, type Status } from "../lib/api";
import { cnProvinces, geoRuleLabel, needsCityDB } from "../lib/regions";
import { useAuth } from "../lib/auth";
import { useLoad } from "../lib/hooks";
import { modeLabels } from "../lib/format";
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
  geo: { mode: "off", rules: [], allow_unknown: false },
  challenge: { mode: "off", ttl_hours: 24, difficulty: 16, exempt_paths: [], provider: "pow" },
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
                {s.geo.mode === "block" && <Badge>封禁 {s.geo.rules.length} 个地区</Badge>}
                {s.geo.mode === "allow" && <Badge tone="info">仅允许 {s.geo.rules.length} 个地区</Badge>}
                {s.challenge.mode !== "off" && <Badge tone="info">人机验证</Badge>}
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
          <Switch
            checked={s.https}
            onChange={(v) => up({ https: v, force_https: v && s.force_https })}
            label="启用 HTTPS"
            desc="优先使用「证书管理」中上传的证书（含泛域名证书）；没有匹配的证书时，用 Let's Encrypt 自动签发（需在配置文件中启用 acme）"
          />
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

        <Section title="人机验证" desc="访客通过验证后才能进入，可挡住绝大多数爬虫、扫描器和脚本化 CC 攻击。可使用内置验证（浏览器自动计算，访客无感知），或 Cloudflare Turnstile、Google reCAPTCHA。注意：搜索引擎爬虫和 API 客户端也会被拦下，API 路径请加入免验证。">
          <Field label="验证模式">
            <Segmented<Challenge["mode"]>
              value={s.challenge.mode}
              onChange={(v) => up({ challenge: { ...s.challenge, mode: v } })}
              options={[
                { value: "off", label: "关闭" },
                { value: "suspicious", label: "仅可疑访问" },
                { value: "always", label: "所有访问" },
              ]}
            />
          </Field>
          <p className="text-xs text-muted -mt-2">
            「仅可疑访问」：最近触发过限流或拦截的 IP，以及不像浏览器的请求（无 User-Agent / 语言头）才需要验证。遭受 CC 攻击时可临时切换到「所有访问」。
          </p>
          {s.challenge.mode !== "off" && (
            <>
              <ProviderPicker value={s.challenge.provider} onChange={(provider) => up({ challenge: { ...s.challenge, provider } })} />
              <div className="grid grid-cols-2 gap-3">
                <Field label={s.challenge.provider === "pow" ? "难度" : "难度（内置验证备用）"}>
                  <Select value={s.challenge.difficulty} onChange={(e) => up({ challenge: { ...s.challenge, difficulty: Number(e.target.value) } })}>
                    <option value={14}>低（手机约 0.1 秒）</option>
                    <option value={16}>标准（推荐）</option>
                    <option value={18}>高（约 0.5–1 秒）</option>
                    <option value={20}>很高（数秒，仅遭受攻击时使用）</option>
                  </Select>
                </Field>
                <Field label="验证有效期（小时）">
                  <Input type="number" min={1} value={s.challenge.ttl_hours} onChange={(e) => up({ challenge: { ...s.challenge, ttl_hours: Number(e.target.value) } })} />
                </Field>
              </div>
              <Field label="免验证路径（每行一个前缀）" hint="API、Webhook、健康检查等非浏览器访问的路径">
                <LinesInput value={s.challenge.exempt_paths} onChange={(v) => up({ challenge: { ...s.challenge, exempt_paths: v } })} placeholder={"/api/\n/webhook/"} />
              </Field>
            </>
          )}
        </Section>

        <Section title="访问控制">
          <GeoEditor value={s.geo} onChange={(geo) => up({ geo })} />
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

function GeoEditor({ value: g, onChange }: { value: GeoPolicy; onChange: (g: GeoPolicy) => void }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [prov, setProv] = useState("");
  useEffect(() => {
    api.status().then(setStatus).catch(() => {});
  }, []);
  const add = (r: string) => !g.rules.includes(r) && onChange({ ...g, rules: [...g.rules, r] });
  const geo = status?.geo;

  return (
    <Field label="地区访问策略">
      <div className="space-y-3">
        <Segmented<GeoPolicy["mode"]>
          value={g.mode}
          onChange={(mode) => onChange({ ...g, mode })}
          options={[
            { value: "off", label: "不限制" },
            { value: "block", label: "封禁以下地区" },
            { value: "allow", label: "仅允许以下地区" },
          ]}
        />
        {geo && !geo.enabled && g.mode !== "off" && (
          <p className="text-xs text-warn bg-warn-soft rounded-lg px-3 py-2">尚未配置 GeoIP 数据库，地区策略不会生效。请在配置文件中设置 geoip_db。</p>
        )}
        {geo?.enabled && !geo.city && needsCityDB(g.rules) && (
          <p className="text-xs text-warn bg-warn-soft rounded-lg px-3 py-2">按省份或城市匹配需要 GeoLite2-City 数据库，当前是国家库，省市规则不会生效。</p>
        )}
        {g.mode !== "off" && (
          <>
            <LinesInput value={g.rules} onChange={(rules) => onChange({ ...g, rules })} placeholder={"CN\nCN-GD\nCN/深圳"} rows={4} />
            <p className="text-xs text-muted">
              每行一条：国家 <code className="font-mono">CN</code>、省份 <code className="font-mono">CN-GD</code>、城市{" "}
              <code className="font-mono">CN/深圳</code> 或 <code className="font-mono">CN-GD/Shenzhen</code>。内网和 VPN 地址始终放行。
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={() => add("CN")}>+ 中国大陆</Button>
              <Button size="sm" onClick={() => add("HK")}>+ 香港</Button>
              <Select value={prov} onChange={(e) => { if (e.target.value) add(`CN-${e.target.value}`); setProv(""); }} className="w-40 h-8">
                <option value="">+ 添加省份…</option>
                {Object.entries(cnProvinces).map(([code, name]) => (
                  <option key={code} value={code}>{name}</option>
                ))}
              </Select>
            </div>
            {g.rules.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {g.rules.map((r) => (
                  <Badge key={r} tone={g.mode === "allow" ? "ok" : "danger"}>{geoRuleLabel(r)}</Badge>
                ))}
              </div>
            )}
            {g.mode === "allow" && (
              <Switch checked={g.allow_unknown} onChange={(v) => onChange({ ...g, allow_unknown: v })} label="放行无法识别地区的 IP" desc="关闭时，数据库查不到位置的公网 IP 会被拒绝" />
            )}
          </>
        )}
      </div>
    </Field>
  );
}

function ProviderPicker({ value, onChange }: { value: Challenge["provider"]; onChange: (v: Challenge["provider"]) => void }) {
  const { isAdmin } = useAuth();
  const [caps, setCaps] = useState<CaptchaProviders | null>(null);
  useEffect(() => {
    if (isAdmin) api.captcha().then((r) => setCaps(r.captcha)).catch(() => {});
  }, [isAdmin]);
  const ready = {
    pow: true,
    turnstile: !!caps?.turnstile.site_key && !!caps?.turnstile.secret,
    recaptcha: !!caps?.recaptcha.site_key && !!caps?.recaptcha.secret,
  };
  return (
    <Field
      label="验证方式"
      hint={
        value !== "pow" && caps && !ready[value] ? (
          <span className="text-warn">尚未在「系统设置」中配置该服务的密钥，将自动使用内置验证。</span>
        ) : value === "pow" ? (
          "无需第三方服务，访客无感知（自动计算），隐私友好，国内访问无障碍。"
        ) : value === "turnstile" ? (
          "Cloudflare Turnstile：多数情况下无需点击，免费。"
        ) : (
          "Google reCAPTCHA：默认通过 recaptcha.net 加载，国内可用。"
        )
      }
    >
      <Segmented<Challenge["provider"]>
        value={value}
        onChange={onChange}
        options={[
          { value: "pow", label: "内置验证" },
          { value: "turnstile", label: "Cloudflare Turnstile" },
          { value: "recaptcha", label: "Google reCAPTCHA" },
        ]}
      />
    </Field>
  );
}
