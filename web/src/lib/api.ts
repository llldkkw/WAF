// Typed client for the admin API.

export type Role = "admin" | "viewer";

export interface User {
  id: number;
  username: string;
  role: Role;
  disabled: boolean;
  created_at: number;
  last_login_at: number;
  last_login_ip: string;
}

export interface RateLimit {
  enabled: boolean;
  rps: number;
  burst: number;
  ban_threshold: number;
  ban_minutes: number;
}

export interface AttackBan {
  enabled: boolean;
  threshold: number;
  minutes: number;
}

export interface RuleExclusion {
  rule_id: number;
  path: string;
  note: string;
}

export interface PathRule {
  path: string;
  action: "deny" | "allow";
  cidrs: string[];
}

export interface HealthCheck {
  enabled: boolean;
  path: string;
  interval_sec: number;
}

export type Mode = "block" | "detect" | "off";

export interface GeoPolicy {
  mode: "off" | "block" | "allow";
  rules: string[];
  allow_unknown: boolean;
}

export interface Challenge {
  mode: "off" | "always" | "suspicious";
  ttl_hours: number;
  difficulty: number;
  exempt_paths: string[];
  provider: "pow" | "turnstile" | "recaptcha";
}

export interface CaptchaProviders {
  turnstile: { site_key: string; secret: string };
  recaptcha: { site_key: string; secret: string; version: "v2" | "v3"; min_score: number; domain: string };
}

export interface Cert {
  id: number;
  name: string;
  domains: string[];
  issuer: string;
  not_before: number;
  not_after: number;
  created_at: number;
}

export interface ActionInfo {
  action: "ban" | "allow" | "unban";
  ip: string;
  minutes: number;
  reason: string;
  expires_at: number;
  used: boolean;
  description: string;
  location: string;
}

export interface ReportSettings {
  daily: boolean;
  daily_time: string;
  weekly: boolean;
  weekly_day: number;
  weekly_time: string;
}

export interface Site {
  id: number;
  name: string;
  enabled: boolean;
  created_at: number;
  updated_at: number;
  hosts: string[];
  upstreams: string[];
  preserve_host: boolean;
  mode: Mode;
  paranoia_level: number;
  anomaly_threshold: number;
  upstream_insecure: boolean;
  https: boolean;
  force_https: boolean;
  rate_limit: RateLimit;
  attack_ban: AttackBan;
  geo: GeoPolicy;
  challenge: Challenge;
  rule_exclusions: RuleExclusion[];
  path_rules: PathRule[];
  health_check: HealthCheck;
}

export interface IPRule {
  id: number;
  cidr: string;
  action: "allow" | "deny";
  site_id: number;
  note: string;
  source: string;
  expires_at: number;
  created_by: string;
  created_at: number;
}

export interface Match {
  rule_id: number;
  message: string;
  data: string;
  severity: string;
  variable: string;
}

export type Action = "blocked" | "detected" | "rate_limited" | "ip_denied" | "geo_denied" | "path_denied";

export interface WafEvent {
  id: number;
  ts: number;
  site_id: number;
  client_ip: string;
  country: string;
  method: string;
  host: string;
  uri: string;
  user_agent: string;
  action: Action;
  status: number;
  rule_id: number;
  message: string;
  category: string;
  severity: string;
  matches: Match[] | null;
}

export interface Count {
  key: string;
  count: number;
}

export interface Overview {
  requests: number;
  blocked: number;
  attackers: number;
  series: { ts: number; requests: number; blocked: number }[];
  top_ips: Count[];
  categories: Count[];
  actions: Count[];
  top_uris: Count[];
  top_rules: Count[];
  countries: Count[];
}

export interface Status {
  version: string;
  uptime: number;
  goroutines: number;
  memory_mb: number;
  acme: boolean;
  geo: { enabled: boolean; city: boolean };
  public_url: string;
  timezone: string;
  tls_missing: string[];
  proxy: {
    sites: number;
    version: number;
    upstreams: { site_id: number; site: string; url: string; healthy: boolean; checked: boolean }[];
  };
}

export interface AuditEntry {
  id: number;
  ts: number;
  username: string;
  ip: string;
  action: string;
  target: string;
  detail: string;
}

export interface ChannelField {
  key: string;
  label: string;
  placeholder?: string;
  secret: boolean;
  required: boolean;
  options?: { value: string; label: string }[];
}

export interface ChannelType {
  type: string;
  label: string;
  fields: ChannelField[];
}

export type Level = "info" | "warning" | "critical";

export interface Channel {
  id: number;
  name: string;
  type: string;
  config: Record<string, string>;
  min_level: Level;
  enabled: boolean;
  created_at: number;
}

export interface Enrollment {
  user: User;
  totp_secret: string;
  totp_url: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();
export function onUnauthorized(fn: Listener) {
  unauthorizedListeners.add(fn);
  return () => {
    unauthorizedListeners.delete(fn);
  };
}

interface ReqOpts {
  body?: unknown;
  background?: boolean;
}

async function request<T>(method: string, path: string, opts: ReqOpts = {}): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "waf" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.background) headers["X-Background"] = "1";
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error ?? `请求失败 (${res.status})`;
    if (res.status === 401 && path !== "/api/login") unauthorizedListeners.forEach((f) => f());
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

function qs(params: Record<string, string | number | undefined>) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "" && v !== 0) p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const api = {
  login: (username: string, password: string, code: string) =>
    request<{ user: User }>("POST", "/api/login", { body: { username, password, code } }),
  logout: () => request("POST", "/api/logout"),
  me: () => request<{ user: User }>("GET", "/api/me"),
  changePassword: (current: string, next: string) =>
    request("POST", "/api/me/password", { body: { current, new: next } }),

  overview: (range: string, site?: number, background = false) =>
    request<{ overview: Overview; bucket: number }>("GET", `/api/overview${qs({ range, site })}`, { background }),
  status: (background = false) => request<Status>("GET", "/api/status", { background }),

  sites: () => request<{ sites: Site[] }>("GET", "/api/sites"),
  saveSite: (s: Partial<Site>) =>
    s.id ? request<{ site: Site }>("PUT", `/api/sites/${s.id}`, { body: s }) : request<{ site: Site }>("POST", "/api/sites", { body: s }),
  deleteSite: (id: number) => request("DELETE", `/api/sites/${id}`),
  addExclusion: (siteId: number, ex: RuleExclusion) =>
    request<{ site: Site }>("POST", `/api/sites/${siteId}/exclusions`, { body: ex }),

  ipRules: () => request<{ rules: IPRule[] }>("GET", "/api/ip-rules"),
  addIPRule: (r: { cidr: string; action: string; site_id: number; note: string; minutes: number }) =>
    request<{ rule: IPRule }>("POST", "/api/ip-rules", { body: r }),
  deleteIPRule: (id: number) => request("DELETE", `/api/ip-rules/${id}`),

  events: (f: Record<string, string | number | undefined>) =>
    request<{ events: WafEvent[]; total: number }>("GET", `/api/events${qs(f)}`),
  audit: (limit: number, offset: number) =>
    request<{ entries: AuditEntry[]; total: number }>("GET", `/api/audit${qs({ limit, offset })}`),

  channelTypes: () => request<{ types: ChannelType[] }>("GET", "/api/channel-types"),
  channels: () => request<{ channels: Channel[] }>("GET", "/api/channels"),
  saveChannel: (c: Partial<Channel>) =>
    c.id ? request("PUT", `/api/channels/${c.id}`, { body: c }) : request("POST", "/api/channels", { body: c }),
  deleteChannel: (id: number) => request("DELETE", `/api/channels/${id}`),
  testChannel: (id: number) => request("POST", `/api/channels/${id}/test`),

  certs: () => request<{ certs: Cert[] }>("GET", "/api/certs"),
  saveCert: (c: { id?: number; name: string; cert: string; key: string }) =>
    c.id
      ? request<{ cert: Cert }>("PUT", `/api/certs/${c.id}`, { body: { name: c.name, cert: c.cert, key: c.key } })
      : request<{ cert: Cert }>("POST", "/api/certs", { body: { name: c.name, cert: c.cert, key: c.key } }),
  deleteCert: (id: number) => request("DELETE", `/api/certs/${id}`),

  inspectAction: (t: string) => request<ActionInfo>("GET", `/api/actions?t=${encodeURIComponent(t)}`),
  executeAction: (token: string) => request<{ ok: boolean; description: string }>("POST", "/api/actions", { body: { token } }),

  reportSettings: () => request<{ settings: ReportSettings; timezone: string }>("GET", "/api/settings/reports"),
  saveReportSettings: (s: ReportSettings) => request("PUT", "/api/settings/reports", { body: s }),
  sendReport: (period: "daily" | "weekly") => request<{ ok: boolean; preview: string }>("POST", "/api/reports/send", { body: { period } }),

  captcha: () => request<{ captcha: CaptchaProviders }>("GET", "/api/settings/captcha"),
  saveCaptcha: (c: CaptchaProviders) => request("PUT", "/api/settings/captcha", { body: c }),

  users: () => request<{ users: User[] }>("GET", "/api/users"),
  createUser: (u: { username: string; password: string; role: Role }) =>
    request<Enrollment>("POST", "/api/users", { body: u }),
  updateUser: (id: number, u: { role: Role; disabled: boolean }) => request("PUT", `/api/users/${id}`, { body: u }),
  deleteUser: (id: number) => request("DELETE", `/api/users/${id}`),
  resetUser: (id: number, password: string) => request<Enrollment>("POST", `/api/users/${id}/reset`, { body: { password } }),
};
