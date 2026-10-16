import countries from "i18n-iso-countries";
import zh from "i18n-iso-countries/langs/zh.json";
import type { Action } from "./api";

countries.registerLocale(zh);

export function countryName(code: string) {
  if (!code) return "";
  return countries.getName(code, "zh") ?? code;
}

export function numericToAlpha2(n: string) {
  return countries.numericToAlpha2(n) ?? "";
}

export function flag(code: string) {
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return String.fromCodePoint(...[...code].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}

export const categoryLabels: Record<string, string> = {
  sqli: "SQL 注入",
  xss: "XSS 跨站脚本",
  rce: "命令执行",
  lfi: "本地文件包含",
  rfi: "远程文件包含",
  php: "PHP 注入",
  java: "Java 攻击",
  protocol: "协议违规",
  scanner: "扫描器",
  generic: "通用攻击",
  injection: "注入",
  fixation: "会话固定",
  "multipart-header": "畸形上传",
  nodejs: "Node.js 攻击",
};

export function categoryLabel(c: string) {
  return categoryLabels[c] ?? (c || "—");
}

export const actionLabels: Record<Action, string> = {
  blocked: "WAF 拦截",
  detected: "观察记录",
  rate_limited: "限流",
  ip_denied: "IP 封禁",
  geo_denied: "地区封禁",
  path_denied: "路径限制",
};

export function actionTone(a: Action): "danger" | "warn" | "info" | "muted" {
  switch (a) {
    case "blocked":
      return "danger";
    case "detected":
      return "info";
    case "rate_limited":
      return "warn";
    default:
      return "muted";
  }
}

export const modeLabels = { block: "拦截模式", detect: "观察模式", off: "仅代理" } as const;

export function fmtTime(ts: number, withDate = true) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  const t = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  if (!withDate) return t;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${t}`;
}

export function fmtRelative(ts: number) {
  if (!ts) return "从未";
  const s = Math.floor(Date.now() / 1000) - ts;
  if (s < 60) return "刚刚";
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

/** Percent-decodes a URI for display (attack payloads are easier to read). */
export function decodeUri(u: string) {
  try {
    return decodeURIComponent(u.replace(/\+/g, " "));
  } catch {
    return u;
  }
}

export function fmtNum(n: number) {
  if (n >= 1e8) return (n / 1e8).toFixed(1) + " 亿";
  if (n >= 1e4) return (n / 1e4).toFixed(1) + " 万";
  return n.toLocaleString("zh-CN");
}

export function fmtDuration(sec: number) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} 天 ${h} 小时`;
  if (h) return `${h} 小时 ${m} 分`;
  return `${m} 分钟`;
}

export function pct(a: number, b: number) {
  if (!b) return "0%";
  const v = (a / b) * 100;
  return (v < 1 && v > 0 ? v.toFixed(2) : v.toFixed(1)) + "%";
}
