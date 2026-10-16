import { useEffect, useMemo, useState } from "react";
import { Activity, Ban, Crosshair, Gauge, ShieldAlert, Users as UsersIcon } from "lucide-react";
import { api, type Overview, type Status, type WafEvent } from "../lib/api";
import { useSites } from "../lib/hooks";
import { useLive } from "../lib/live";
import { useTheme } from "../lib/theme";
import { actionLabels, actionTone, categoryLabel, countryName, decodeUri, flag, fmtDuration, fmtNum, fmtTime, pct } from "../lib/format";
import { Chart, cssVar, ensureWorldMap } from "../components/Chart";
import { EventDetail } from "../components/EventDetail";
import { Badge, Card, Dot, Empty, PageHeader, Segmented, Select, cx } from "../components/ui";

type Range = "1h" | "24h" | "7d" | "30d";

export default function Dashboard() {
  const [range, setRange] = useState<Range>("24h");
  const [site, setSite] = useState(0);
  const [ov, setOv] = useState<Overview | null>(null);
  const [bucket, setBucket] = useState(900);
  const [status, setStatus] = useState<Status | null>(null);
  const [selected, setSelected] = useState<WafEvent | null>(null);
  const { sites, name } = useSites();
  const live = useLive();

  useEffect(() => {
    let alive = true;
    const load = (bg: boolean) => {
      api.overview(range, site, bg).then((r) => {
        if (!alive) return;
        setOv(r.overview);
        setBucket(r.bucket);
      }).catch(() => {});
      api.status(bg).then((s) => alive && setStatus(s)).catch(() => {});
    };
    load(false);
    const t = setInterval(() => load(true), 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [range, site]);

  const qps = useMemo(() => {
    const last = live.ticks.slice(-5);
    if (!last.length) return { req: 0, blk: 0 };
    return {
      req: last.reduce((a, t) => a + t.requests, 0) / last.length,
      blk: last.reduce((a, t) => a + t.blocked, 0) / last.length,
    };
  }, [live.ticks]);

  const unhealthy = status?.proxy.upstreams.filter((u) => u.checked && !u.healthy) ?? [];

  return (
    <>
      <PageHeader
        title="安全总览"
        desc={status ? `运行 ${fmtDuration(status.uptime)} · ${status.proxy.sites} 个站点受保护 · 版本 ${status.version}` : " "}
        actions={
          <>
            <Select value={site} onChange={(e) => setSite(Number(e.target.value))} className="w-40">
              <option value={0}>全部站点</option>
              {sites.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </Select>
            <Segmented<Range>
              value={range}
              onChange={setRange}
              options={[
                { value: "1h", label: "1 小时" },
                { value: "24h", label: "24 小时" },
                { value: "7d", label: "7 天" },
                { value: "30d", label: "30 天" },
              ]}
            />
          </>
        }
      />

      {!!status?.tls_missing?.length && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-warn/40 bg-warn-soft px-4 py-3 text-sm">
          <ShieldAlert className="size-4 text-warn mt-0.5 shrink-0" />
          <div>
            <span className="font-medium text-warn">以下 HTTPS 域名没有可用证书：</span>
            {status.tls_missing.join("、")}。请在「证书管理」上传证书，或在配置中启用 acme。
          </div>
        </div>
      )}

      {unhealthy.length > 0 && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-danger/40 bg-danger-soft px-4 py-3 text-sm">
          <ShieldAlert className="size-4 text-danger mt-0.5 shrink-0" />
          <div>
            <span className="font-medium text-danger">{unhealthy.length} 个后端不可用：</span>
            {unhealthy.map((u) => `${u.site} (${u.url})`).join("、")}
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-4">
        <Stat icon={<Activity />} label="总请求" value={fmtNum(ov?.requests ?? 0)} />
        <Stat icon={<Ban />} label="已拦截" value={fmtNum(ov?.blocked ?? 0)} tone="danger" sub={`拦截率 ${pct(ov?.blocked ?? 0, ov?.requests ?? 0)}`} />
        <Stat icon={<UsersIcon />} label="攻击来源 IP" value={fmtNum(ov?.attackers ?? 0)} tone="warn" />
        <Stat icon={<Crosshair />} label="攻击类型" value={String(ov?.categories.length ?? 0)} sub={ov?.categories[0] ? `最多: ${categoryLabel(ov.categories[0].key)}` : undefined} />
        <Stat
          icon={<Gauge />}
          label="实时 QPS"
          value={qps.req.toFixed(qps.req < 10 ? 1 : 0)}
          tone="accent"
          sub={`拦截 ${qps.blk.toFixed(1)}/s`}
          className="col-span-2 lg:col-span-1"
          live
        />
      </div>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        <Card title="流量趋势" className="lg:col-span-2">
          <TrafficChart ov={ov} bucket={bucket} />
        </Card>
        <Card title="实时流量（近 2 分钟）">
          <LiveChart />
        </Card>
      </div>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        <Card title="攻击来源地图" className="lg:col-span-2">
          <WorldMap ov={ov} />
        </Card>
        <Card title="攻击类型分布">
          <CategoryChart ov={ov} />
        </Card>
      </div>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        <Card title="Top 攻击 IP">
          <TopList items={ov?.top_ips ?? []} render={(k) => <span className="font-mono text-[13px]">{k}</span>} />
        </Card>
        <Card title="Top 被攻击路径">
          <TopList items={ov?.top_uris ?? []} render={(k) => <span className="font-mono text-[13px]">{k}</span>} />
        </Card>
        <Card title="Top 命中规则">
          <TopList items={ov?.top_rules ?? []} render={(k) => {
            const [id, ...rest] = k.split(" ");
            return <span className="text-[13px]"><span className="font-mono text-accent mr-1.5">{id}</span>{rest.join(" ")}</span>;
          }} />
        </Card>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <Card title={<span className="flex items-center gap-2"><Dot tone={live.connected ? "ok" : "muted"} />实时攻击事件</span>} className="lg:col-span-2" bodyClass="p-0">
          <LiveFeed events={live.events} siteName={name} onSelect={setSelected} />
        </Card>
        <Card title="后端健康">
          {!status?.proxy.upstreams.length ? (
            <Empty text="尚未配置站点" />
          ) : (
            <ul className="space-y-2">
              {status.proxy.upstreams.map((u, i) => (
                <li key={i} className="flex items-center gap-2.5 text-sm">
                  <Dot tone={!u.checked ? "muted" : u.healthy ? "ok" : "danger"} />
                  <span className="font-medium">{u.site}</span>
                  <span className="font-mono text-xs text-muted truncate flex-1">{u.url}</span>
                  <span className={cx("text-xs", !u.checked ? "text-muted" : u.healthy ? "text-ok" : "text-danger")}>
                    {!u.checked ? "未检查" : u.healthy ? "正常" : "宕机"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <EventDetail event={selected} siteName={name} onClose={() => setSelected(null)} />
    </>
  );
}

function Stat({ icon, label, value, sub, tone = "muted", className, live }: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  tone?: "muted" | "danger" | "warn" | "accent";
  className?: string;
  live?: boolean;
}) {
  const iconTone = { muted: "text-muted bg-surface-2", danger: "text-danger bg-danger-soft", warn: "text-warn bg-warn-soft", accent: "text-accent bg-accent-soft" }[tone];
  return (
    <div className={cx("bg-surface border border-border rounded-xl p-4", className)}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-[13px] text-muted">{label}</span>
        <span className={cx("size-7 rounded-lg grid place-items-center [&>svg]:size-4", iconTone)}>{icon}</span>
      </div>
      <div className="text-2xl font-semibold tracking-tight tabular flex items-center gap-2">
        {value}
        {live && <span className="size-1.5 rounded-full bg-ok live-dot" />}
      </div>
      {sub && <div className="text-xs text-muted mt-1">{sub}</div>}
    </div>
  );
}

function fmtAxis(ts: number, bucket: number) {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return bucket >= 3600 * 6 || (bucket >= 3600 && d.getHours() === 0) ? `${d.getMonth() + 1}/${d.getDate()}` : `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function TrafficChart({ ov, bucket }: { ov: Overview | null; bucket: number }) {
  const { dark } = useTheme();
  const option = useMemo(() => {
    const s = ov?.series ?? [];
    const accent = cssVar("--accent");
    const danger = cssVar("--danger");
    const border = cssVar("--border");
    return {
      tooltip: { trigger: "axis" },
      legend: { top: 0, right: 0, icon: "roundRect", itemWidth: 10, itemHeight: 10, textStyle: { color: cssVar("--muted") } },
      xAxis: { type: "category", data: s.map((p) => fmtAxis(p.ts, bucket)), axisLine: { lineStyle: { color: border } }, axisTick: { show: false } },
      yAxis: { type: "value", splitLine: { lineStyle: { color: border, type: "dashed" } } },
      series: [
        { name: "请求", type: "line", smooth: true, showSymbol: s.length < 3, symbolSize: 8, data: s.map((p) => p.requests), lineStyle: { width: 2, color: accent }, itemStyle: { color: accent }, areaStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: accent + "55" }, { offset: 1, color: accent + "00" }] } } },
        { name: "拦截", type: "line", smooth: true, showSymbol: s.length < 3, symbolSize: 8, data: s.map((p) => p.blocked), lineStyle: { width: 2, color: danger }, itemStyle: { color: danger }, areaStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: danger + "44" }, { offset: 1, color: danger + "00" }] } } },
      ],
    };
  }, [ov, bucket, dark]);
  if (ov && !ov.series.length) return <Empty text="该时间段暂无流量" />;
  return <Chart option={option} height={260} />;
}

function LiveChart() {
  const { ticks } = useLive();
  const { dark } = useTheme();
  const option = useMemo(() => {
    const accent = cssVar("--accent");
    const danger = cssVar("--danger");
    const border = cssVar("--border");
    return {
      animation: false,
      tooltip: { trigger: "axis" },
      xAxis: { type: "category", data: ticks.map((t) => fmtTime(t.ts, false)), show: false },
      yAxis: { type: "value", splitLine: { lineStyle: { color: border, type: "dashed" } }, minInterval: 1 },
      series: [
        { name: "请求/秒", type: "bar", stack: "a", data: ticks.map((t) => t.requests - t.blocked), itemStyle: { color: accent, borderRadius: [2, 2, 0, 0] }, barCategoryGap: "20%" },
        { name: "拦截/秒", type: "bar", stack: "a", data: ticks.map((t) => t.blocked), itemStyle: { color: danger } },
      ],
    };
  }, [ticks, dark]);
  return <Chart option={option} height={260} />;
}

function WorldMap({ ov }: { ov: Overview | null }) {
  const { dark } = useTheme();
  const option = useMemo(() => {
    ensureWorldMap();
    const data = (ov?.countries ?? []).map((c) => ({ name: c.key, value: c.count }));
    const max = Math.max(1, ...data.map((d) => d.value));
    return {
      tooltip: {
        trigger: "item",
        formatter: (p: { name: string; value: number }) => `${flag(p.name)} ${countryName(p.name) || p.name}<br/><b>${isNaN(p.value) ? 0 : p.value}</b> 次攻击`,
      },
      visualMap: {
        min: 0, max, show: data.length > 0, left: 0, bottom: 0, itemWidth: 10, itemHeight: 80, calculable: false,
        text: ["多", "少"], textStyle: { color: cssVar("--muted") },
        inRange: { color: [cssVar("--warn-soft"), cssVar("--warn"), cssVar("--danger")] },
      },
      series: [{
        type: "map", map: "world", roam: false, data,
        emphasis: { label: { show: false }, itemStyle: { areaColor: cssVar("--accent") } },
        select: { disabled: true },
        itemStyle: { areaColor: cssVar("--surface-2"), borderColor: cssVar("--border"), borderWidth: 0.6 },
        layoutCenter: ["50%", "54%"], layoutSize: "118%",
      }],
    };
  }, [ov, dark]);
  return (
    <div className="relative overflow-hidden">
      <Chart option={option} height={300} />
      {ov && !ov.countries.length && (
        <p className="absolute inset-x-0 bottom-2 text-center text-xs text-muted pointer-events-none">暂无地区数据（需要在配置中设置 geoip_db）</p>
      )}
    </div>
  );
}

const palette = ["--danger", "--warn", "--accent", "--info", "--ok"];

function CategoryChart({ ov }: { ov: Overview | null }) {
  const { dark } = useTheme();
  const option = useMemo(() => {
    const data = (ov?.categories ?? []).map((c, i) => ({ name: categoryLabel(c.key), value: c.count, itemStyle: { color: i < palette.length ? cssVar(palette[i]) : undefined } }));
    return {
      tooltip: { trigger: "item", formatter: "{b}<br/><b>{c}</b> 次 ({d}%)" },
      legend: { bottom: 0, icon: "circle", itemWidth: 8, itemHeight: 8, textStyle: { color: cssVar("--muted"), fontSize: 12 } },
      series: [{
        type: "pie", radius: ["52%", "74%"], center: ["50%", "42%"], data,
        label: { show: false }, itemStyle: { borderColor: cssVar("--surface"), borderWidth: 2, borderRadius: 4 },
      }],
    };
  }, [ov, dark]);
  if (ov && !ov.categories.length) return <Empty text="暂无攻击，一切正常" />;
  return <Chart option={option} height={300} />;
}

function TopList({ items, render }: { items: { key: string; count: number }[]; render: (k: string) => React.ReactNode }) {
  if (!items.length) return <Empty />;
  const max = items[0].count;
  return (
    <ul className="space-y-2.5">
      {items.slice(0, 8).map((it) => (
        <li key={it.key} className="relative">
          <div className="flex items-center justify-between gap-3 relative z-10 px-2 py-1">
            <span className="min-w-0 flex-1 truncate">{render(it.key)}</span>
            <span className="tabular text-[13px] text-muted">{fmtNum(it.count)}</span>
          </div>
          <div className="absolute inset-y-0 left-0 rounded-md bg-accent-soft/70" style={{ width: `${(it.count / max) * 100}%` }} />
        </li>
      ))}
    </ul>
  );
}

function LiveFeed({ events, siteName, onSelect }: { events: WafEvent[]; siteName: (id: number) => string; onSelect: (e: WafEvent) => void }) {
  if (!events.length) return <Empty text="等待实时事件…" />;
  return (
    <ul className="divide-y divide-border max-h-[340px] overflow-y-auto">
      {events.slice(0, 30).map((e) => (
        <li key={`${e.id}-${e.ts}`}>
          <button onClick={() => onSelect(e)} className="w-full text-left px-4 py-2.5 hover:bg-surface-2/60 flex items-center gap-3 animate-in">
            <span className="text-xs text-muted tabular w-16 shrink-0">{fmtTime(e.ts, false)}</span>
            <Badge tone={actionTone(e.action)} className="shrink-0">{actionLabels[e.action]}</Badge>
            <span className="font-mono text-[13px] shrink-0 w-32 truncate">
              {flag(e.country)} {e.client_ip}
            </span>
            <span className="text-[13px] truncate flex-1 min-w-0">
              <span className="text-muted">{siteName(e.site_id)} </span>
              <span className="font-mono">{e.method} {decodeUri(e.uri)}</span>
            </span>
            {e.category && <Badge tone="accent" className="hidden sm:inline-flex">{categoryLabel(e.category)}</Badge>}
          </button>
        </li>
      ))}
    </ul>
  );
}
