import { useEffect, useState } from "react";
import { RotateCw, Search, X } from "lucide-react";
import { api, type WafEvent } from "../lib/api";
import { useSites } from "../lib/hooks";
import { actionLabels, actionTone, categoryLabel, categoryLabels, decodeUri, flag, fmtTime } from "../lib/format";
import { EventDetail } from "../components/EventDetail";
import { Badge, Button, Card, Input, PageHeader, Pager, Select, Spinner, Table, Td } from "../components/ui";

const LIMIT = 50;

export default function Events() {
  const { sites, name } = useSites();
  const [filters, setFilters] = useState({ site: 0, ip: "", action: "", category: "", q: "", hours: 24 });
  const [qInput, setQInput] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ events: WafEvent[]; total: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<WafEvent | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    setLoading(true);
    const from = filters.hours ? Math.floor(Date.now() / 1000) - filters.hours * 3600 : undefined;
    api
      .events({ site: filters.site, ip: filters.ip, action: filters.action, category: filters.category, q: filters.q, from, limit: LIMIT, offset })
      .then(setData)
      .catch(() => setData({ events: [], total: 0 }))
      .finally(() => setLoading(false));
  }, [filters, offset, tick]);

  const set = (patch: Partial<typeof filters>) => {
    setOffset(0);
    setFilters((f) => ({ ...f, ...patch }));
  };

  return (
    <>
      <PageHeader
        title="攻击日志"
        desc="所有被拦截、限流、封禁和观察模式记录的请求。点击一行查看详情、封禁 IP 或标记误报。"
        actions={<Button icon={<RotateCw className="size-4" />} onClick={() => setTick((t) => t + 1)}>刷新</Button>}
      />
      <Card bodyClass="p-4">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 mb-4">
          <form
            className="col-span-2 relative"
            onSubmit={(e) => {
              e.preventDefault();
              set({ q: qInput.trim() });
            }}
          >
            <Search className="size-4 text-muted absolute left-3 top-2.5" />
            <Input className="pl-9" placeholder="搜索路径、域名、规则描述…" value={qInput} onChange={(e) => setQInput(e.target.value)} />
          </form>
          <Select value={filters.hours} onChange={(e) => set({ hours: Number(e.target.value) })}>
            <option value={1}>近 1 小时</option>
            <option value={24}>近 24 小时</option>
            <option value={168}>近 7 天</option>
            <option value={720}>近 30 天</option>
            <option value={0}>全部时间</option>
          </Select>
          <Select value={filters.site} onChange={(e) => set({ site: Number(e.target.value) })}>
            <option value={0}>全部站点</option>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </Select>
          <Select value={filters.action} onChange={(e) => set({ action: e.target.value })}>
            <option value="">全部动作</option>
            {Object.entries(actionLabels).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </Select>
          <Select value={filters.category} onChange={(e) => set({ category: e.target.value })}>
            <option value="">全部类型</option>
            {Object.entries(categoryLabels).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </Select>
        </div>
        {(filters.ip || filters.q) && (
          <div className="flex flex-wrap gap-2 mb-3">
            {filters.ip && (
              <button onClick={() => set({ ip: "" })} className="inline-flex items-center gap-1 text-xs bg-accent-soft text-accent rounded-md px-2 py-1">
                IP: {filters.ip} <X className="size-3" />
              </button>
            )}
            {filters.q && (
              <button onClick={() => { setQInput(""); set({ q: "" }); }} className="inline-flex items-center gap-1 text-xs bg-accent-soft text-accent rounded-md px-2 py-1">
                搜索: {filters.q} <X className="size-3" />
              </button>
            )}
          </div>
        )}

        {loading && !data ? (
          <Spinner />
        ) : (
          <>
            <Table head={["时间", "动作", "来源", "站点", "请求", "类型 / 规则"]} empty={data?.events.length === 0}>
              {data?.events.map((e) => (
                <tr key={e.id} onClick={() => setSelected(e)} className="cursor-pointer">
                  <Td className="whitespace-nowrap text-muted tabular text-[13px]">{fmtTime(e.ts)}</Td>
                  <Td><Badge tone={actionTone(e.action)}>{actionLabels[e.action]}</Badge></Td>
                  <Td mono className="whitespace-nowrap">{flag(e.country)} {e.client_ip}</Td>
                  <Td className="whitespace-nowrap">{name(e.site_id)}</Td>
                  <Td mono className="max-w-[380px] truncate"><span className="text-muted">{e.method}</span> {decodeUri(e.uri)}</Td>
                  <Td className="max-w-[300px]">
                    <div className="flex items-center gap-2 min-w-0">
                      {e.category && <Badge tone="accent">{categoryLabel(e.category)}</Badge>}
                      <span className="truncate text-[13px] text-muted">{e.rule_id > 0 && <span className="font-mono">{e.rule_id} </span>}{e.message}</span>
                    </div>
                  </Td>
                </tr>
              ))}
            </Table>
            {data && <Pager total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />}
          </>
        )}
      </Card>
      <EventDetail
        event={selected}
        siteName={name}
        onClose={() => setSelected(null)}
        onFilterIP={(ip) => {
          setSelected(null);
          set({ ip });
        }}
      />
    </>
  );
}
