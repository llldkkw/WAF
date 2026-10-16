import { useState } from "react";
import { api } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { fmtTime } from "../lib/format";
import { Badge, Card, PageHeader, Pager, Spinner, Table, Td, type Tone } from "../components/ui";

const LIMIT = 50;

const labels: Record<string, [string, Tone]> = {
  login: ["登录", "ok"],
  login_failed: ["登录失败", "danger"],
  change_password: ["修改密码", "warn"],
  site_create: ["新建站点", "accent"],
  site_update: ["修改站点", "accent"],
  site_delete: ["删除站点", "danger"],
  rule_exclusion: ["误报排除", "warn"],
  ip_add: ["添加 IP 规则", "accent"],
  ip_delete: ["删除 IP 规则", "warn"],
  ip_allow: ["命令行加白", "warn"],
  ip_deny: ["命令行拉黑", "accent"],
  ip_del: ["命令行删除 IP", "warn"],
  channel_save: ["保存通知渠道", "accent"],
  channel_delete: ["删除通知渠道", "warn"],
  cert_upload: ["上传证书", "accent"],
  cert_replace: ["更新证书", "accent"],
  cert_delete: ["删除证书", "danger"],
  action_link: ["一键操作", "warn"],
  report_settings: ["报告设置", "accent"],
  captcha_settings: ["人机验证服务", "warn"],
  user_create: ["新建用户", "accent"],
  user_update: ["修改用户", "warn"],
  user_delete: ["删除用户", "danger"],
  user_reset: ["重置凭据", "danger"],
  user_add: ["命令行建用户", "warn"],
};

export default function Audit() {
  const [offset, setOffset] = useState(0);
  const { data, loading } = useLoad(() => api.audit(LIMIT, offset), [offset]);
  return (
    <>
      <PageHeader title="操作审计" desc="记录所有登录和配置变更，保留 365 天。" />
      <Card>
        {loading && !data ? (
          <Spinner />
        ) : (
          <>
            <Table head={["时间", "用户", "来源 IP", "操作", "对象", "详情"]} empty={data?.entries.length === 0}>
              {data?.entries.map((e) => {
                const [label, tone] = labels[e.action] ?? [e.action, "muted" as Tone];
                return (
                  <tr key={e.id}>
                    <Td className="whitespace-nowrap text-[13px] text-muted tabular">{fmtTime(e.ts)}</Td>
                    <Td className="font-medium">{e.username || "—"}</Td>
                    <Td mono>{e.ip}</Td>
                    <Td><Badge tone={tone}>{label}</Badge></Td>
                    <Td className="max-w-[240px] truncate">{e.target}</Td>
                    <Td mono className="max-w-[360px] truncate text-xs text-muted" >
                      <span title={e.detail}>{e.detail}</span>
                    </Td>
                  </tr>
                );
              })}
            </Table>
            {data && <Pager total={data.total} limit={LIMIT} offset={offset} onChange={setOffset} />}
          </>
        )}
      </Card>
    </>
  );
}
