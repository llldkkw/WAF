import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Ban, CheckCircle2, ShieldCheck, Unlock } from "lucide-react";
import { api, type ActionInfo } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtTime } from "../lib/format";
import { Button, Card, PageHeader, Spinner } from "../components/ui";

/** Landing page for one-click links from notifications. Nothing happens until the operator confirms. */
export default function ActionConfirm() {
  const [params] = useSearchParams();
  const token = params.get("t") ?? "";
  const { isAdmin } = useAuth();
  const nav = useNavigate();
  const [info, setInfo] = useState<ActionInfo | null>(null);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!isAdmin) {
      setErr("只有管理员可以执行该操作");
      return;
    }
    api.inspectAction(token).then(setInfo).catch((e) => setErr((e as Error).message));
  }, [token, isAdmin]);

  const execute = async () => {
    setBusy(true);
    try {
      const r = await api.executeAction(token);
      setDone(r.description);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const icon = info?.action === "ban" ? <Ban className="size-6 text-danger" /> : info?.action === "allow" ? <ShieldCheck className="size-6 text-ok" /> : <Unlock className="size-6 text-accent" />;

  return (
    <>
      <PageHeader title="确认操作" desc="来自推送通知的一键操作链接。每个链接只能使用一次，7 天后失效。" />
      <div className="max-w-lg">
        <Card>
          {err ? (
            <div className="text-center py-6">
              <p className="text-danger font-medium mb-4">{err}</p>
              <Button onClick={() => nav("/ip-rules")}>前往 IP 黑白名单</Button>
            </div>
          ) : done ? (
            <div className="text-center py-6">
              <CheckCircle2 className="size-10 text-ok mx-auto mb-3" />
              <p className="font-medium mb-1">已完成：{done}</p>
              <p className="text-sm text-muted mb-4">2 秒内对所有站点生效。</p>
              <Button onClick={() => nav("/ip-rules")}>查看 IP 黑白名单</Button>
            </div>
          ) : !info ? (
            <Spinner />
          ) : (
            <div>
              <div className="flex items-center gap-3 mb-5">
                <div className="size-12 rounded-xl bg-surface-2 grid place-items-center">{icon}</div>
                <div>
                  <div className="text-lg font-semibold">{info.description}</div>
                  <div className="text-sm text-muted font-mono">{info.ip}{info.location && <span className="font-sans"> · {info.location}</span>}</div>
                </div>
              </div>
              <dl className="text-sm space-y-2 mb-6">
                {info.reason && <div className="flex justify-between"><dt className="text-muted">原因</dt><dd>{info.reason}</dd></div>}
                <div className="flex justify-between"><dt className="text-muted">范围</dt><dd>全部站点</dd></div>
                <div className="flex justify-between"><dt className="text-muted">链接有效期至</dt><dd className="tabular">{fmtTime(info.expires_at)}</dd></div>
              </dl>
              {info.used ? (
                <p className="text-sm text-warn bg-warn-soft rounded-lg px-3 py-2">该链接已经使用过。</p>
              ) : (
                <div className="flex gap-2">
                  <Button variant={info.action === "ban" ? "danger" : "primary"} loading={busy} onClick={execute}>确认执行</Button>
                  <Button onClick={() => nav("/")}>取消</Button>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
