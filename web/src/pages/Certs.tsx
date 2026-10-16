import { useState } from "react";
import { FileKey2, Plus, RefreshCw, Trash2 } from "lucide-react";
import { api, type Cert } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { fmtTime } from "../lib/format";
import { Badge, Button, Empty, Field, Input, Modal, PageHeader, Spinner, Textarea, useAction, useToast } from "../components/ui";

function daysLeft(c: Cert) {
  return Math.floor((c.not_after * 1000 - Date.now()) / 86400000);
}

export default function Certs() {
  const { data, loading, reload } = useLoad(() => api.certs().then((r) => r.certs));
  const [editing, setEditing] = useState<{ id?: number; name: string } | null>(null);
  const { confirm } = useToast();
  const { run } = useAction();

  const del = async (c: Cert) => {
    if (!(await confirm(`删除证书「${c.name}」？使用它的域名将改用 Let's Encrypt（如已启用），否则 HTTPS 将无法访问。`, { danger: true, ok: "删除" }))) return;
    if (await run(() => api.deleteCert(c.id), "已删除")) reload();
  };

  return (
    <>
      <PageHeader
        title="证书管理"
        desc="上传自己的 HTTPS 证书，支持泛域名证书（*.example.com）。上传的证书优先于 Let's Encrypt 使用，到期前 14 天会推送提醒。"
        actions={<Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditing({ name: "" })}>上传证书</Button>}
      />
      {loading && !data ? (
        <Spinner />
      ) : !data?.length ? (
        <div className="bg-surface border border-dashed border-border rounded-xl">
          <Empty text="还没有上传证书。未上传时，开启 HTTPS 的站点会使用 Let's Encrypt 自动签发。" />
        </div>
      ) : (
        <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
          {data.map((c) => {
            const left = daysLeft(c);
            const tone = left < 0 ? "danger" : left <= 14 ? "warn" : "ok";
            return (
              <article key={c.id} className="bg-surface border border-border rounded-xl p-4 flex flex-col">
                <div className="flex items-start gap-3 mb-3">
                  <div className="size-9 rounded-lg bg-accent-soft text-accent grid place-items-center shrink-0">
                    <FileKey2 className="size-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h3 className="font-semibold truncate">{c.name}</h3>
                    <div className="text-xs text-muted truncate">颁发者：{c.issuer || "未知"}</div>
                  </div>
                  <Badge tone={tone}>{left < 0 ? "已过期" : `剩余 ${left} 天`}</Badge>
                </div>
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {c.domains.map((d) => (
                    <Badge key={d} tone={d.startsWith("*.") ? "accent" : "muted"} className="font-mono">{d}</Badge>
                  ))}
                </div>
                <div className="text-xs text-muted mb-4">有效期：{fmtTime(c.not_before).slice(0, 10)} 至 {fmtTime(c.not_after).slice(0, 10)}</div>
                <div className="mt-auto flex gap-2">
                  <Button size="sm" icon={<RefreshCw className="size-3.5" />} onClick={() => setEditing({ id: c.id, name: c.name })}>更新证书</Button>
                  <Button size="sm" variant="ghost" onClick={() => del(c)} aria-label="删除"><Trash2 className="size-4" /></Button>
                </div>
              </article>
            );
          })}
        </div>
      )}
      {editing && <CertEditor init={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function CertEditor({ init, onClose, onSaved }: { init: { id?: number; name: string }; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ name: init.name, cert: "", key: "" });
  const { run, busy } = useAction();
  const readFile = (k: "cert" | "key") => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) file.text().then((t) => setF((x) => ({ ...x, [k]: t })));
  };
  const save = async () => {
    if (await run(() => api.saveCert({ id: init.id, ...f }), init.id ? "证书已更新，2 秒内生效" : "证书已上传，2 秒内生效")) onSaved();
  };
  return (
    <Modal open wide onClose={onClose} title={init.id ? `更新证书 · ${init.name}` : "上传证书"} footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" loading={busy} onClick={save}>保存</Button></>}>
      <div className="space-y-4">
        <Field label="名称" hint="留空则使用证书中的第一个域名">
          <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="例如：example.com 泛域名" />
        </Field>
        <Field label={<span className="flex items-center justify-between w-full">证书（PEM，含中间证书链）<input type="file" accept=".pem,.crt,.cer" onChange={readFile("cert")} className="text-xs text-muted file:mr-2 file:rounded-md file:border-0 file:bg-surface-2 file:px-2 file:py-1 file:text-xs" /></span>} hint="通常是 fullchain.pem 或 .crt 文件，以 -----BEGIN CERTIFICATE----- 开头">
          <Textarea rows={6} value={f.cert} onChange={(e) => setF({ ...f, cert: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
        </Field>
        <Field label={<span className="flex items-center justify-between w-full">私钥（PEM）<input type="file" accept=".pem,.key" onChange={readFile("key")} className="text-xs text-muted file:mr-2 file:rounded-md file:border-0 file:bg-surface-2 file:px-2 file:py-1 file:text-xs" /></span>} hint="私钥加密保存，保存后不会再显示">
          <Textarea rows={5} value={f.key} onChange={(e) => setF({ ...f, key: e.target.value })} placeholder="-----BEGIN PRIVATE KEY-----" />
        </Field>
      </div>
    </Modal>
  );
}
