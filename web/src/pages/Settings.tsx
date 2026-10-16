import { useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { api, type CaptchaProviders } from "../lib/api";
import { Badge, Button, Card, Field, Input, PageHeader, Segmented, Select, Spinner, useAction } from "../components/ui";

const MASK = "••••••";

export default function Settings() {
  const [c, setC] = useState<CaptchaProviders | null>(null);
  const [dirty, setDirty] = useState(false);
  const { run, busy } = useAction();

  useEffect(() => {
    api.captcha().then((r) => setC(r.captcha)).catch(() => {});
  }, []);
  if (!c) return <Spinner />;

  const upT = (p: Partial<CaptchaProviders["turnstile"]>) => { setC({ ...c, turnstile: { ...c.turnstile, ...p } }); setDirty(true); };
  const upR = (p: Partial<CaptchaProviders["recaptcha"]>) => { setC({ ...c, recaptcha: { ...c.recaptcha, ...p } }); setDirty(true); };
  const save = async () => {
    if (await run(() => api.saveCaptcha(c), "已保存，2 秒内生效")) setDirty(false);
  };
  const ready = (k: { site_key: string; secret: string }) => !!k.site_key && !!k.secret;

  return (
    <>
      <PageHeader
        title="系统设置"
        desc="第三方人机验证服务的密钥。配置后在「站点防护 → 人机验证」中为每个站点选择使用哪一种。"
        actions={<Button variant="primary" loading={busy} disabled={!dirty} onClick={save}>保存</Button>}
      />
      <div className="grid lg:grid-cols-2 gap-4 max-w-5xl">
        <Card
          title={<span className="flex items-center gap-2">Cloudflare Turnstile {ready(c.turnstile) ? <Badge tone="ok">已配置</Badge> : <Badge>未配置</Badge>}</span>}
          actions={<a className="text-xs text-accent inline-flex items-center gap-1" href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noreferrer">获取密钥 <ExternalLink className="size-3" /></a>}
        >
          <div className="space-y-4">
            <p className="text-[13px] text-muted">
              免费，大多数访客无需点击即可通过。域名不需要托管在 Cloudflare。在 Cloudflare 控制台 → Turnstile → 添加站点，填入你的域名，复制两个密钥。
            </p>
            <Field label="Site Key（站点密钥）">
              <Input className="font-mono" value={c.turnstile.site_key} onChange={(e) => upT({ site_key: e.target.value })} placeholder="0x4AAAAAAA..." />
            </Field>
            <Field label="Secret Key（私钥）" hint={c.turnstile.secret === MASK ? "已保存，保持「••••••」表示不修改" : "加密保存，保存后不再显示"}>
              <Input className="font-mono" type="password" autoComplete="off" value={c.turnstile.secret} onChange={(e) => upT({ secret: e.target.value })} />
            </Field>
          </div>
        </Card>

        <Card
          title={<span className="flex items-center gap-2">Google reCAPTCHA {ready(c.recaptcha) ? <Badge tone="ok">已配置</Badge> : <Badge>未配置</Badge>}</span>}
          actions={<a className="text-xs text-accent inline-flex items-center gap-1" href="https://www.google.com/recaptcha/admin/create" target="_blank" rel="noreferrer">获取密钥 <ExternalLink className="size-3" /></a>}
        >
          <div className="space-y-4">
            <p className="text-[13px] text-muted">
              在 reCAPTCHA 管理后台（现已归入 Google Cloud）创建密钥，类型选 v2「进行人机身份验证」复选框或 v3，并添加你的域名。已迁移到 Google Cloud 项目的旧密钥同样可用。
            </p>
            <Field label="版本">
              <Segmented<"v2" | "v3">
                value={c.recaptcha.version}
                onChange={(v) => upR({ version: v })}
                options={[
                  { value: "v2", label: "v2 复选框" },
                  { value: "v3", label: "v3 无感评分" },
                ]}
              />
            </Field>
            <Field label="Site Key（网站密钥）">
              <Input className="font-mono" value={c.recaptcha.site_key} onChange={(e) => upR({ site_key: e.target.value })} placeholder="6Lc..." />
            </Field>
            <Field label="Secret Key（通信密钥）" hint={c.recaptcha.secret === MASK ? "已保存，保持「••••••」表示不修改" : "加密保存，保存后不再显示"}>
              <Input className="font-mono" type="password" autoComplete="off" value={c.recaptcha.secret} onChange={(e) => upR({ secret: e.target.value })} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="加载域名" hint="国内访客请用 recaptcha.net">
                <Select value={c.recaptcha.domain} onChange={(e) => upR({ domain: e.target.value })}>
                  <option value="www.recaptcha.net">www.recaptcha.net</option>
                  <option value="www.google.com">www.google.com</option>
                </Select>
              </Field>
              {c.recaptcha.version === "v3" && (
                <Field label="最低分数（0–1）" hint="低于此分数视为机器人，默认 0.5">
                  <Input type="number" step={0.1} min={0.1} max={1} value={c.recaptcha.min_score} onChange={(e) => upR({ min_score: Number(e.target.value) })} />
                </Field>
              )}
            </div>
          </div>
        </Card>
      </div>
      <p className="text-xs text-muted mt-4 max-w-5xl">
        第三方服务无法访问时验证会失败（访客看到重新验证），网关不会因此放行。选择的服务未配置密钥时，站点自动使用内置验证。
      </p>
    </>
  );
}
