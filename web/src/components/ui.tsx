import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, CheckCircle2, Info, Loader2, X } from "lucide-react";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

// --- Button ---

type BtnVariant = "primary" | "secondary" | "ghost" | "danger";
const btnStyles: Record<BtnVariant, string> = {
  primary: "bg-accent text-accent-fg hover:brightness-110 shadow-sm",
  secondary: "bg-surface border border-border hover:bg-surface-2",
  ghost: "hover:bg-surface-2 text-muted hover:text-fg",
  danger: "bg-danger text-white hover:brightness-110",
};

export function Button({
  variant = "secondary",
  size = "md",
  loading,
  icon,
  className,
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: BtnVariant;
  size?: "sm" | "md";
  loading?: boolean;
  icon?: ReactNode;
}) {
  return (
    <button
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-all disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent whitespace-nowrap",
        size === "sm" ? "h-8 px-2.5 text-[13px]" : "h-9 px-3.5 text-sm",
        btnStyles[variant],
        className,
      )}
      disabled={loading || rest.disabled}
      {...rest}
    >
      {loading ? <Loader2 className="size-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}

// --- Card ---

export function Card({ title, actions, children, className, bodyClass }: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
}) {
  return (
    <section className={cx("bg-surface border border-border rounded-xl min-w-0", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 px-4 pt-3.5 pb-1">
          <h3 className="text-[13px] font-semibold text-muted">{title}</h3>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={cx("p-4", bodyClass)}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, desc, actions }: { title: string; desc?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {desc && <p className="text-muted text-[13px] mt-1">{desc}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

// --- Badge ---

export type Tone = "accent" | "danger" | "warn" | "ok" | "info" | "muted";
const toneStyles: Record<Tone, string> = {
  accent: "bg-accent-soft text-accent",
  danger: "bg-danger-soft text-danger",
  warn: "bg-warn-soft text-warn",
  ok: "bg-ok-soft text-ok",
  info: "bg-info-soft text-info",
  muted: "bg-surface-2 text-muted",
};

export function Badge({ tone = "muted", children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap", toneStyles[tone], className)}>
      {children}
    </span>
  );
}

export function Dot({ tone }: { tone: Tone }) {
  const c = { accent: "bg-accent", danger: "bg-danger", warn: "bg-warn", ok: "bg-ok", info: "bg-info", muted: "bg-muted" }[tone];
  return <span className={cx("inline-block size-2 rounded-full", c)} />;
}

// --- Form controls ---

const inputCls =
  "h-9 rounded-lg border border-border bg-surface px-3 text-sm placeholder:text-muted/70 focus:outline-none focus:ring-2 focus:ring-accent/40 focus:border-accent transition disabled:opacity-60";

// Default to full width unless the caller sets a width (w-* / max-w-*).
function widthOf(className?: string) {
  return className && /(^|\s)w-/.test(className) ? "" : "w-full";
}

export function Input({ className, ...rest }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(inputCls, widthOf(className), className)} {...rest} />;
}

export function Textarea({ className, ...rest }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(inputCls, "w-full h-auto py-2 min-h-20 font-mono text-[13px]", className)} {...rest} />;
}

export function Select({ className, children, ...rest }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cx(inputCls, widthOf(className), "pr-8 appearance-none bg-[length:16px] bg-[right_8px_center] bg-no-repeat", className)}
      style={{ backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")" }}
      {...rest}>
      {children}
    </select>
  );
}

export function Field({ label, hint, children, className }: { label: ReactNode; hint?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cx("flex flex-col gap-1.5", className)}>
      <span className="text-[13px] font-medium">{label}</span>
      {children}
      {hint && <p className="text-xs text-muted">{hint}</p>}
    </div>
  );
}

export function Switch({ checked, onChange, label, desc, disabled }: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: ReactNode;
  desc?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <label className={cx("flex items-start gap-3 cursor-pointer select-none", disabled && "opacity-50 pointer-events-none")}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cx(
          "relative mt-0.5 h-5 w-9 shrink-0 rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-accent",
          checked ? "bg-accent" : "bg-border",
        )}
      >
        <span className={cx("absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow transition-transform", checked && "translate-x-4")} />
      </button>
      {(label || desc) && (
        <span className="flex flex-col">
          {label && <span className="text-sm font-medium">{label}</span>}
          {desc && <span className="text-xs text-muted">{desc}</span>}
        </span>
      )}
    </label>
  );
}

export function Segmented<T extends string>({ value, onChange, options }: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: ReactNode }[];
}) {
  return (
    <div className="inline-flex rounded-lg bg-surface-2 p-0.5 border border-border">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={cx(
            "px-3 h-7 text-[13px] rounded-md transition",
            value === o.value ? "bg-surface shadow-sm text-fg font-medium" : "text-muted hover:text-fg",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Editable list of strings, one per line. */
export function LinesInput({ value, onChange, placeholder, rows = 3 }: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  rows?: number;
}) {
  const [text, setText] = useState(value.join("\n"));
  useEffect(() => {
    if (text.split("\n").map((s) => s.trim()).filter(Boolean).join("\n") !== value.join("\n")) setText(value.join("\n"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return (
    <Textarea
      rows={rows}
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        setText(e.target.value);
        onChange(e.target.value.split("\n").map((s) => s.trim()).filter(Boolean));
      }}
    />
  );
}

// --- Modal / Drawer ---

export function Modal({ open, onClose, title, children, footer, wide }: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEscape(open, onClose);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start sm:items-center justify-center p-4 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50 backdrop-blur-[2px]" onClick={onClose} />
      <div role="dialog" aria-modal className={cx("relative w-full animate-in bg-surface border border-border rounded-2xl shadow-2xl", wide ? "max-w-2xl" : "max-w-md")}>
        <div className="flex items-center justify-between px-5 pt-4">
          <h2 className="text-base font-semibold">{title}</h2>
          <button onClick={onClose} className="text-muted hover:text-fg p-1 -mr-1 rounded-md" aria-label="关闭">
            <X className="size-4" />
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 px-5 pb-4">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

export function Drawer({ open, onClose, title, children, footer }: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(open, onClose);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50">
      <div className="fixed inset-0 bg-black/50 backdrop-blur-[2px]" onClick={onClose} />
      <aside className="fixed right-0 top-0 h-full w-full max-w-2xl bg-surface border-l border-border shadow-2xl flex flex-col animate-in">
        <div className="flex items-center justify-between px-5 h-14 border-b border-border shrink-0">
          <h2 className="text-base font-semibold truncate">{title}</h2>
          <button onClick={onClose} className="text-muted hover:text-fg p-1 rounded-md" aria-label="关闭">
            <X className="size-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-5">{children}</div>
        {footer && <div className="flex justify-end gap-2 px-5 py-3 border-t border-border shrink-0">{footer}</div>}
      </aside>
    </div>,
    document.body,
  );
}

function useEscape(active: boolean, fn: () => void) {
  useEffect(() => {
    if (!active) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && fn();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [active, fn]);
}

// --- Table ---

export function Table({ head, children, empty }: { head: ReactNode[]; children: ReactNode; empty?: boolean }) {
  return (
    <div className="overflow-x-auto -mx-4">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-muted border-b border-border">
            {head.map((h, i) => (
              <th key={i} className="font-medium px-4 py-2 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="[&>tr]:border-b [&>tr]:border-border [&>tr:last-child]:border-0 [&>tr:hover]:bg-surface-2/60">{children}</tbody>
      </table>
      {empty && <Empty />}
    </div>
  );
}

export function Td({ children, className, mono }: { children?: ReactNode; className?: string; mono?: boolean }) {
  return <td className={cx("px-4 py-2.5 align-middle", mono && "font-mono text-[13px]", className)}>{children}</td>;
}

export function Empty({ text = "暂无数据" }: { text?: string }) {
  return <div className="py-12 text-center text-muted text-sm">{text}</div>;
}

export function Spinner() {
  return (
    <div className="flex justify-center py-16 text-muted">
      <Loader2 className="size-5 animate-spin" />
    </div>
  );
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  return (
    <div className="flex items-center justify-between pt-3 text-[13px] text-muted">
      <span>
        共 {total.toLocaleString()} 条 · 第 {page}/{pages} 页
      </span>
      <div className="flex gap-2">
        <Button size="sm" disabled={page <= 1} onClick={() => onChange(offset - limit)}>
          上一页
        </Button>
        <Button size="sm" disabled={page >= pages} onClick={() => onChange(offset + limit)}>
          下一页
        </Button>
      </div>
    </div>
  );
}

// --- Toasts & confirm ---

type Toast = { id: number; tone: "ok" | "danger" | "info"; text: string };
const ToastCtx = createContext<{ toast: (text: string, tone?: Toast["tone"]) => void; confirm: (text: string, opts?: { danger?: boolean; ok?: string }) => Promise<boolean> }>(null!);

export function useToast() {
  return useContext(ToastCtx);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [conf, setConf] = useState<{ text: string; danger?: boolean; ok?: string; resolve: (v: boolean) => void } | null>(null);

  const toast = useCallback((text: string, tone: Toast["tone"] = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, tone, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === "danger" ? 6000 : 3000);
  }, []);
  const confirm = useCallback(
    (text: string, opts: { danger?: boolean; ok?: string } = {}) => new Promise<boolean>((resolve) => setConf({ text, ...opts, resolve })),
    [],
  );
  const close = (v: boolean) => {
    conf?.resolve(v);
    setConf(null);
  };

  return (
    <ToastCtx.Provider value={{ toast, confirm }}>
      {children}
      {createPortal(
        <div className="fixed top-4 right-4 z-[60] flex flex-col gap-2 w-[min(360px,calc(100vw-32px))]">
          {toasts.map((t) => (
            <div key={t.id} className="animate-in flex items-start gap-2.5 bg-surface border border-border rounded-xl shadow-lg px-3.5 py-3 text-sm">
              {t.tone === "ok" ? <CheckCircle2 className="size-4 text-ok mt-0.5 shrink-0" /> : t.tone === "danger" ? <AlertTriangle className="size-4 text-danger mt-0.5 shrink-0" /> : <Info className="size-4 text-info mt-0.5 shrink-0" />}
              <span className="break-words min-w-0">{t.text}</span>
            </div>
          ))}
        </div>,
        document.body,
      )}
      <Modal
        open={!!conf}
        onClose={() => close(false)}
        title="请确认"
        footer={
          <>
            <Button onClick={() => close(false)}>取消</Button>
            <Button variant={conf?.danger ? "danger" : "primary"} onClick={() => close(true)}>
              {conf?.ok ?? "确定"}
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">{conf?.text}</p>
      </Modal>
    </ToastCtx.Provider>
  );
}

/** Runs an async action, showing errors as toasts. */
export function useAction() {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, success?: string): Promise<T | undefined> => {
      setBusy(true);
      try {
        const r = await fn();
        if (success) toast(success);
        return r;
      } catch (e) {
        toast((e as Error).message, "danger");
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [toast],
  );
  return { busy, run };
}
