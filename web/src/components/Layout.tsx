import { useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Bell,
  FileClock,
  FileKey2,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  ScrollText,
  Settings2,
  ShieldCheck,
  ShieldBan,
  Sun,
  UserCog,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { useLive } from "../lib/live";
import { useTheme } from "../lib/theme";
import { cx } from "./ui";

const nav: { to: string; label: string; icon: ReactNode; admin?: boolean }[] = [
  { to: "/", label: "总览", icon: <LayoutDashboard /> },
  { to: "/events", label: "攻击日志", icon: <ScrollText /> },
  { to: "/sites", label: "站点防护", icon: <Globe2 /> },
  { to: "/ip-rules", label: "IP 黑白名单", icon: <ShieldBan /> },
  { to: "/certs", label: "证书管理", icon: <FileKey2 />, admin: true },
  { to: "/notifications", label: "推送通知", icon: <Bell />, admin: true },
  { to: "/users", label: "用户管理", icon: <Users />, admin: true },
  { to: "/audit", label: "操作审计", icon: <FileClock />, admin: true },
  { to: "/settings", label: "系统设置", icon: <Settings2 />, admin: true },
  { to: "/account", label: "账号安全", icon: <UserCog /> },
];

export function Layout() {
  const { user, logout, isAdmin } = useAuth();
  const { dark, toggle } = useTheme();
  const { connected } = useLive();
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  const current = nav.find((n) => (n.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(n.to)));

  const sidebar = (
    <nav className="flex flex-col h-full">
      <div className="flex items-center gap-2.5 px-5 h-16 shrink-0">
        <div className="size-8 rounded-lg bg-gradient-to-br from-cyan-500 to-cyan-700 grid place-items-center shadow-lg shadow-cyan-500/20">
          <ShieldCheck className="size-[18px] text-white" />
        </div>
        <div className="leading-tight">
          <div className="font-semibold tracking-tight">WAF Gateway</div>
          <div className="text-[11px] text-muted">安全网关控制台</div>
        </div>
      </div>
      <div className="flex-1 px-3 py-2 space-y-0.5 overflow-y-auto">
        {nav
          .filter((n) => !n.admin || isAdmin)
          .map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-3 px-3 h-9 rounded-lg text-[13.5px] transition [&>svg]:size-4",
                  isActive ? "bg-accent-soft text-accent font-medium" : "text-muted hover:text-fg hover:bg-surface-2",
                )
              }
            >
              {n.icon}
              {n.label}
            </NavLink>
          ))}
      </div>
      <div className="p-3 border-t border-border">
        <div className="flex items-center gap-2.5 px-2 py-1.5">
          <div className="size-8 rounded-full bg-surface-2 border border-border grid place-items-center text-xs font-semibold uppercase">
            {user?.username.slice(0, 2)}
          </div>
          <div className="flex-1 min-w-0 leading-tight">
            <div className="text-sm font-medium truncate">{user?.username}</div>
            <div className="text-[11px] text-muted">{user?.role === "admin" ? "管理员" : "只读"}</div>
          </div>
          <button onClick={logout} className="p-1.5 rounded-md text-muted hover:text-danger hover:bg-surface-2" title="退出登录" aria-label="退出登录">
            <LogOut className="size-4" />
          </button>
        </div>
      </div>
    </nav>
  );

  return (
    <div className="min-h-full lg:pl-60">
      <aside className="hidden lg:block fixed inset-y-0 left-0 w-60 bg-surface border-r border-border">{sidebar}</aside>
      {open && (
        <div className="lg:hidden fixed inset-0 z-40">
          <div className="absolute inset-0 bg-black/50" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 bg-surface border-r border-border animate-in">
            <button className="absolute right-3 top-5 p-1 text-muted" onClick={() => setOpen(false)} aria-label="关闭菜单">
              <X className="size-4" />
            </button>
            {sidebar}
          </aside>
        </div>
      )}
      <header className="sticky top-0 z-30 h-14 flex items-center gap-3 px-4 sm:px-6 bg-bg/80 backdrop-blur border-b border-border">
        <button className="lg:hidden p-1.5 -ml-1.5 text-muted" onClick={() => setOpen(true)} aria-label="打开菜单">
          <Menu className="size-5" />
        </button>
        <span className="text-sm font-medium lg:hidden">{current?.label}</span>
        <div className="flex-1" />
        <span className={cx("flex items-center gap-1.5 text-xs px-2 h-7 rounded-full border border-border", connected ? "text-ok" : "text-muted")}>
          <span className={cx("size-1.5 rounded-full", connected ? "bg-ok live-dot" : "bg-muted")} />
          {connected ? "实时连接" : "连接中…"}
        </span>
        <button onClick={toggle} className="p-2 rounded-lg text-muted hover:text-fg hover:bg-surface-2" title="切换主题" aria-label="切换主题">
          {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </button>
      </header>
      <main className="px-4 sm:px-6 py-6 max-w-[1440px] mx-auto">
        <Outlet />
      </main>
    </div>
  );
}
