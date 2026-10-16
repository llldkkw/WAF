// Command waf is a self-hosted web application firewall gateway with a web
// management panel.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/term"

	"github.com/llldkkw/waf/internal/actions"
	"github.com/llldkkw/waf/internal/admin"
	"github.com/llldkkw/waf/internal/config"
	"github.com/llldkkw/waf/internal/events"
	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/proxy"
	"github.com/llldkkw/waf/internal/report"
	"github.com/llldkkw/waf/internal/secure"
	"github.com/llldkkw/waf/internal/store"
	"github.com/llldkkw/waf/web"
)

var version = "dev"

const usage = `WAF 安全网关 %s

用法:
  waf serve      [-c waf.yaml]                         启动网关和管理面板
  waf user add   [-c waf.yaml] -name NAME [-role admin|viewer]
                                                       创建用户（交互输入密码，输出两步验证二维码）
  waf user reset [-c waf.yaml] -name NAME              重置密码和两步验证
  waf ip list    [-c waf.yaml]                         列出 IP 规则
  waf ip allow   [-c waf.yaml] [-note TEXT] IP/CIDR    加入白名单（应急恢复访问）
  waf ip deny    [-c waf.yaml] [-note TEXT] [-minutes N] IP/CIDR
  waf ip del     [-c waf.yaml] IP/CIDR                 删除该地址的所有规则
  waf version
`

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "user":
		err = cmdUser(os.Args[2:])
	case "ip":
		err = cmdIP(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("WAF_CONFIG")
	if def == "" {
		def = "waf.yaml"
	}
	return fs.String("c", def, "配置文件路径")
}

func loadConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		slog.Warn("config file not found, using defaults", "path", path)
		path = ""
	}
	return config.Load(path)
}

func openAll(cfgPath string) (*config.Config, *store.Store, *secure.Box, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}
	box, err := secure.LoadOrCreateKey(filepath.Join(cfg.DataDir, "master.key"))
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, st, box, nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := configFlag(fs)
	_ = fs.Parse(args)

	cfg, st, box, err := openAll(*cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if n, _ := st.CountUsers(ctx); n == 0 {
		slog.Warn("no users yet: create the first admin with `waf user add -name admin`")
	}

	geo, err := events.OpenGeo(cfg.GeoIPDB)
	if err != nil {
		return fmt.Errorf("geoip: %w", err)
	}
	nt := notify.New(st, box)
	if err := nt.Reload(ctx); err != nil {
		return err
	}
	hub := events.NewHub()
	rec := events.NewRecorder(st, hub, nt, geo)
	px := proxy.New(cfg, st, rec, nt, box)
	links := actions.NewSigner(box, cfg.Admin.PublicURL)
	rec.SetLinks(links)
	px.SetLinks(links)
	nt.SetLocation(cfg.Location())
	rep := report.New(st, nt, geo, cfg.Location())
	adm := admin.New(admin.Deps{Config: cfg, Store: st, Box: box, Notifier: nt, Hub: hub, Proxy: px, Web: web.FS(), Version: version, Reporter: rep, Geo: geo})

	go nt.Run(ctx)
	go rec.Run(ctx)
	go px.Watch(ctx)
	go rep.Run(ctx)

	errc := make(chan error, 2)
	go func() { errc <- px.Serve(ctx) }()
	go func() { errc <- adm.Serve(ctx) }()

	nt.Notify(notify.Message{Level: notify.Info, Kind: "system", Title: "WAF 网关已启动", Body: "版本 " + version + "，启动时间 " + time.Now().Format("2006-01-02 15:04:05")})

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-errc:
		if err != nil {
			stop()
			return err
		}
	}
	// Give recorder a moment to flush.
	time.Sleep(500 * time.Millisecond)
	return nil
}

func cmdUser(args []string) error {
	if len(args) < 1 {
		return errors.New("用法: waf user add|reset -name NAME")
	}
	sub := args[0]
	fs := flag.NewFlagSet("user "+sub, flag.ExitOnError)
	cfgPath := configFlag(fs)
	name := fs.String("name", "", "用户名")
	role := fs.String("role", store.RoleAdmin, "角色: admin 或 viewer")
	_ = fs.Parse(args[1:])
	if *name == "" {
		return errors.New("需要 -name")
	}
	_, st, box, err := openAll(*cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	pw, err := readPassword()
	if err != nil {
		return err
	}
	hash, err := admin.HashPassword(pw)
	if err != nil {
		return err
	}
	key, err := admin.NewTOTP(*name)
	if err != nil {
		return err
	}
	enc, err := box.Seal([]byte(key.Secret()))
	if err != nil {
		return err
	}

	switch sub {
	case "add":
		if *role != store.RoleAdmin && *role != store.RoleViewer {
			return errors.New("角色必须是 admin 或 viewer")
		}
		u := &store.User{Username: *name, PasswordHash: hash, TOTPEnc: enc, Role: *role}
		if err := st.CreateUser(ctx, u); err != nil {
			return err
		}
	case "reset":
		u, err := st.UserByName(ctx, *name)
		if err != nil {
			return fmt.Errorf("用户 %s 不存在", *name)
		}
		if err := st.UpdateUserPassword(ctx, u.ID, hash); err != nil {
			return err
		}
		if err := st.UpdateUserTOTP(ctx, u.ID, enc); err != nil {
			return err
		}
		_ = st.DeleteUserSessions(ctx, u.ID)
	default:
		return fmt.Errorf("未知子命令 %q", sub)
	}
	_ = st.Audit(ctx, store.AuditEntry{Username: "cli", IP: "local", Action: "user_" + sub, Target: *name})

	fmt.Printf("\n用户 %s 已保存。请用 Google Authenticator / Microsoft Authenticator / 1Password 等扫描二维码：\n\n", *name)
	qrterminal.GenerateHalfBlock(key.URL(), qrterminal.L, os.Stdout)
	fmt.Printf("\n无法扫码时手动输入密钥: %s\n此密钥只显示一次，请妥善保存。\n", key.Secret())
	return nil
}

func readPassword() (string, error) {
	if env := os.Getenv("WAF_PASSWORD"); env != "" {
		return env, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	fmt.Print("输入密码（至少 10 位）: ")
	a, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("再次输入密码: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("两次输入的密码不一致")
	}
	return string(a), nil
}

func cmdIP(args []string) error {
	if len(args) < 1 {
		return errors.New("用法: waf ip list|allow|deny|del")
	}
	sub := args[0]
	fs := flag.NewFlagSet("ip "+sub, flag.ExitOnError)
	cfgPath := configFlag(fs)
	note := fs.String("note", "", "备注")
	minutes := fs.Int("minutes", 0, "有效分钟数（0 为永久）")
	_ = fs.Parse(args[1:])
	_, st, _, err := openAll(*cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	if sub == "list" {
		rules, err := st.ListIPRules(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\t地址\t动作\t站点\t来源\t过期\t备注")
		for _, r := range rules {
			exp := "永久"
			if r.ExpiresAt > 0 {
				exp = time.Unix(r.ExpiresAt, 0).Format("01-02 15:04")
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\t%s\t%s\n", r.ID, r.CIDR, r.Action, r.SiteID, r.Source, exp, r.Note)
		}
		return tw.Flush()
	}
	if fs.NArg() != 1 {
		return errors.New("需要一个 IP 或网段参数")
	}
	p, err := config.ParsePrefixOrAddr(fs.Arg(0))
	if err != nil {
		return err
	}
	switch sub {
	case "allow", "deny":
		r := &store.IPRule{CIDR: p.String(), Action: sub, Note: *note, Source: "cli", CreatedBy: "cli"}
		if *minutes > 0 {
			r.ExpiresAt = time.Now().Add(time.Duration(*minutes) * time.Minute).Unix()
		}
		if err := r.Normalize(); err != nil {
			return err
		}
		if err := st.AddIPRule(ctx, r); err != nil {
			return err
		}
		fmt.Printf("已添加 %s %s（运行中的网关会在 2 秒内生效）\n", sub, r.CIDR)
	case "del":
		n, err := st.DeleteIPRulesByCIDR(ctx, p.String())
		if err != nil {
			return err
		}
		fmt.Printf("已删除 %d 条规则\n", n)
	default:
		return fmt.Errorf("未知子命令 %q", sub)
	}
	_ = st.Audit(ctx, store.AuditEntry{Username: "cli", IP: "local", Action: "ip_" + sub, Target: p.String(), Detail: *note})
	return nil
}
