package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/secure"
)

// sendMail delivers a message over SMTP. It works with standard providers
// and with Oracle Cloud (OCI) Email Delivery, which expects:
//   - host smtp.email.<region>.oci.oraclecloud.com, port 587 with STARTTLS
//     (or 25 with STARTTLS)
//   - SMTP credentials generated for an IAM user (username is an OCID string)
//   - a From address registered as an Approved Sender
//
// TLS is mandatory unless security=none is set explicitly.
func sendMail(ctx context.Context, cfg map[string]string, m Message) error {
	host, port := strings.TrimSpace(cfg["host"]), strings.TrimSpace(cfg["port"])
	if port == "" {
		port = "587"
	}
	security := strings.ToLower(strings.TrimSpace(cfg["security"]))
	if security == "" {
		security = "starttls"
		if port == "465" {
			security = "ssl"
		}
	}
	from, err := mail.ParseAddress(cfg["from"])
	if err != nil {
		return fmt.Errorf("发件人格式无效: %v", err)
	}
	var to []string
	for _, t := range strings.Split(cfg["to"], ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		a, err := mail.ParseAddress(t)
		if err != nil {
			return fmt.Errorf("收件人格式无效: %q", t)
		}
		to = append(to, a.Address)
	}
	if len(to) == 0 {
		return errors.New("没有收件人")
	}
	msg := buildMail(from, to, m)

	d := net.Dialer{Timeout: 10 * time.Second}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	addr := net.JoinHostPort(host, port)
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	if security == "ssl" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: tlsCfg}).DialContext(dctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(dctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(heloName(from.Address)); err != nil {
		return err
	}
	switch security {
	case "starttls":
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("服务器不支持 STARTTLS（如确需明文，请把加密方式设为 none）")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	case "ssl", "none":
	default:
		return fmt.Errorf("加密方式无效: %q", security)
	}
	if user := cfg["username"]; user != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("服务器不支持 SMTP 认证")
		}
		if err := c.Auth(plainAuth{user: user, pass: cfg["password"], tlsDone: security != "none"}); err != nil {
			return fmt.Errorf("SMTP 认证失败: %v", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// plainAuth is smtp.PlainAuth without its host check, which rejects
// connections the server name differs from (some relays) while still
// refusing to send credentials over plaintext.
type plainAuth struct {
	user, pass string
	tlsDone    bool
}

func (a plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !a.tlsDone {
		return "", nil, errors.New("拒绝在未加密连接上发送密码")
	}
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a plainAuth) Next([]byte, bool) ([]byte, error) { return nil, nil }

func heloName(from string) string {
	if i := strings.LastIndexByte(from, '@'); i >= 0 {
		return from[i+1:]
	}
	return "localhost"
}

// buildMail renders a multipart/alternative message (plain text + HTML) with
// the headers strict relays require (Date, Message-ID).
func buildMail(from *mail.Address, to []string, m Message) []byte {
	boundary := "waf-" + secure.Token(12)
	subject := fmt.Sprintf("[WAF][%s] %s", m.Level.Label(), m.Title)
	domain := heloName(from.Address)

	var plain strings.Builder
	plain.WriteString(m.Body)
	for _, a := range m.Actions {
		plain.WriteString("\n\n" + a.Label + ": " + a.URL)
	}

	var hb strings.Builder
	color := map[Level]string{Critical: "#dc2626", Warning: "#d97706", Info: "#0891b2"}[m.Level]
	hb.WriteString(`<!doctype html><html><body style="margin:0;padding:24px;background:#f5f7fa;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;color:#0f172a">`)
	hb.WriteString(`<div style="max-width:600px;margin:0 auto;background:#fff;border:1px solid #e3e8ef;border-radius:12px;overflow:hidden">`)
	fmt.Fprintf(&hb, `<div style="padding:16px 20px;border-top:4px solid %s"><div style="font-size:12px;color:%s;font-weight:600">%s %s</div><h2 style="margin:6px 0 0;font-size:18px">%s</h2></div>`,
		color, color, m.Level.Emoji(), m.Level.Label(), html.EscapeString(m.Title))
	fmt.Fprintf(&hb, `<pre style="margin:0;padding:0 20px 16px;font:14px/1.7 -apple-system,'PingFang SC','Microsoft YaHei',sans-serif;white-space:pre-wrap">%s</pre>`, html.EscapeString(m.Body))
	if len(m.Actions) > 0 {
		hb.WriteString(`<div style="padding:0 20px 20px">`)
		for _, a := range m.Actions {
			bg := "#0891b2"
			if a.Danger {
				bg = "#dc2626"
			}
			fmt.Fprintf(&hb, `<a href="%s" style="display:inline-block;margin:0 8px 8px 0;padding:8px 14px;border-radius:8px;background:%s;color:#fff;text-decoration:none;font-size:14px">%s</a>`,
				html.EscapeString(a.URL), bg, html.EscapeString(a.Label))
		}
		hb.WriteString(`<div style="font-size:12px;color:#64748b">链接需在 VPN 内打开，并登录控制台确认后执行。</div></div>`)
	}
	hb.WriteString(`<div style="padding:12px 20px;background:#f8fafc;font-size:12px;color:#64748b">WAF Gateway · ` + time.Now().Format("2006-01-02 15:04:05") + `</div></div></body></html>`)

	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from.String())
	h("To", strings.Join(to, ", "))
	h("Subject", mime.BEncoding.Encode("UTF-8", subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", "<"+secure.Token(16)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ct, body string) {
		b.WriteString("--" + boundary + "\r\nContent-Type: " + ct + "; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
		enc := base64.StdEncoding.EncodeToString([]byte(body))
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
	}
	part("text/plain", plain.String())
	part("text/html", hb.String())
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}
