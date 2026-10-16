package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ChannelTypes describes each supported channel and its config fields, so
// the UI can render forms. Fields marked secret are masked when read back.
var ChannelTypes = []ChannelType{
	{Type: "telegram", Label: "Telegram", Fields: []Field{
		{Key: "bot_token", Label: "Bot Token", Secret: true, Required: true},
		{Key: "chat_id", Label: "Chat ID", Required: true},
	}},
	{Type: "wecom", Label: "企业微信机器人", Fields: []Field{
		{Key: "webhook", Label: "Webhook 地址", Secret: true, Required: true},
	}},
	{Type: "dingtalk", Label: "钉钉机器人", Fields: []Field{
		{Key: "webhook", Label: "Webhook 地址", Secret: true, Required: true},
		{Key: "secret", Label: "加签密钥 (SEC...)", Secret: true},
	}},
	{Type: "feishu", Label: "飞书机器人", Fields: []Field{
		{Key: "webhook", Label: "Webhook 地址", Secret: true, Required: true},
		{Key: "secret", Label: "签名校验密钥", Secret: true},
	}},
	{Type: "bark", Label: "Bark (iOS)", Fields: []Field{
		{Key: "server", Label: "服务器", Placeholder: "https://api.day.app"},
		{Key: "key", Label: "Device Key", Secret: true, Required: true},
	}},
	{Type: "email", Label: "邮件 (SMTP)", Fields: []Field{
		{Key: "host", Label: "SMTP 主机", Required: true},
		{Key: "port", Label: "端口", Placeholder: "465", Required: true},
		{Key: "username", Label: "用户名"},
		{Key: "password", Label: "密码", Secret: true},
		{Key: "from", Label: "发件人", Required: true},
		{Key: "to", Label: "收件人 (逗号分隔)", Required: true},
	}},
	{Type: "webhook", Label: "通用 Webhook", Fields: []Field{
		{Key: "url", Label: "URL", Secret: true, Required: true},
		{Key: "secret", Label: "HMAC 签名密钥 (X-WAF-Signature)", Secret: true},
	}},
}

type ChannelType struct {
	Type   string  `json:"type"`
	Label  string  `json:"label"`
	Fields []Field `json:"fields"`
}

type Field struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
}

func channelType(t string) *ChannelType {
	for i := range ChannelTypes {
		if ChannelTypes[i].Type == t {
			return &ChannelTypes[i]
		}
	}
	return nil
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func send(ctx context.Context, typ string, cfg map[string]string, m Message) error {
	switch typ {
	case "telegram":
		text := fmt.Sprintf("<b>%s %s</b>\n%s", m.Level.Emoji(), htmlEscape(m.Title), htmlEscape(m.Body))
		return postJSON(ctx, "https://api.telegram.org/bot"+cfg["bot_token"]+"/sendMessage", map[string]any{
			"chat_id": cfg["chat_id"], "text": text, "parse_mode": "HTML", "disable_web_page_preview": true,
		}, nil)
	case "wecom":
		return postJSON(ctx, cfg["webhook"], map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"content": fmt.Sprintf("**%s %s**\n%s", m.Level.Emoji(), m.Title, m.Body)},
		}, checkErrcode)
	case "dingtalk":
		u := cfg["webhook"]
		if sec := cfg["secret"]; sec != "" {
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			mac := hmac.New(sha256.New, []byte(sec))
			mac.Write([]byte(ts + "\n" + sec))
			u += "&timestamp=" + ts + "&sign=" + url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		}
		return postJSON(ctx, u, map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"title": m.Title, "text": fmt.Sprintf("### %s %s\n%s", m.Level.Emoji(), m.Title, strings.ReplaceAll(m.Body, "\n", "\n\n"))},
		}, checkErrcode)
	case "feishu":
		body := map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": fmt.Sprintf("%s %s\n%s", m.Level.Emoji(), m.Title, m.Body)},
		}
		if sec := cfg["secret"]; sec != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			mac := hmac.New(sha256.New, []byte(ts+"\n"+sec))
			body["timestamp"] = ts
			body["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
		}
		return postJSON(ctx, cfg["webhook"], body, checkFeishu)
	case "bark":
		server := strings.TrimRight(cfg["server"], "/")
		if server == "" {
			server = "https://api.day.app"
		}
		body := map[string]any{"device_key": cfg["key"], "title": m.Title, "body": m.Body, "group": "WAF"}
		if m.Level == Critical {
			body["level"] = "timeSensitive"
		}
		return postJSON(ctx, server+"/push", body, nil)
	case "webhook":
		return postWebhook(ctx, cfg["url"], cfg["secret"], m)
	case "email":
		return sendMail(cfg, m)
	}
	return fmt.Errorf("unknown channel type %q", typ)
}

func postJSON(ctx context.Context, u string, body any, check func([]byte) error) error {
	b, _ := json.Marshal(body)
	return doPost(ctx, u, b, nil, check)
}

func postWebhook(ctx context.Context, u, secret string, m Message) error {
	b, _ := json.Marshal(map[string]any{
		"level": m.Level.String(), "kind": m.Kind, "title": m.Title, "body": m.Body, "ts": time.Now().Unix(),
	})
	h := map[string]string{}
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(b)
		h["X-WAF-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	return doPost(ctx, u, b, h, nil)
}

func doPost(ctx context.Context, u string, body []byte, headers map[string]string, check func([]byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Do not leak tokens embedded in the URL into logs.
		if ue, ok := err.(*url.Error); ok {
			return fmt.Errorf("request failed: %v", ue.Err)
		}
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(rb), 200))
	}
	if check != nil {
		return check(rb)
	}
	return nil
}

func checkErrcode(b []byte) error {
	var r struct {
		Errcode int    `json:"errcode"`
		Errmsg  string `json:"errmsg"`
	}
	if json.Unmarshal(b, &r) == nil && r.Errcode != 0 {
		return fmt.Errorf("errcode %d: %s", r.Errcode, r.Errmsg)
	}
	return nil
}

func checkFeishu(b []byte) error {
	var r struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(b, &r) == nil && r.Code != 0 {
		return fmt.Errorf("code %d: %s", r.Code, r.Msg)
	}
	return nil
}

func sendMail(cfg map[string]string, m Message) error {
	host, port := cfg["host"], cfg["port"]
	if port == "" {
		port = "465"
	}
	to := []string{}
	for _, t := range strings.Split(cfg["to"], ",") {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	if len(to) == 0 {
		return fmt.Errorf("no recipients")
	}
	for _, v := range append([]string{cfg["from"]}, to...) {
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("invalid address")
		}
	}
	subject := mimeHeader(fmt.Sprintf("[WAF][%s] %s", m.Level.Label(), m.Title))
	msg := "From: " + cfg["from"] + "\r\nTo: " + strings.Join(to, ", ") + "\r\nSubject: " + subject +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(m.Body)) + "\r\n"

	addr := net.JoinHostPort(host, port)
	var auth smtp.Auth
	if cfg["username"] != "" {
		auth = smtp.PlainAuth("", cfg["username"], cfg["password"], host)
	}
	if port != "465" {
		// SendMail upgrades with STARTTLS when the server supports it.
		return smtp.SendMail(addr, auth, cfg["from"], to, []byte(msg))
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(cfg["from"]); err != nil {
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
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func mimeHeader(s string) string {
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
