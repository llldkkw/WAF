package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	{Type: "slack", Label: "Slack", Fields: []Field{
		{Key: "webhook", Label: "Incoming Webhook URL", Placeholder: "https://hooks.slack.com/services/...", Secret: true, Required: true},
	}},
	{Type: "teams", Label: "Microsoft Teams", Fields: []Field{
		{Key: "webhook", Label: "Workflows Webhook URL", Placeholder: "Teams 工作流「收到 Webhook 请求时发布到频道」生成的地址", Secret: true, Required: true},
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
		{Key: "host", Label: "SMTP 主机", Placeholder: "smtp.email.ap-tokyo-1.oci.oraclecloud.com", Required: true},
		{Key: "port", Label: "端口", Placeholder: "587", Required: true},
		{Key: "security", Label: "加密方式", Options: []Option{{"", "自动（465 用 SSL，其它用 STARTTLS）"}, {"starttls", "STARTTLS（Oracle / 587）"}, {"ssl", "SSL/TLS（465）"}, {"none", "不加密（不推荐）"}}},
		{Key: "username", Label: "用户名", Placeholder: "Oracle：SMTP 凭据的用户名（ocid1.user...）"},
		{Key: "password", Label: "密码", Secret: true},
		{Key: "from", Label: "发件人", Placeholder: "WAF <alerts@example.com>（Oracle 需为已批准发件人）", Required: true},
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
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Placeholder string   `json:"placeholder,omitempty"`
	Secret      bool     `json:"secret"`
	Required    bool     `json:"required"`
	Options     []Option `json:"options,omitempty"`
}

type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
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
		for _, a := range m.Actions {
			text += fmt.Sprintf("\n👉 <a href=\"%s\">%s</a>", htmlEscape(a.URL), htmlEscape(a.Label))
		}
		return postJSON(ctx, "https://api.telegram.org/bot"+cfg["bot_token"]+"/sendMessage", map[string]any{
			"chat_id": cfg["chat_id"], "text": text, "parse_mode": "HTML", "disable_web_page_preview": true,
		}, nil)
	case "slack":
		return postJSON(ctx, cfg["webhook"], slackPayload(m), checkSlack)
	case "teams":
		return postJSON(ctx, cfg["webhook"], teamsPayload(m), nil)
	case "wecom":
		return postJSON(ctx, cfg["webhook"], map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"content": fmt.Sprintf("**%s %s**\n%s%s", m.Level.Emoji(), m.Title, m.Body, mdLinks(m.Actions, "\n"))},
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
			"msgtype": "markdown",
			"markdown": map[string]string{"title": m.Title, "text": fmt.Sprintf("### %s %s\n%s%s", m.Level.Emoji(), m.Title,
				strings.ReplaceAll(m.Body, "\n", "\n\n"), mdLinks(m.Actions, "\n\n"))},
		}, checkErrcode)
	case "feishu":
		text := fmt.Sprintf("%s %s\n%s", m.Level.Emoji(), m.Title, m.Body)
		for _, a := range m.Actions {
			text += "\n" + a.Label + ": " + a.URL
		}
		body := map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
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
		if len(m.Actions) > 0 {
			body["url"] = m.Actions[0].URL // tapping the notification opens it
		}
		return postJSON(ctx, server+"/push", body, nil)
	case "webhook":
		return postWebhook(ctx, cfg["url"], cfg["secret"], m)
	case "email":
		return sendMail(ctx, cfg, m)
	}
	return fmt.Errorf("unknown channel type %q", typ)
}

func mdLinks(as []Action, sep string) string {
	var b strings.Builder
	for _, a := range as {
		b.WriteString(sep + "[" + a.Label + "](" + a.URL + ")")
	}
	return b.String()
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func slackPayload(m Message) map[string]any {
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(m.Level.Emoji()+" "+m.Title, 150), "emoji": true}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": truncate(slackEscape(m.Body), 2900)}},
	}
	if len(m.Actions) > 0 {
		var els []map[string]any
		for i, a := range m.Actions {
			b := map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": a.Label}, "url": a.URL, "action_id": fmt.Sprintf("waf_%d", i)}
			if a.Danger {
				b["style"] = "danger"
			}
			els = append(els, b)
		}
		blocks = append(blocks, map[string]any{"type": "actions", "elements": els})
	}
	return map[string]any{"text": m.Level.Emoji() + " " + m.Title, "blocks": blocks}
}

// teamsPayload builds an Adaptive Card, the format accepted by Teams
// Workflows ("When a Teams webhook request is received") webhooks.
func teamsPayload(m Message) map[string]any {
	color := map[Level]string{Critical: "Attention", Warning: "Warning", Info: "Accent"}[m.Level]
	body := []map[string]any{
		{"type": "TextBlock", "text": m.Level.Emoji() + " " + m.Title, "weight": "Bolder", "size": "Medium", "color": color, "wrap": true},
	}
	for _, line := range strings.Split(m.Body, "\n") {
		body = append(body, map[string]any{"type": "TextBlock", "text": line, "wrap": true, "spacing": "None"})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
	}
	if len(m.Actions) > 0 {
		var acts []map[string]any
		for _, a := range m.Actions {
			act := map[string]any{"type": "Action.OpenUrl", "title": a.Label, "url": a.URL}
			if a.Danger {
				act["style"] = "destructive"
			}
			acts = append(acts, act)
		}
		card["actions"] = acts
	}
	return map[string]any{
		"type":        "message",
		"attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	}
}

func postJSON(ctx context.Context, u string, body any, check func([]byte) error) error {
	b, _ := json.Marshal(body)
	return doPost(ctx, u, b, nil, check)
}

func postWebhook(ctx context.Context, u, secret string, m Message) error {
	b, _ := json.Marshal(map[string]any{
		"level": m.Level.String(), "kind": m.Kind, "title": m.Title, "body": m.Body, "actions": m.Actions, "ts": time.Now().Unix(),
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

func checkSlack(b []byte) error {
	if s := strings.TrimSpace(string(b)); s != "" && s != "ok" {
		return fmt.Errorf("slack: %s", truncate(s, 200))
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

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
