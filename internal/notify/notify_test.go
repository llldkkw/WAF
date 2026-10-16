package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/mail"
	"strings"
	"testing"
)

var msg = Message{Level: Critical, Title: "后端宕机", Body: "第一行\n第二行 <b>", Actions: []Action{{Label: "解除封禁", URL: "https://10.8.0.1:9443/actions?t=x", Danger: true}}}

func TestSlackPayload(t *testing.T) {
	b, _ := json.Marshal(slackPayload(msg))
	s := string(b)
	for _, want := range []string{`"type":"header"`, `"type":"actions"`, `"style":"danger"`} {
		if !strings.Contains(s, want) {
			t.Errorf("slack payload missing %s: %s", want, s)
		}
	}
	section := slackPayload(msg)["blocks"].([]map[string]any)[1]["text"].(map[string]any)["text"]
	if section != "第一行\n第二行 &lt;b&gt;" {
		t.Errorf("mrkdwn not escaped: %q", section)
	}
}

func TestTeamsPayload(t *testing.T) {
	p := teamsPayload(msg)
	att := p["attachments"].([]map[string]any)[0]
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatal("wrong content type")
	}
	card := att["content"].(map[string]any)
	if card["type"] != "AdaptiveCard" || len(card["actions"].([]map[string]any)) != 1 {
		t.Fatalf("card: %+v", card)
	}
}

func TestBuildMail(t *testing.T) {
	from, _ := mail.ParseAddress("WAF 告警 <alerts@example.com>")
	raw := string(buildMail(from, []string{"ops@example.com"}, msg))
	for _, want := range []string{"Date: ", "Message-ID: <", "@example.com>", "multipart/alternative", "text/plain", "text/html", "Subject: =?UTF-8?b?"} {
		if !strings.Contains(raw, want) {
			t.Errorf("mail missing %q", want)
		}
	}
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if addr, _ := m.Header.AddressList("From"); len(addr) != 1 || addr[0].Address != "alerts@example.com" {
		t.Errorf("from header: %v", m.Header.Get("From"))
	}
}

// A minimal SMTP server: checks that credentials are never sent without TLS
// and that a plaintext (security=none) delivery without auth works.
func fakeSMTP(t *testing.T, starttls bool) (addr string, got chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { c.Write([]byte(s + "\r\n")) }
		w("220 fake")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				got <- data.String()
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					w("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				ext := "250-fake\r\n250-AUTH PLAIN\r\n250 8BITMIME"
				if starttls {
					ext = "250-fake\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 8BITMIME"
				}
				w(ext)
			case strings.HasPrefix(cmd, "AUTH"):
				w("235 ok")
			case cmd == "DATA":
				inData = true
				w("354 go")
			case cmd == "QUIT":
				w("221 bye")
				got <- data.String()
				return
			default:
				w("250 ok")
			}
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), got
}

func TestSendMailPlain(t *testing.T) {
	addr, got := fakeSMTP(t, false)
	host, port, _ := net.SplitHostPort(addr)
	cfg := map[string]string{"host": host, "port": port, "security": "none", "from": "a@example.com", "to": "b@example.com"}
	if err := sendMail(context.Background(), cfg, msg); err != nil {
		t.Fatal(err)
	}
	if body := <-got; !strings.Contains(body, "Subject:") {
		t.Fatalf("no message delivered: %q", body)
	}
}

func TestSendMailRequiresTLS(t *testing.T) {
	addr, _ := fakeSMTP(t, false)
	host, port, _ := net.SplitHostPort(addr)
	// Default security for a non-465 port is STARTTLS; a server without it must be refused.
	cfg := map[string]string{"host": host, "port": port, "username": "u", "password": "p", "from": "a@example.com", "to": "b@example.com"}
	if err := sendMail(context.Background(), cfg, msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected STARTTLS error, got %v", err)
	}
	addr2, _ := fakeSMTP(t, false)
	host2, port2, _ := net.SplitHostPort(addr2)
	cfg2 := map[string]string{"host": host2, "port": port2, "security": "none", "username": "u", "password": "p", "from": "a@example.com", "to": "b@example.com"}
	if err := sendMail(context.Background(), cfg2, msg); err == nil {
		t.Fatal("password sent over plaintext")
	}
}
