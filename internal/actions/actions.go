// Package actions creates and verifies signed one-click links embedded in
// notifications (ban / allow / unban an IP). A link only opens a confirmation
// page in the admin panel: it executes after the operator logs in (password +
// TOTP) and confirms, and each link works once.
package actions

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/llldkkw/waf/internal/notify"
	"github.com/llldkkw/waf/internal/secure"
)

const (
	Ban   = "ban"
	Allow = "allow"
	Unban = "unban"

	linkTTL = 7 * 24 * time.Hour
)

type Claims struct {
	Action  string `json:"a"`
	IP      string `json:"ip"`
	Minutes int    `json:"m,omitempty"`
	Reason  string `json:"r,omitempty"`
	Exp     int64  `json:"e"`
	Nonce   string `json:"n"`
}

func (c *Claims) Describe() string {
	switch c.Action {
	case Ban:
		switch {
		case c.Minutes == 0:
		case c.Minutes%1440 == 0:
			return fmt.Sprintf("封禁 %s %d 天", c.IP, c.Minutes/1440)
		case c.Minutes%60 == 0:
			return fmt.Sprintf("封禁 %s %d 小时", c.IP, c.Minutes/60)
		default:
			return fmt.Sprintf("封禁 %s %d 分钟", c.IP, c.Minutes)
		}
		return "永久封禁 " + c.IP
	case Allow:
		return "将 " + c.IP + " 加入白名单"
	case Unban:
		return "解除 " + c.IP + " 的封禁"
	}
	return c.Action
}

// Signer issues links pointing at the admin panel. A nil Signer (no
// admin.public_url configured) issues nothing.
type Signer struct {
	box  *secure.Box
	base string
}

func NewSigner(box *secure.Box, publicURL string) *Signer {
	if publicURL == "" {
		return nil
	}
	return &Signer{box: box, base: strings.TrimRight(publicURL, "/")}
}

func (s *Signer) sign(c Claims) string {
	b, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(b)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.box.MAC("action", []byte(payload)))
}

func (s *Signer) link(label string, danger bool, c Claims) notify.Action {
	c.Exp = time.Now().Add(linkTTL).Unix()
	c.Nonce = secure.Token(8)
	return notify.Action{Label: label, Danger: danger, URL: s.base + "/actions?t=" + url.QueryEscape(s.sign(c))}
}

// ForAttacker returns links for an IP that triggered an attack alert.
func (s *Signer) ForAttacker(ip string) []notify.Action {
	if s == nil {
		return nil
	}
	return []notify.Action{
		s.link("封禁 24 小时", true, Claims{Action: Ban, IP: ip, Minutes: 1440, Reason: "告警一键封禁"}),
		s.link("永久封禁", true, Claims{Action: Ban, IP: ip, Reason: "告警一键封禁"}),
		s.link("误报，加入白名单", false, Claims{Action: Allow, IP: ip, Reason: "告警一键加白"}),
	}
}

// ForBanned returns links for an automatically banned IP.
func (s *Signer) ForBanned(ip string) []notify.Action {
	if s == nil {
		return nil
	}
	return []notify.Action{
		s.link("解除封禁", false, Claims{Action: Unban, IP: ip}),
		s.link("加入白名单", false, Claims{Action: Allow, IP: ip, Reason: "告警一键加白"}),
		s.link("改为永久封禁", true, Claims{Action: Ban, IP: ip, Reason: "告警一键封禁"}),
	}
}

var ErrInvalid = errors.New("链接无效或已过期")

// Verify checks a token's signature and expiry.
func Verify(box *secure.Box, tok string) (*Claims, error) {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return nil, ErrInvalid
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(want, box.MAC("action", []byte(payload))) {
		return nil, ErrInvalid
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	var c Claims
	if json.Unmarshal(b, &c) != nil || c.Exp < time.Now().Unix() || c.Nonce == "" {
		return nil, ErrInvalid
	}
	if _, err := netip.ParseAddr(c.IP); err != nil {
		return nil, ErrInvalid
	}
	switch c.Action {
	case Ban, Allow, Unban:
	default:
		return nil, ErrInvalid
	}
	return &c, nil
}
