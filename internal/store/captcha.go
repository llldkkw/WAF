package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// CaptchaProviders holds third-party human verification keys. Secrets are
// stored encrypted (the whole object is sealed with the master key).
type CaptchaProviders struct {
	Turnstile TurnstileConfig `json:"turnstile"`
	Recaptcha RecaptchaConfig `json:"recaptcha"`
}

type TurnstileConfig struct {
	SiteKey string `json:"site_key"`
	Secret  string `json:"secret"`
}

type RecaptchaConfig struct {
	SiteKey string `json:"site_key"`
	Secret  string `json:"secret"`
	// Version: v2 (checkbox) or v3 (invisible, scored).
	Version string `json:"version"`
	// MinScore for v3, 0.0-1.0 (default 0.5).
	MinScore float64 `json:"min_score"`
	// Domain serving the API: www.recaptcha.net (reachable from mainland
	// China, default) or www.google.com.
	Domain string `json:"domain"`
}

func (t TurnstileConfig) Ready() bool { return t.SiteKey != "" && t.Secret != "" }
func (r RecaptchaConfig) Ready() bool { return r.SiteKey != "" && r.Secret != "" }

func (c *CaptchaProviders) Normalize() error {
	c.Turnstile.SiteKey = strings.TrimSpace(c.Turnstile.SiteKey)
	c.Turnstile.Secret = strings.TrimSpace(c.Turnstile.Secret)
	r := &c.Recaptcha
	r.SiteKey, r.Secret = strings.TrimSpace(r.SiteKey), strings.TrimSpace(r.Secret)
	switch r.Version {
	case "":
		r.Version = "v2"
	case "v2", "v3":
	default:
		return errors.New("reCAPTCHA 版本应为 v2 或 v3")
	}
	if r.MinScore <= 0 {
		r.MinScore = 0.5
	}
	if r.MinScore > 1 {
		return errors.New("reCAPTCHA 最低分数应在 0-1 之间")
	}
	switch r.Domain {
	case "":
		r.Domain = "www.recaptcha.net"
	case "www.recaptcha.net", "www.google.com":
	default:
		return errors.New("reCAPTCHA 域名应为 www.recaptcha.net 或 www.google.com")
	}
	return nil
}

const captchaKey = "captcha_providers"

type sealer interface {
	Seal([]byte) (string, error)
	Open(string) ([]byte, error)
}

func (s *Store) CaptchaProviders(ctx context.Context, box sealer) (*CaptchaProviders, error) {
	c := &CaptchaProviders{}
	var enc string
	if err := s.GetJSON(ctx, captchaKey, &enc); err != nil {
		return nil, err
	}
	if enc != "" {
		raw, err := box.Open(enc)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, c); err != nil {
			return nil, err
		}
	}
	_ = c.Normalize()
	return c, nil
}

func (s *Store) SaveCaptchaProviders(ctx context.Context, box sealer, c *CaptchaProviders) error {
	raw, _ := json.Marshal(c)
	enc, err := box.Seal(raw)
	if err != nil {
		return err
	}
	if err := s.SetJSON(ctx, captchaKey, enc); err != nil {
		return err
	}
	return s.BumpConfigVersion(ctx)
}
