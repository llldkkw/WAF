// Package config loads the static bootstrap configuration (waf.yaml).
// Everything that changes at runtime (sites, IP rules, channels...) lives in
// the database and is managed from the admin panel.
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
	_ "time/tzdata" // timezones work in minimal containers too

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string `yaml:"data_dir"`

	Proxy ProxyConfig `yaml:"proxy"`
	Admin AdminConfig `yaml:"admin"`
	ACME  ACMEConfig  `yaml:"acme"`

	// GeoIPDB is an optional MaxMind GeoLite2-Country/City .mmdb file used for
	// the attack map and country blocking.
	GeoIPDB string `yaml:"geoip_db"`

	// Timezone for scheduled reports (default Asia/Shanghai).
	Timezone string `yaml:"timezone"`
	loc      *time.Location

	// LogRetentionDays controls how long attack events and stats are kept.
	LogRetentionDays int `yaml:"log_retention_days"`
}

type ProxyConfig struct {
	HTTPListen  string `yaml:"http_listen"`
	HTTPSListen string `yaml:"https_listen"`
	// TrustedProxies lists CIDRs (e.g. a CDN in front of the gateway) whose
	// X-Forwarded-For header is honoured when determining the client IP.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// FailOpen decides what happens when the WAF engine errors on a request:
	// true lets it through (availability), false blocks it (security).
	FailOpen bool `yaml:"fail_open"`
	// MaxBodyBytes caps how much of a request body is buffered for inspection.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`

	trusted []netip.Prefix
}

type AdminConfig struct {
	// Listen should be a private address only (WireGuard / LAN), never public.
	Listen string `yaml:"listen"`
	// TLS: "self-signed" (default), "off", or "file" (use CertFile/KeyFile).
	TLS      string `yaml:"tls"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// AllowedCIDRs restricts which source addresses may reach the panel at all.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	// SessionHours is the absolute session lifetime.
	SessionHours int `yaml:"session_hours"`
	// IdleMinutes logs a session out after this much inactivity.
	IdleMinutes int `yaml:"idle_minutes"`
	// PublicURL is how operators reach the panel (e.g. https://10.8.0.1:9443).
	// It enables one-click links in notifications.
	PublicURL string `yaml:"public_url"`

	allowed []netip.Prefix
}

type ACMEConfig struct {
	Enabled bool   `yaml:"enabled"`
	Email   string `yaml:"email"`
	// DirectoryURL defaults to Let's Encrypt production.
	DirectoryURL string `yaml:"directory_url"`
}

func Default() *Config {
	return &Config{
		DataDir: "./data",
		Proxy: ProxyConfig{
			HTTPListen:   ":80",
			HTTPSListen:  ":443",
			FailOpen:     false,
			MaxBodyBytes: 10 << 20,
		},
		Admin: AdminConfig{
			Listen:       "127.0.0.1:9443",
			TLS:          "self-signed",
			AllowedCIDRs: []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"},
			SessionHours: 12,
			IdleMinutes:  30,
		},
		LogRetentionDays: 30,
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var err error
	if c.Proxy.trusted, err = parsePrefixes(c.Proxy.TrustedProxies); err != nil {
		return fmt.Errorf("proxy.trusted_proxies: %w", err)
	}
	if c.Admin.allowed, err = parsePrefixes(c.Admin.AllowedCIDRs); err != nil {
		return fmt.Errorf("admin.allowed_cidrs: %w", err)
	}
	switch c.Admin.TLS {
	case "self-signed", "off":
	case "file":
		if c.Admin.CertFile == "" || c.Admin.KeyFile == "" {
			return fmt.Errorf("admin.tls=file requires cert_file and key_file")
		}
	default:
		return fmt.Errorf("admin.tls must be self-signed, off or file")
	}
	if c.ACME.Enabled && c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required when acme is enabled")
	}
	if c.Proxy.MaxBodyBytes <= 0 {
		c.Proxy.MaxBodyBytes = 10 << 20
	}
	if c.Admin.SessionHours <= 0 {
		c.Admin.SessionHours = 12
	}
	if c.Admin.IdleMinutes <= 0 {
		c.Admin.IdleMinutes = 30
	}
	if u := c.Admin.PublicURL; u != "" {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
			return fmt.Errorf("admin.public_url must look like https://10.8.0.1:9443")
		}
	}
	if c.Timezone == "" {
		c.Timezone = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return fmt.Errorf("timezone: %w", err)
	}
	c.loc = loc
	if c.LogRetentionDays <= 0 {
		c.LogRetentionDays = 30
	}
	return nil
}

// Location is the configured timezone.
func (c *Config) Location() *time.Location { return c.loc }

func (p *ProxyConfig) Trusted() []netip.Prefix { return p.trusted }
func (a *AdminConfig) Allowed() []netip.Prefix { return a.allowed }

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := ParsePrefixOrAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ParsePrefixOrAddr accepts either "1.2.3.4" or "1.2.3.0/24".
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ContainsAddr reports whether any prefix contains addr.
func ContainsAddr(ps []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range ps {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
