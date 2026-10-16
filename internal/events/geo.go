package events

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// Geo resolves IPs to ISO country codes. A nil *Geo resolves nothing.
type Geo struct {
	db *geoip2.Reader
}

func OpenGeo(path string) (*Geo, error) {
	if path == "" {
		return nil, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &Geo{db: db}, nil
}

func (g *Geo) Country(ip string) string {
	if g == nil {
		return ""
	}
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	c, err := g.db.Country(p)
	if err != nil {
		return ""
	}
	return c.Country.IsoCode
}
