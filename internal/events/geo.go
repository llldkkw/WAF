package events

import (
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// Location is the result of a GeoIP lookup. Region is the ISO 3166-2 code
// ("CN-GD"); city names are given in English and Chinese when known.
type Location struct {
	Country string `json:"country"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	CityZh  string `json:"city_zh,omitempty"`
}

// Geo resolves IPs to locations. A nil *Geo resolves nothing.
type Geo struct {
	db   *geoip2.Reader
	city bool // City database: also has regions and cities
}

func OpenGeo(path string) (*Geo, error) {
	if path == "" {
		return nil, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &Geo{db: db, city: strings.Contains(db.Metadata().DatabaseType, "City")}, nil
}

// HasCity reports whether region/city lookups are available.
func (g *Geo) HasCity() bool { return g != nil && g.city }

// Enabled reports whether any GeoIP database is loaded.
func (g *Geo) Enabled() bool { return g != nil }

func (g *Geo) Country(ip string) string {
	return g.Lookup(ip).Country
}

func (g *Geo) Lookup(ip string) Location {
	if g == nil {
		return Location{}
	}
	p := net.ParseIP(ip)
	if p == nil {
		return Location{}
	}
	if !g.city {
		c, err := g.db.Country(p)
		if err != nil {
			return Location{}
		}
		return Location{Country: c.Country.IsoCode}
	}
	c, err := g.db.City(p)
	if err != nil {
		return Location{}
	}
	loc := Location{Country: c.Country.IsoCode, City: c.City.Names["en"], CityZh: c.City.Names["zh-CN"]}
	if len(c.Subdivisions) > 0 && c.Subdivisions[0].IsoCode != "" && loc.Country != "" {
		loc.Region = loc.Country + "-" + c.Subdivisions[0].IsoCode
	}
	return loc
}

// Matches reports whether a location matches a geo rule. Rules are:
//
//	"CN"          country
//	"CN-GD"       province / state (ISO 3166-2)
//	"CN/Shenzhen" or "CN/深圳"      city within a country
//	"CN-GD/深圳"  city within a province
func (l Location) Matches(rule string) bool {
	if l.Country == "" {
		return false
	}
	area, city, hasCity := strings.Cut(rule, "/")
	switch {
	case strings.Contains(area, "-"):
		if !strings.EqualFold(area, l.Region) {
			return false
		}
	default:
		if !strings.EqualFold(area, l.Country) {
			return false
		}
	}
	if !hasCity {
		return true
	}
	return city != "" && (strings.EqualFold(city, l.City) || city == l.CityZh)
}

// String renders a location for logs and alerts.
func (l Location) String() string {
	s := l.Country
	if l.Region != "" {
		s = l.Region
	}
	if l.CityZh != "" {
		s += " " + l.CityZh
	} else if l.City != "" {
		s += " " + l.City
	}
	return s
}
