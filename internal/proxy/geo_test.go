package proxy

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"github.com/llldkkw/waf/internal/store"
)

// writeCityDB builds a tiny GeoLite2-City style database:
// 1.0.1.0/24 → CN / Guangdong / Shenzhen, 1.0.2.0/24 → CN / Beijing,
// 8.8.8.0/24 → US.
func writeCityDB(t *testing.T) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-City", RecordSize: 28})
	if err != nil {
		t.Fatal(err)
	}
	rec := func(country, sub, cityEn, cityZh string) mmdbtype.Map {
		m := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(country)}}
		if sub != "" {
			m["subdivisions"] = mmdbtype.Slice{mmdbtype.Map{"iso_code": mmdbtype.String(sub)}}
		}
		if cityEn != "" {
			m["city"] = mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(cityEn), "zh-CN": mmdbtype.String(cityZh)}}
		}
		return m
	}
	for cidr, r := range map[string]mmdbtype.Map{
		"1.0.1.0/24": rec("CN", "GD", "Shenzhen", "深圳"),
		"1.0.2.0/24": rec("CN", "BJ", "Beijing", "北京"),
		"8.8.8.0/24": rec("US", "CA", "", ""),
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, r); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "city.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGeoPolicy(t *testing.T) {
	db := writeCityDB(t)
	be := backend(t)
	cases := []struct {
		name string
		geo  store.GeoPolicy
		ip   string
		want int
	}{
		{"block province", store.GeoPolicy{Mode: "block", Rules: []string{"CN-GD"}}, "1.0.1.5", 403},
		{"block province other", store.GeoPolicy{Mode: "block", Rules: []string{"CN-GD"}}, "1.0.2.5", 200},
		{"block city zh", store.GeoPolicy{Mode: "block", Rules: []string{"CN/深圳"}}, "1.0.1.5", 403},
		{"allow country", store.GeoPolicy{Mode: "allow", Rules: []string{"CN"}}, "1.0.2.5", 200},
		{"allow country denies others", store.GeoPolicy{Mode: "allow", Rules: []string{"CN"}}, "8.8.8.8", 403},
		{"allow city only", store.GeoPolicy{Mode: "allow", Rules: []string{"CN-BJ/Beijing"}}, "1.0.1.5", 403},
		{"allow unknown denied", store.GeoPolicy{Mode: "allow", Rules: []string{"CN"}}, "9.9.9.9", 403},
		{"allow unknown permitted", store.GeoPolicy{Mode: "allow", Rules: []string{"CN"}, AllowUnknown: true}, "9.9.9.9", 200},
		{"private always allowed", store.GeoPolicy{Mode: "allow", Rules: []string{"CN"}}, "10.8.0.2", 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, _ := setup(t, store.Site{Name: "app", Enabled: true, Hosts: []string{"app.test"}, Upstreams: []string{be.URL},
				Mode: store.ModeOff, Geo: c.geo}, "geoip_db: "+db+"\n")
			if w := do(p, "GET", "http://app.test/", c.ip+":1", nil); w.Code != c.want {
				t.Fatalf("%s from %s: got %d want %d", c.name, c.ip, w.Code, c.want)
			}
		})
	}
}
